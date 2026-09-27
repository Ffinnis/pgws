package physical

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type Database struct {
	Name             string            `json:"name"`
	Encoding         string            `json:"encoding"`
	Collation        string            `json:"collation"`
	Extensions       map[string]string `json:"extensions"`
	UnloggedTables   int               `json:"unlogged_tables"`
	ForeignServers   int               `json:"foreign_servers"`
	Subscriptions    int               `json:"subscriptions"`
	CustomCFunctions int               `json:"custom_c_functions"`
	EventTriggers    int               `json:"event_triggers"`
}
type Manifest struct {
	Identity
	ServerVersion int               `json:"server_version"`
	Settings      map[string]string `json:"settings"`
	Databases     []Database        `json:"databases"`
	ExistingSlots []string          `json:"existing_slots"`
	Blockers      []string          `json:"blockers"`
	ObservedAt    time.Time         `json:"observed_at"`
}

// Inspect fails on incomplete inspection. The report is evidence for subsequent
// approval, not permission to publish customer data or a full compatibility audit.
func (s Source) Inspect(ctx context.Context) (Manifest, error) {
	id, e := s.Identify(ctx)
	if e != nil {
		return Manifest{}, e
	}
	conn, e := s.ConnectAdmin(ctx)
	if e != nil {
		return Manifest{}, e
	}
	defer conn.Close(context.Background())
	m := Manifest{Identity: id, Settings: map[string]string{}, Databases: []Database{}, ExistingSlots: []string{}, Blockers: []string{}, ObservedAt: time.Now().UTC()}
	var recovery bool
	if e = conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int,pg_is_in_recovery()`).Scan(&m.ServerVersion, &recovery); e != nil {
		return m, safeError("version inspection")
	}
	if m.ServerVersion/10000 != 18 {
		m.Blockers = append(m.Blockers, "PostgreSQL major must be 18")
	}
	if recovery {
		m.Blockers = append(m.Blockers, "source must be a primary")
	}
	rows, e := conn.Query(ctx, `SELECT name,setting FROM pg_settings WHERE name=ANY($1::text[])`, []string{"wal_level", "wal_segment_size", "max_connections", "max_prepared_transactions", "max_locks_per_transaction", "max_wal_senders", "max_worker_processes", "shared_preload_libraries", "session_preload_libraries", "local_preload_libraries", "max_slot_wal_keep_size", "checkpoint_timeout", "full_page_writes", "fsync", "archive_mode"})
	if e != nil {
		return m, safeError("recovery settings")
	}
	for rows.Next() {
		var k, v string
		if e = rows.Scan(&k, &v); e != nil {
			rows.Close()
			return m, safeError("recovery settings")
		}
		m.Settings[k] = v
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return m, safeError("recovery settings")
	}
	if len(m.Settings) != 15 {
		return m, errors.New("incomplete recovery setting visibility")
	}
	for _, k := range []string{"shared_preload_libraries", "session_preload_libraries", "local_preload_libraries"} {
		if m.Settings[k] != "" {
			m.Blockers = append(m.Blockers, "unqualified preload setting: "+k)
		}
	}
	if m.Settings["wal_level"] != "replica" && m.Settings["wal_level"] != "logical" {
		m.Blockers = append(m.Blockers, "wal_level must support physical replication")
	}
	if m.Settings["fsync"] != "on" || m.Settings["full_page_writes"] != "on" {
		m.Blockers = append(m.Blockers, "durable WAL settings are required")
	}
	var externalTablespaces, prepared int
	if e = conn.QueryRow(ctx, `SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')`).Scan(&externalTablespaces); e != nil {
		return m, safeError("tablespace inspection")
	}
	if externalTablespaces > 0 {
		m.Blockers = append(m.Blockers, "external tablespaces are unsupported")
	}
	if e = conn.QueryRow(ctx, `SELECT count(*) FROM pg_prepared_xacts`).Scan(&prepared); e != nil {
		return m, safeError("prepared transactions")
	}
	if prepared > 0 {
		m.Blockers = append(m.Blockers, "prepared transactions are unsupported")
	}
	rows, e = conn.Query(ctx, `SELECT slot_name FROM pg_replication_slots ORDER BY slot_name`)
	if e != nil {
		return m, safeError("slot inventory")
	}
	for rows.Next() {
		var slot string
		if e = rows.Scan(&slot); e != nil {
			rows.Close()
			return m, safeError("slot inventory")
		}
		m.ExistingSlots = append(m.ExistingSlots, slot)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return m, safeError("slot inventory")
	}
	rows, e = conn.Query(ctx, `SELECT datname,pg_encoding_to_char(encoding),datcollate,datallowconn FROM pg_database WHERE datname<>'template0' ORDER BY datname`)
	if e != nil {
		return m, safeError("database inventory")
	}
	approved := map[string]bool{"template1": true}
	for _, d := range s.ApprovedDatabases {
		approved[d] = true
	}
	for rows.Next() {
		var db Database
		var canConnect bool
		if e = rows.Scan(&db.Name, &db.Encoding, &db.Collation, &canConnect); e != nil {
			rows.Close()
			return m, safeError("database inventory")
		}
		if !approved[db.Name] {
			m.Blockers = append(m.Blockers, "database outside approved inventory: "+db.Name)
		}
		if !canConnect {
			m.Blockers = append(m.Blockers, "database cannot be inspected: "+db.Name)
		}
		m.Databases = append(m.Databases, db)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return m, safeError("database inventory")
	}
	for i := range m.Databases {
		db := &m.Databases[i]
		source := s
		source.Database = db.Name
		dc, e := source.ConnectAdmin(ctx)
		if e != nil {
			return m, safeError("database inspection")
		}
		blockers, e := inspectDatabaseCatalog(ctx, dc, db)
		dc.Close(context.Background())
		if e != nil {
			return m, e
		}
		m.Blockers = append(m.Blockers, blockers...)
	}
	after, e := s.Identify(ctx)
	if e != nil || after != id {
		return m, errors.New("source lineage changed during discovery")
	}
	sort.Strings(m.Blockers)
	return m, nil
}

// Both initial discovery and the promoted private clone use the same catalog
// checks. Source DDL can arrive after discovery and before a baseline capture.
func inspectDatabaseCatalog(ctx context.Context, conn *pgx.Conn, db *Database) ([]string, error) {
	var blockers []string
	db.Extensions = map[string]string{}
	rows, err := conn.Query(ctx, `SELECT extname,extversion FROM pg_extension ORDER BY extname`)
	if err != nil {
		return nil, safeError("extension inspection")
	}
	for rows.Next() {
		var name, version string
		if err = rows.Scan(&name, &version); err != nil {
			break
		}
		db.Extensions[name] = version
		if name != "plpgsql" {
			blockers = append(blockers, "unqualified extension in "+db.Name+": "+name)
		}
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, safeError("extension inspection")
	}
	err = conn.QueryRow(ctx, `SELECT
   (SELECT count(*) FROM pg_class WHERE relpersistence='u' AND relnamespace NOT IN ('pg_catalog'::regnamespace,'information_schema'::regnamespace)),
   (SELECT count(*) FROM pg_foreign_server),
   (SELECT count(*) FROM pg_subscription WHERE subdbid=(SELECT oid FROM pg_database WHERE datname=current_database())),
   (SELECT count(*) FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang JOIN pg_namespace n ON n.oid=p.pronamespace WHERE l.lanname='c' AND n.nspname NOT IN ('pg_catalog','information_schema')),
   (SELECT count(*) FROM pg_event_trigger)`).Scan(&db.UnloggedTables, &db.ForeignServers, &db.Subscriptions, &db.CustomCFunctions, &db.EventTriggers)
	if err != nil {
		return nil, safeError("unsupported feature inspection")
	}
	if db.UnloggedTables+db.ForeignServers+db.Subscriptions+db.CustomCFunctions > 0 {
		blockers = append(blockers, "unsupported persistent objects in "+db.Name)
	}
	if db.EventTriggers > 0 {
		blockers = append(blockers, "event triggers in "+db.Name)
	}
	return blockers, nil
}
func (m Manifest) RequireSeedable() error {
	if len(m.Blockers) > 0 {
		return errors.New("source is blocked: " + strings.Join(m.Blockers, "; "))
	}
	return nil
}
