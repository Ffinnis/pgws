// Package physical provides administrator-side physical PostgreSQL operations.
// It does not authorize workspace publication or replace network isolation.
package physical

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/sourcebroker"
)

type Source struct {
	Host              string   `json:"host"`
	Port              uint16   `json:"port"`
	User              string   `json:"user"`
	Database          string   `json:"database"`
	PasswordFile      string   `json:"password_file,omitempty"`
	RootCertificate   string   `json:"root_certificate,omitempty"`
	ApprovedDatabases []string `json:"approved_databases"`
	ExpectedSystemID  string   `json:"expected_system_id,omitempty"`
	ApprovedAddresses []string `json:"approved_addresses,omitempty"`
}
type Identity struct {
	SystemID string `json:"system_id"`
	Timeline int64  `json:"timeline"`
}
type Barrier struct {
	Identity
	LSN        string    `json:"lsn"`
	ObservedAt time.Time `json:"observed_at"`
}

func (s Source) config() (*pgx.ConnConfig, error) {
	if s.Host == "" || s.User == "" || s.Database == "" || s.Port == 0 {
		return nil, errors.New("incomplete approved source configuration")
	}
	u := url.URL{Scheme: "postgresql", User: url.User(s.User), Path: "/" + s.Database}
	q := url.Values{}
	if filepath.IsAbs(s.Host) {
		q.Set("host", s.Host)
		q.Set("port", strconv.Itoa(int(s.Port)))
		q.Set("sslmode", "disable")
	} else {
		u.Host = net.JoinHostPort(s.Host, strconv.Itoa(int(s.Port)))
		q.Set("sslmode", "verify-full")
		if s.RootCertificate != "" {
			q.Set("sslrootcert", s.RootCertificate)
		}
	}
	q.Set("connect_timeout", "5")
	u.RawQuery = q.Encode()
	cfg, e := pgx.ParseConfig(u.String())
	if e != nil {
		return nil, errors.New("invalid approved source configuration")
	}
	cfg.Password = "" // Do not inherit an ambient pgpass password.
	if s.PasswordFile != "" {
		password, e := readSecret(s.PasswordFile)
		if e != nil {
			return nil, e
		}
		cfg.Password = password
	}
	cfg.RuntimeParams = map[string]string{"application_name": "pgws-inspector", "statement_timeout": "5000", "lock_timeout": "2000"}
	if !filepath.IsAbs(s.Host) {
		endpoint := s.TLSEndpoint()
		if e = endpoint.Validate(); e != nil {
			return nil, e
		}
		cfg.LookupFunc, cfg.DialFunc = endpoint.Lookup, endpoint.DialContext
		if cfg.TLSConfig == nil {
			return nil, errors.New("TCP sources require TLS verification")
		}
		cfg.TLSConfig.MinVersion = tls.VersionTLS12
	}
	return cfg, nil
}

func (s Source) TLSEndpoint() sourcebroker.Endpoint {
	return sourcebroker.Endpoint{Hostname: s.Host, Port: s.Port, Addresses: s.ApprovedAddresses, RootCertificate: s.RootCertificate}
}
func readSecret(path string) (string, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 65536 {
		return "", errors.New("secret must be a private regular file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", errors.New("source secret unavailable")
	}
	password := strings.TrimSuffix(string(b), "\n")
	if strings.ContainsAny(password, "\r\n\x00") {
		return "", errors.New("invalid password file")
	}
	return password, nil
}
func (s Source) Connect(ctx context.Context) (*pgx.Conn, error) {
	return s.connect(ctx, false, false)
}

// ConnectAdmin uses catalog-only name resolution and durable SQL commits even
// when the copied database/role has different session defaults.
func (s Source) ConnectAdmin(ctx context.Context) (*pgx.Conn, error) {
	return s.connect(ctx, true, false)
}

// ConnectPrivateAdmin is for the isolated local baseline/clone, whose copied
// role and database defaults must not load libraries before SQL hardening.
func (s Source) ConnectPrivateAdmin(ctx context.Context) (*pgx.Conn, error) {
	if !filepath.IsAbs(s.Host) {
		return nil, errors.New("private runtime administration requires a local Unix socket")
	}
	return s.connect(ctx, true, true)
}

func (s Source) connect(ctx context.Context, administrator, private bool) (*pgx.Conn, error) {
	cfg, e := s.config()
	if e != nil {
		return nil, e
	}
	if administrator {
		cfg.RuntimeParams["search_path"] = "pg_catalog"
		cfg.RuntimeParams["synchronous_commit"] = "on"
	}
	if private {
		// PG18 login event triggers run before the first SQL statement. Disable
		// them in the startup packet, before inspecting the copied catalog.
		cfg.RuntimeParams["event_triggers"] = "off"
		cfg.RuntimeParams["session_preload_libraries"] = ""
		cfg.RuntimeParams["local_preload_libraries"] = ""
		cfg.RuntimeParams["role"] = "none"
		cfg.RuntimeParams["default_transaction_read_only"] = "off"
	}
	conn, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		return nil, errors.New("approved source connection failed")
	}
	return conn, nil
}
func (s Source) Identify(ctx context.Context) (Identity, error) {
	cfg, e := s.config()
	if e != nil {
		return Identity{}, e
	}
	cfg.RuntimeParams = map[string]string{"replication": "true", "application_name": "pgws-identity"}
	conn, e := pgx.ConnectConfig(ctx, cfg)
	if e != nil {
		return Identity{}, errors.New("source identity connection failed")
	}
	defer conn.Close(context.Background())
	results, e := conn.PgConn().Exec(ctx, "IDENTIFY_SYSTEM").ReadAll()
	if e != nil || len(results) != 1 || len(results[0].Rows) != 1 || len(results[0].Rows[0]) < 3 {
		return Identity{}, errors.New("source identity inspection failed")
	}
	row := results[0].Rows[0]
	timeline, e := strconv.ParseInt(string(row[1]), 10, 64)
	if e != nil || timeline < 1 {
		return Identity{}, errors.New("invalid source timeline")
	}
	id := Identity{SystemID: string(row[0]), Timeline: timeline}
	if _, e = strconv.ParseUint(id.SystemID, 10, 64); e != nil {
		return Identity{}, errors.New("invalid source system identity")
	}
	if s.ExpectedSystemID != "" && id.SystemID != s.ExpectedSystemID {
		return Identity{}, errors.New("source identity changed")
	}
	return id, nil
}
func (s Source) CaptureBarrier(ctx context.Context) (Barrier, error) {
	before, e := s.Identify(ctx)
	if e != nil {
		return Barrier{}, e
	}
	conn, e := s.ConnectAdmin(ctx)
	if e != nil {
		return Barrier{}, e
	}
	defer conn.Close(context.Background())
	var lsn string
	var recovery bool
	if e = conn.QueryRow(ctx, `SELECT pg_is_in_recovery(),pg_current_wal_insert_lsn()::text`).Scan(&recovery, &lsn); e != nil || recovery {
		return Barrier{}, errors.New("barrier requires a writable primary")
	}
	for {
		var flushed bool
		if e = conn.QueryRow(ctx, `SELECT pg_current_wal_flush_lsn()>=$1::pg_lsn`, lsn).Scan(&flushed); e != nil {
			return Barrier{}, errors.New("source WAL flush observation failed")
		}
		if flushed {
			break
		}
		if e = wait(ctx, 20*time.Millisecond); e != nil {
			return Barrier{}, e
		}
	}
	after, e := s.Identify(ctx)
	if e != nil {
		return Barrier{}, e
	}
	if before != after {
		return Barrier{}, errors.New("source lineage changed during barrier")
	}
	return Barrier{Identity: after, LSN: lsn, ObservedAt: time.Now().UTC()}, nil
}
func ParseLSN(s string) (uint64, error) {
	pieces := strings.Split(s, "/")
	if len(pieces) != 2 {
		return 0, errors.New("invalid LSN")
	}
	hi, e := strconv.ParseUint(pieces[0], 16, 32)
	if e != nil {
		return 0, e
	}
	lo, e := strconv.ParseUint(pieces[1], 16, 32)
	if e != nil {
		return 0, e
	}
	return hi<<32 | lo, nil
}
func wait(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func safeError(stage string) error { return fmt.Errorf("physical operation failed at %s", stage) }
