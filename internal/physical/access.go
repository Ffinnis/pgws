package physical

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type Access struct {
	Admin     string   `json:"admin"`
	Owner     string   `json:"owner_role"`
	Reader    string   `json:"reader_role"`
	Databases []string `json:"databases"`
}
type Credential struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	ExpiresAt time.Time `json:"expires_at"`
}

func randomName(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}
func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

// HardenAccess runs only on the private, promoted clone. It disables imported
// login credentials and memberships, and gives agents ownership of application
// objects without granting membership in the source's catalog-owning roles.
func HardenAccess(ctx context.Context, r Recovery) (Access, error) {
	var out Access
	var err error
	if err = ValidateRecoveryPlan(r); err != nil {
		return out, err
	}
	planPath := filepath.Join(r.ControlDir, "access-plan.json")
	var plan accessPlan
	reserved := false
	if data, e := os.ReadFile(planPath); e == nil {
		if len(data) > 1<<20 || json.Unmarshal(data, &plan) != nil || !reflect.DeepEqual(plan.Recovery, r) || !validAccess(plan.Access) {
			return out, errors.New("access plan differs from the recovery generation")
		}
		out, reserved = plan.Access, true
	} else if !os.IsNotExist(e) {
		return out, e
	} else {
		for _, dest := range []*string{&out.Admin, &out.Owner, &out.Reader} {
			*dest, err = randomName("pgws_service_")
			if err != nil {
				return out, err
			}
		}
	}
	source := Source{Host: r.SocketDir, Port: 5432, User: r.SourceUser, Database: "postgres"}
	var conn *pgx.Conn
	if reserved {
		admin := source
		admin.User = out.Admin
		conn, err = admin.ConnectPrivateAdmin(ctx)
	}
	if conn == nil {
		conn, err = source.ConnectPrivateAdmin(ctx)
	}
	if err != nil {
		return out, err
	}
	defer conn.Close(context.Background())
	var recovery bool
	if err = conn.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery); err != nil || recovery {
		return out, errors.New("access changes require promoted clone")
	}
	rows, err := conn.Query(ctx, `SELECT datname, datallowconn AND NOT datistemplate, datallowconn FROM pg_database ORDER BY datname`)
	if err != nil {
		return out, err
	}
	var databases []string
	var applicationDatabases []string
	var inspectDatabases []string
	for rows.Next() {
		var name string
		var application, canConnect bool
		if err = rows.Scan(&name, &application, &canConnect); err != nil {
			rows.Close()
			return out, err
		}
		databases = append(databases, name)
		if canConnect {
			inspectDatabases = append(inspectDatabases, name)
		} else if name != "template0" {
			rows.Close()
			return out, errors.New("private database cannot be inspected")
		}
		if application {
			applicationDatabases = append(applicationDatabases, name)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	// No application DDL or access-role creation may precede this check. A
	// copied event trigger could otherwise execute during ALTER ... OWNER as
	// the bootstrap superuser. Startup also suppresses login event triggers.
	for _, name := range inspectDatabases {
		private := source
		private.User, private.Database = conn.Config().User, name
		dc, e := private.ConnectPrivateAdmin(ctx)
		if e != nil {
			return out, safeError("private database preflight")
		}
		blockers, e := inspectDatabaseCatalog(ctx, dc, &Database{Name: name})
		dc.Close(context.Background())
		if e != nil {
			return out, e
		}
		if len(blockers) > 0 {
			return out, errors.New("private clone is blocked: " + strings.Join(blockers, "; "))
		}
	}
	if reserved {
		if !reflect.DeepEqual(applicationDatabases, out.Databases) {
			return out, errors.New("database inventory differs from the access plan")
		}
	} else {
		out.Databases = applicationDatabases
		plan = accessPlan{Recovery: r, Access: out}
		if !validAccess(out) {
			return out, errors.New("invalid private access plan")
		}
		if err = writeJSON(planPath, plan); err != nil {
			return out, err
		}
	}
	encoded, _ := json.Marshal(plan)
	marker := fmt.Sprintf("pgws-access:%x", sha256.Sum256(encoded))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	var present, matching int
	if err = tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER(WHERE shobj_description(oid,'pg_authid')=$2 AND rolpassword IS NULL AND CASE WHEN rolname=$3 THEN rolcanlogin AND rolsuper ELSE NOT (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls) END) FROM pg_authid WHERE rolname=ANY($1::text[])`, []string{out.Admin, out.Owner, out.Reader}, marker, out.Admin).Scan(&present, &matching); err != nil {
		return out, safeError("access role ownership")
	}
	if present == 0 {
		if _, err = tx.Exec(ctx, "CREATE ROLE "+ident(out.Admin)+" LOGIN SUPERUSER PASSWORD NULL; CREATE ROLE "+ident(out.Owner)+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE "+ident(out.Reader)+" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
			return out, err
		}
		for _, name := range []string{out.Admin, out.Owner, out.Reader} {
			if _, err = tx.Exec(ctx, "COMMENT ON ROLE "+ident(name)+" IS '"+marker+"'"); err != nil {
				return out, err
			}
		}
	} else if present != 3 || matching != 3 {
		return out, errors.New("existing access roles differ from their reserved plan")
	}
	if _, err = tx.Exec(ctx, "SET SESSION AUTHORIZATION "+ident(out.Admin)); err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT rolname FROM pg_roles WHERE rolname !~ '^pg_' AND rolname<>ALL($1::text[])`, []string{out.Admin, out.Owner, out.Reader})
	if err != nil {
		return out, err
	}
	var roles []string
	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			rows.Close()
			return out, err
		}
		roles = append(roles, role)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	var bootstrap string
	if err = tx.QueryRow(ctx, `SELECT rolname FROM pg_roles WHERE oid=10`).Scan(&bootstrap); err != nil {
		return out, err
	}
	for _, role := range roles {
		attributes := "NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD NULL"
		// PostgreSQL 16+ requires OID 10 to retain SUPERUSER. No imported
		// membership survives, and its login/password are disabled instead.
		if role == bootstrap {
			attributes = "NOLOGIN PASSWORD NULL"
		}
		if _, err = tx.Exec(ctx, "ALTER ROLE "+ident(role)+" "+attributes+"; ALTER ROLE "+ident(role)+" RESET ALL"); err != nil {
			return out, err
		}
	}
	rows, err = tx.Query(ctx, `SELECT r.rolname,m.rolname FROM pg_auth_members a JOIN pg_roles r ON r.oid=a.roleid JOIN pg_roles m ON m.oid=a.member`)
	if err != nil {
		return out, err
	}
	var grants [][2]string
	for rows.Next() {
		var pair [2]string
		if err = rows.Scan(&pair[0], &pair[1]); err != nil {
			rows.Close()
			return out, err
		}
		grants = append(grants, pair)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	for _, g := range grants {
		if _, err = tx.Exec(ctx, "REVOKE "+ident(g[0])+" FROM "+ident(g[1])+" CASCADE"); err != nil {
			return out, err
		}
	}
	for _, db := range databases {
		if _, err = tx.Exec(ctx, "ALTER DATABASE "+ident(db)+" RESET ALL; REVOKE ALL ON DATABASE "+ident(db)+" FROM PUBLIC"); err != nil {
			return out, err
		}
		for _, role := range roles {
			if _, err = tx.Exec(ctx, "ALTER ROLE "+ident(role)+" IN DATABASE "+ident(db)+" RESET ALL"); err != nil {
				return out, err
			}
		}
	}
	for _, db := range out.Databases {
		if _, err = tx.Exec(ctx, "GRANT CONNECT ON DATABASE "+ident(db)+" TO "+ident(out.Owner)+","+ident(out.Reader)); err != nil {
			return out, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	if _, err = conn.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()`); err != nil {
		return out, err
	}
	// Host-only administrator access is separated from SCRAM application roles.
	hba := "local all " + out.Admin + " trust\nlocal all all scram-sha-256\nhost all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n"
	path := filepath.Join(r.ControlDir, "hba.conf")
	if err = os.WriteFile(path, []byte(hba), 0600); err != nil {
		return out, err
	}
	// Keep the existing file's ownership when the helper runs as root.
	if _, err = conn.Exec(ctx, "SELECT pg_reload_conf()"); err != nil {
		return out, err
	}
	for _, db := range out.Databases {
		s := source
		s.User = out.Admin
		s.Database = db
		dc, err := s.ConnectPrivateAdmin(ctx)
		if err != nil {
			return out, err
		}
		err = transferApplicationObjects(ctx, dc, out, db)
		dc.Close(context.Background())
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

type accessPlan struct {
	Recovery Recovery `json:"recovery"`
	Access   Access   `json:"access"`
}

func validAccess(a Access) bool {
	name := regexp.MustCompile(`^pgws_service_[a-f0-9]{32}$`)
	return name.MatchString(a.Admin) && name.MatchString(a.Owner) && name.MatchString(a.Reader) && a.Admin != a.Owner && a.Admin != a.Reader && a.Owner != a.Reader && len(a.Databases) > 0
}

func transferApplicationObjects(ctx context.Context, conn *pgx.Conn, a Access, db string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SET LOCAL search_path=pg_catalog"); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT nspname FROM pg_namespace WHERE nspname !~ '^pg_' AND nspname<>'information_schema'`)
	if err != nil {
		return err
	}
	var schemas []string
	for rows.Next() {
		var s string
		if err = rows.Scan(&s); err != nil {
			rows.Close()
			return err
		}
		schemas = append(schemas, s)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	// The server formats catalog-derived identities, including routine argument
	// types. No source-provided SQL body is executed by this migration.
	rows, err = tx.Query(ctx, `SELECT format('ALTER %s %I.%I OWNER TO %I',CASE c.relkind WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,n.nspname,c.relname,$1::text)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=ANY($2::text[]) AND c.relkind IN ('r','p','v','m','S') ORDER BY c.relkind='S',c.oid`, a.Owner, schemas)
	if err != nil {
		return err
	}
	var statements []string
	for rows.Next() {
		var q string
		if err = rows.Scan(&q); err != nil {
			rows.Close()
			return err
		}
		statements = append(statements, q)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, q := range statements {
		if _, err = tx.Exec(ctx, q); err != nil {
			return safeError("application object ownership")
		}
	}
	rows, err = tx.Query(ctx, `SELECT format('ALTER %s %I.%I(%s) OWNER TO %I', CASE WHEN p.prokind='a' THEN 'AGGREGATE' ELSE 'ROUTINE' END,n.nspname,p.proname,CASE WHEN p.prokind='a' AND p.pronargs=0 THEN '*' ELSE pg_get_function_identity_arguments(p.oid) END,$1::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname=ANY($2::text[])
 UNION ALL SELECT format('ALTER %s %I.%I OWNER TO %I',CASE WHEN t.typtype='d' THEN 'DOMAIN' ELSE 'TYPE' END,n.nspname,t.typname,$1::text) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace LEFT JOIN pg_class c ON c.oid=t.typrelid WHERE n.nspname=ANY($2::text[]) AND (t.typtype IN ('e','d','r') OR (t.typtype='c' AND c.relkind='c'))`, a.Owner, schemas)
	if err != nil {
		return err
	}
	statements = nil
	for rows.Next() {
		var q string
		if err = rows.Scan(&q); err != nil {
			rows.Close()
			return err
		}
		statements = append(statements, q)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, q := range statements {
		if _, err = tx.Exec(ctx, q); err != nil {
			return safeError("application routine ownership")
		}
	}
	// Routine EXECUTE is granted to PUBLIC globally by default. A schema-local
	// revoke cannot remove that default for newly created procedures/functions.
	if _, err = tx.Exec(ctx, "ALTER DEFAULT PRIVILEGES FOR ROLE "+ident(a.Owner)+" REVOKE EXECUTE ON ROUTINES FROM PUBLIC"); err != nil {
		return err
	}
	for _, schema := range schemas {
		s := ident(schema)
		owner, reader := ident(a.Owner), ident(a.Reader)
		for _, q := range []string{"ALTER SCHEMA " + s + " OWNER TO " + owner, "REVOKE ALL ON SCHEMA " + s + " FROM PUBLIC", "GRANT USAGE ON SCHEMA " + s + " TO " + reader, "REVOKE ALL ON ALL TABLES IN SCHEMA " + s + " FROM PUBLIC", "REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + s + " FROM PUBLIC", "REVOKE ALL ON ALL ROUTINES IN SCHEMA " + s + " FROM PUBLIC", "GRANT SELECT ON ALL TABLES IN SCHEMA " + s + " TO " + reader, "GRANT SELECT ON ALL SEQUENCES IN SCHEMA " + s + " TO " + reader, "ALTER DEFAULT PRIVILEGES FOR ROLE " + owner + " IN SCHEMA " + s + " GRANT SELECT ON TABLES TO " + reader} {
			if _, err = tx.Exec(ctx, q); err != nil {
				return safeError("application grants")
			}
		}
	}
	if _, err = tx.Exec(ctx, "ALTER DATABASE "+ident(db)+" OWNER TO "+ident(a.Owner)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func IssueCredential(ctx context.Context, r Recovery, a Access, role string, expiry time.Time) (Credential, error) {
	out, err := NewCredential(expiry)
	if err != nil {
		return out, err
	}
	return out, InstallCredential(ctx, r, a, role, out)
}
func NewCredential(expiry time.Time) (Credential, error) {
	var out Credential
	if !expiry.After(time.Now()) || expiry.After(time.Now().Add(time.Hour+time.Second)) {
		return out, errors.New("invalid credential grant")
	}
	var err error
	out.Username, err = randomName("pgws_")
	if err != nil {
		return out, err
	}
	id := strings.TrimPrefix(out.Username, "pgws_")
	out.ID = fmt.Sprintf("%s-%s-%s-%s-%s", id[:8], id[8:12], id[12:16], id[16:20], id[20:])
	out.ExpiresAt = expiry
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return out, err
	}
	out.Password = hex.EncodeToString(secret[:])
	return out, nil
}
func InstallCredential(ctx context.Context, r Recovery, a Access, role string, out Credential) error {
	if (role != "owner" && role != "reader") || !out.ExpiresAt.After(time.Now()) || len(out.Password) != 64 {
		return errors.New("invalid credential grant")
	}
	if _, e := hex.DecodeString(out.Password); e != nil {
		return errors.New("invalid generated credential")
	}
	expiry := out.ExpiresAt
	s := Source{Host: r.SocketDir, Port: 5432, User: a.Admin, Database: "postgres"}
	conn, err := s.ConnectPrivateAdmin(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	bytes, _ := json.Marshal(struct {
		Credential Credential
		Role       string
	}{out, role})
	marker := fmt.Sprintf("pgws-credential:%x", sha256.Sum256(bytes))
	var prior string
	err = tx.QueryRow(ctx, `SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1`, out.Username).Scan(&prior)
	if err == nil {
		if prior != marker {
			return errors.New("existing credential role has different ownership")
		}
		return nil
	}
	if err != pgx.ErrNoRows {
		return err
	}
	// Generated password and RFC3339 timestamp contain no SQL quote characters.
	if _, err = tx.Exec(ctx, "SET LOCAL password_encryption='scram-sha-256'; CREATE ROLE "+ident(out.Username)+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+out.Password+"' VALID UNTIL '"+expiry.UTC().Format(time.RFC3339Nano)+"'"); err != nil {
		return safeError("credential creation")
	}
	if _, err = tx.Exec(ctx, "COMMENT ON ROLE "+ident(out.Username)+" IS '"+marker+"'"); err != nil {
		return err
	}
	group := a.Owner
	if role == "reader" {
		group = a.Reader
	}
	if _, err = tx.Exec(ctx, "GRANT "+ident(group)+" TO "+ident(out.Username)); err != nil {
		return err
	}
	if role == "reader" {
		if _, err = tx.Exec(ctx, "ALTER ROLE "+ident(out.Username)+" SET default_transaction_read_only=on"); err != nil {
			return err
		}
	}
	for _, db := range a.Databases {
		if _, err = tx.Exec(ctx, "GRANT CONNECT ON DATABASE "+ident(db)+" TO "+ident(out.Username)); err != nil {
			return err
		}
	}
	// SET ROLE NONE must not let credentials create objects with different default ACLs.
	if _, err = tx.Exec(ctx, "ALTER ROLE "+ident(out.Username)+" SET role = '"+group+"'"); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
