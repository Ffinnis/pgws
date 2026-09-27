package discover

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func fixture(t *testing.T) (*pgx.Conn, *pgx.ConnConfig, Request) {
	t.Helper()
	dsn := os.Getenv("PGWS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL integration cluster")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	var random [8]byte
	if _, err = rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	suffix := hex.EncodeToString(random[:])
	db, role := "discovery_"+suffix, "reader_"+suffix
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{db}.Sanitize()+" TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{db}.Sanitize()+" WITH (FORCE)")
		admin.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{role}.Sanitize())
		admin.Close(context.Background())
	})
	if _, err = admin.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"); err != nil {
		t.Fatal(err)
	}
	cfg, _ := pgx.ParseConfig(dsn)
	cfg.Database = db
	owner, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close(context.Background()) })
	if _, err = owner.Exec(ctx, `CREATE TABLE public.people(id bigint PRIMARY KEY,email varchar(64) UNIQUE, note text, payload jsonb, unicode varchar(64), oversized varchar(65), derived bigint GENERATED ALWAYS AS (id+1) STORED);
 INSERT INTO public.people(id,email,note,payload,unicode,oversized) SELECT n,'private-canary@example.org',repeat('private-canary',100000),'{}',repeat('😀',64),'private-canary' FROM generate_series(1,1)n;
 UPDATE people SET email='private-canary-1@example.org';
 INSERT INTO people(id,email,note,unicode) SELECT n,'private-canary-'||n||'@example.org','private-canary',repeat('😀',64) FROM generate_series(2,64)n;
 ANALYZE people;`); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Exec(ctx, "GRANT USAGE ON SCHEMA public TO "+pgx.Identifier{role}.Sanitize()+"; GRANT SELECT ON ALL TABLES IN SCHEMA public TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	cfg.User = role
	cfg.Password = ""
	return owner, cfg, Request{Source: "12345678-1234-1234-1234-123456789abc", Epoch: 1, Schema: "public", Table: "people"}
}

func TestBoundedPostgresProfiles(t *testing.T) {
	owner, cfg, request := fixture(t)
	result, err := Profile(context.Background(), cfg, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.SampledRows != 64 || result.Attempts != 1 || result.ReturnedBytes > MaxBytes || !result.Review || len(result.Profiles) != 7 || result.SchemaHash == "" {
		t.Fatalf("unexpected evidence: rows=%d attempts=%d profiles=%d", result.SampledRows, result.Attempts, len(result.Profiles))
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "private-canary") || strings.Contains(string(encoded), "😀") {
		t.Fatal("raw values escaped aggregate profile")
	}
	for _, p := range result.Profiles {
		switch p.Column {
		case "id":
			if p.Numeric["primary_key"] != 1 || p.Numeric["sample_distinct_fraction"] != 1 {
				t.Fatal("key metadata/aggregate")
			}
		case "email":
			if p.Numeric["email_pattern_fraction"] != 1 || p.Numeric["unique_constraint"] != 1 {
				t.Fatal("email aggregate")
			}
		case "unicode":
			if p.Numeric["max_length_log"] != 1 {
				t.Fatal("256-byte multibyte bound")
			}
		default:
			if p.Numeric["sample_present"] != 0 || !slices.Contains(p.Evidence.ReviewFlags, "unsupported_type") {
				t.Fatal("unbounded or generated field was read")
			}
		}
	}
	again, err := Profile(context.Background(), cfg, request)
	if err != nil || again.SchemaHash != result.SchemaHash {
		t.Fatal("unstable metadata fingerprint", err)
	}
	if _, err = owner.Exec(context.Background(), "ALTER TABLE people ADD COLUMN extra int"); err != nil {
		t.Fatal(err)
	}
	again, err = Profile(context.Background(), cfg, request)
	if err != nil || again.SchemaHash == result.SchemaHash {
		t.Fatal("schema drift not bound", err)
	}
}

func TestDiscoveryRejectsUnsafeRolesAndRelations(t *testing.T) {
	owner, cfg, request := fixture(t)
	if _, err := Profile(context.Background(), owner.Config(), request); err == nil {
		t.Fatal("superuser discovery allowed")
	}
	ctx := context.Background()
	for _, statement := range []string{
		"GRANT UPDATE ON people TO " + pgx.Identifier{cfg.User}.Sanitize(),
		"ALTER TABLE people ENABLE ROW LEVEL SECURITY",
		`ALTER TABLE people ADD COLUMN "literal-private@example.org" int`,
	} {
		tx, err := owner.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Commit so the separate reader observes the change, then undo explicitly.
		if _, err = tx.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		_, err = Profile(ctx, cfg, request)
		if err == nil || strings.Contains(err.Error(), "literal-private") {
			t.Fatal("unsafe relation accepted or echoed")
		}
		if _, err = owner.Exec(ctx, "REVOKE UPDATE ON people FROM "+pgx.Identifier{cfg.User}.Sanitize()+`; ALTER TABLE people DISABLE ROW LEVEL SECURITY; ALTER TABLE people DROP COLUMN IF EXISTS "literal-private@example.org"`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := owner.Exec(ctx, "TRUNCATE people"); err != nil {
		t.Fatal(err)
	}
	r, err := Profile(ctx, cfg, request)
	if err != nil || r.Attempts != 2 || r.SampledRows != 0 || r.IncompleteReason != "insufficient_sample" {
		t.Fatal("empty sample treated as complete", err)
	}
}

func TestDiscoveryDeadlineClosesConnection(t *testing.T) {
	owner, cfg, request := fixture(t)
	ctx := context.Background()
	lock, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Rollback(ctx)
	if _, err = lock.Exec(ctx, "LOCK TABLE people IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	request.StatementTimeout = 100 * time.Millisecond
	request.JobTimeout = 150 * time.Millisecond
	start := time.Now()
	if _, err = Profile(ctx, cfg, request); err == nil {
		t.Fatal("blocked relation returned profiles")
	}
	if time.Since(start) > time.Second {
		t.Fatal("bounded job did not cancel")
	}
	deadline := time.Now().Add(time.Second)
	for {
		var connections int
		if err = lock.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND usename=$1", cfg.User).Scan(&connections); err != nil {
			t.Fatal(err)
		}
		if connections == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("discovery connection survived cancellation")
		}
		lock.Exec(ctx, "SELECT pg_stat_clear_snapshot()")
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBoundedReaderTypeAndInputMatrix(t *testing.T) {
	for _, c := range []column{{OID: 25, Builtin: true}, {OID: 3802, Builtin: true}, {OID: 1043, Modifier: 69, Builtin: true}, {OID: 1043, Modifier: -1, Builtin: true}, {OID: 23, Builtin: false}, {OID: 23, Builtin: true, Generated: true}} {
		if bounded(c) {
			t.Fatal("unsafe read type")
		}
	}
	for _, c := range []column{{OID: 1043, Modifier: 68, Builtin: true}, {OID: 20, Modifier: -1, Builtin: true}, {OID: 1184, Modifier: 6, Builtin: true}} {
		if !bounded(c) {
			t.Fatal("bounded type rejected")
		}
	}
	for _, name := range []string{"literal@example.org", "sk_live_private", "AKIA_PRIVATE", "a\x00b", strings.Repeat("x", 64)} {
		if identifier(name) {
			t.Fatal("protected metadata accepted")
		}
	}
	cfg, _ := pgx.ParseConfig("host=127.0.0.1 user=reader dbname=source")
	if _, err := Profile(context.Background(), cfg, Request{}); err == nil {
		t.Fatal("remote/unbound discovery allowed")
	}
}
