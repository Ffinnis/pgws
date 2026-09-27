package host

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type bulkFixture struct {
	Rows          int64   `json:"rows"`
	DatabaseBytes int64   `json:"database_bytes"`
	PayloadBytes  int64   `json:"payload_bytes"`
	LoadSeconds   float64 `json:"load_seconds"`
	FirstChecksum string  `json:"-"`
}

func fillOneGiB(t *testing.T, ctx context.Context, conn *pgx.Conn) bulkFixture {
	t.Helper()
	started := time.Now()
	if _, err := conn.Exec(ctx, `CREATE TABLE bulk_fixture(id bigint PRIMARY KEY,payload bytea NOT NULL,checksum text NOT NULL);
 ALTER TABLE bulk_fixture ALTER COLUMN payload SET STORAGE PLAIN`); err != nil {
		t.Fatal(err)
	}
	var result bulkFixture
	for result.DatabaseBytes < 1<<30 {
		remaining := 8192
		_, err := conn.CopyFrom(ctx, pgx.Identifier{"bulk_fixture"}, []string{"id", "payload", "checksum"}, pgx.CopyFromFunc(func() ([]any, error) {
			if remaining == 0 {
				return nil, nil
			}
			remaining--
			payload := make([]byte, 1900)
			if _, err := rand.Read(payload); err != nil {
				return nil, err
			}
			digest := md5.Sum(payload)
			checksum := hex.EncodeToString(digest[:]) // Integrity marker, not a security primitive.
			result.Rows++
			result.PayloadBytes += int64(len(payload))
			if result.Rows == 1 {
				result.FirstChecksum = checksum
			}
			return []any{result.Rows, payload, checksum}, nil
		}))
		if err != nil {
			t.Fatal("bulk COPY", err)
		}
		if err := conn.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&result.DatabaseBytes); err != nil {
			t.Fatal(err)
		}
		if result.Rows%131072 == 0 {
			t.Logf("ONE_GIB generated rows=%d database_bytes=%d", result.Rows, result.DatabaseBytes)
		}
	}
	if _, err := conn.Exec(ctx, `VACUUM ANALYZE bulk_fixture;`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CHECKPOINT`); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&result.DatabaseBytes); err != nil {
		t.Fatal(err)
	}
	result.LoadSeconds = time.Since(started).Seconds()
	data, _ := json.Marshal(result)
	t.Logf("ONE_GIB source=%s", data)
	return result
}

func verifyOneGiB(t *testing.T, ctx context.Context, conn *pgx.Conn, want bulkFixture) {
	t.Helper()
	var rows, payload, invalid, database int64
	if err := conn.QueryRow(ctx, `SELECT count(*),coalesce(sum(octet_length(payload)),0)::bigint,
 count(*) FILTER (WHERE md5(payload)<>checksum),pg_database_size(current_database()) FROM bulk_fixture`).Scan(&rows, &payload, &invalid, &database); err != nil {
		t.Fatal("full copied data integrity scan", err)
	}
	if rows != want.Rows || payload != want.PayloadBytes || invalid != 0 || database < 1<<30 {
		t.Fatal("one GiB integrity differs", rows, payload, invalid, database)
	}
}

func benchmarkOneGiB(t *testing.T, ctx context.Context, bulk bulkFixture, source, management *pgx.Conn, baseline, cert string, cfg Config,
	cli func(string, ...string) map[string]json.RawMessage, wait func(json.RawMessage)) {
	t.Helper()
	type clone struct {
		ID        string
		Operation json.RawMessage
		Started   time.Time
		Conn      *pgx.Conn
	}
	type measurement struct {
		Workspace     string  `json:"workspace"`
		CreateSeconds float64 `json:"create_seconds"`
		ScanSeconds   float64 `json:"full_integrity_scan_seconds"`
	}
	capacity := func() CapacityReport {
		t.Helper()
		if _, err := source.Exec(ctx, `CHECKPOINT`); err != nil {
			t.Fatal(err)
		}
		c, err := InspectCapacity(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	before := capacity()
	var clones []clone
	for i := 0; i < 3; i++ {
		started := time.Now()
		created := cli(fmt.Sprintf(`{"baseline_id":%q,"task_id":"one-gib-%d","freshness":{"mode":"latest"},"resource_profile":"small","ttl_seconds":900}`, baseline, i), "create", "--file", "-", "--key", fmt.Sprint("one-gib-create-", i))
		var workspace struct{ ID string }
		if json.Unmarshal(created["workspace"], &workspace) != nil || workspace.ID == "" {
			t.Fatal("workspace admission")
		}
		clones = append(clones, clone{ID: workspace.ID, Operation: created["operation"], Started: started})
	}
	connect := func(id string, generation int, key string) *pgx.Conn {
		t.Helper()
		v := cli(fmt.Sprintf(`{"expected_generation":%d,"role":"owner","ttl_seconds":600}`, generation), "credentials", "--id", id, "--file", "-", "--key", key)
		var credential struct {
			Username string
			Password string
			Endpoint struct {
				Hostname string
				Port     int
				Database string
			}
		}
		b, _ := json.Marshal(v)
		if json.Unmarshal(b, &credential) != nil {
			t.Fatal("credential response")
		}
		u := url.URL{Scheme: "postgresql", Host: net.JoinHostPort(credential.Endpoint.Hostname, fmt.Sprint(credential.Endpoint.Port)), Path: "/" + credential.Endpoint.Database, User: url.UserPassword(credential.Username, credential.Password)}
		u.RawQuery = url.Values{"sslmode": {"verify-full"}, "sslrootcert": {cert}}.Encode()
		conn, err := pgx.Connect(ctx, u.String())
		if err != nil {
			t.Fatal("TLS SQL unavailable")
		}
		t.Cleanup(func() { conn.Close(context.Background()) })
		return conn
	}
	// Read durable completion timestamps so earlier integrity scans do not inflate
	// later clones' create measurements. API and test clocks share this VM.
	var measurements []measurement
	for i := range clones {
		wait(clones[i].Operation)
		var completedAt time.Time
		var op struct{ ID string }
		_ = json.Unmarshal(clones[i].Operation, &op)
		if err := management.QueryRow(ctx, "SELECT completed_at FROM pgws_control.operations WHERE id=$1 AND status='succeeded'", op.ID).Scan(&completedAt); err != nil || completedAt.IsZero() {
			t.Fatal("operation completion time missing")
		}
		seconds := completedAt.Sub(clones[i].Started).Seconds()
		if seconds < 0 {
			t.Fatal("operation completion clock moved backwards")
		}
		clones[i].Conn = connect(clones[i].ID, 1, fmt.Sprint("one-gib-credential-", i))
		scanStarted := time.Now()
		verifyOneGiB(t, ctx, clones[i].Conn, bulk)
		measurements = append(measurements, measurement{clones[i].ID, seconds, time.Since(scanStarted).Seconds()})
		t.Logf("ONE_GIB clone=%d create_seconds=%.3f full_scan_seconds=%.3f", i, seconds, time.Since(scanStarted).Seconds())
	}
	withClones := capacity()
	for i, c := range clones {
		if _, err := c.Conn.Exec(ctx, `UPDATE fixture SET value=$1`, fmt.Sprint("clone-", i)); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Conn.Exec(ctx, `UPDATE bulk_fixture SET payload=set_byte(payload,0,(get_byte(payload,0)+$1)%256),
 checksum=md5(set_byte(payload,0,(get_byte(payload,0)+$1)%256)) WHERE id<=2048`, i+1); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range clones {
		var value string
		if err := c.Conn.QueryRow(ctx, `SELECT value FROM fixture WHERE id=1`).Scan(&value); err != nil || value != fmt.Sprint("clone-", i) {
			t.Fatal("sibling write isolation", err)
		}
		verifyOneGiB(t, ctx, c.Conn, bulk)
	}
	var original string
	if err := source.QueryRow(ctx, `SELECT checksum FROM bulk_fixture WHERE id=1`).Scan(&original); err != nil || original != bulk.FirstChecksum {
		t.Fatal("source changed", err)
	}
	if err := source.QueryRow(ctx, `SELECT value FROM fixture WHERE id=1`).Scan(&original); err != nil || original != "original" {
		t.Fatal("source changed", err)
	}
	withWrites := capacity()
	remove := func(c clone, generation int) {
		t.Helper()
		c.Conn.Close(context.Background())
		op, _ := json.Marshal(cli("", "delete", "--id", c.ID, "--generation", fmt.Sprint(generation), "--key", "one-gib-delete-"+c.ID))
		wait(op)
		if string(cli("", "get", "--id", c.ID)["phase"]) != `"deleted"` {
			t.Fatal("delete not confirmed")
		}
	}
	remove(clones[1], 1)
	remove(clones[2], 1)
	for _, action := range []string{"pause", "resume"} {
		op, _ := json.Marshal(cli(fmt.Sprintf(`{"action":%q,"expected_generation":1}`, action), "action", "--id", clones[0].ID, "--file", "-", "--key", "one-gib-"+action))
		wait(op)
		if action == "pause" {
			if _, err := clones[0].Conn.Exec(ctx, "SELECT 1"); err == nil {
				t.Fatal("pause kept SQL open")
			}
		}
	}
	resumed := connect(clones[0].ID, 1, "one-gib-resumed")
	if err := resumed.QueryRow(ctx, `SELECT value FROM fixture WHERE id=1`).Scan(&original); err != nil || original != "clone-0" {
		t.Fatal("resume lost writes", err)
	}
	resumed.Close(ctx)
	reset, _ := json.Marshal(cli(fmt.Sprintf(`{"action":"reset","expected_generation":1,"discard_local_changes":true,"baseline_id":%q,"freshness":{"mode":"latest"}}`, baseline), "action", "--id", clones[0].ID, "--file", "-", "--key", "one-gib-reset"))
	wait(reset)
	clones[0].Conn = connect(clones[0].ID, 2, "one-gib-reset-credential")
	verifyOneGiB(t, ctx, clones[0].Conn, bulk)
	if err := clones[0].Conn.QueryRow(ctx, `SELECT checksum FROM bulk_fixture WHERE id=1`).Scan(&original); err != nil || original != bulk.FirstChecksum {
		t.Fatal("reset retained local writes", err)
	}
	remove(clones[0], 2)
	after := capacity()
	report := map[string]any{"source": bulk, "clones": measurements, "before_clones": before, "with_three_clones": withClones, "after_private_writes": withWrites, "after_delete": after,
		"checks": []string{"full payload checksums", "TLS verify-full", "three simultaneous clones", "independent writes", "source unchanged", "pause closes session", "resume retains writes", "reset discards writes", "confirmed deletion"}}
	b, _ := json.Marshal(report)
	t.Logf("ONE_GIB benchmark=%s", b)
}
