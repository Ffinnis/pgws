package physical

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStreamingPreparationRecovery(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := Recovery{DataDir: filepath.Join(root, "data"), ControlDir: filepath.Join(root, "controls"), SocketDir: filepath.Join(root, "socket"), SourceUser: "postgres", Barrier: Barrier{Identity: Identity{SystemID: "123", Timeline: 1}, LSN: "0/100"}, Settings: map[string]string{"max_connections": "20", "max_prepared_transactions": "0", "max_locks_per_transaction": "64", "max_wal_senders": "10", "max_worker_processes": "8"}}
	for _, dir := range []string{r.DataDir, filepath.Join(r.DataDir, "pg_wal"), filepath.Join(r.DataDir, "pg_tblspc")} {
		if err = os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(filepath.Join(r.DataDir, "PG_VERSION"), []byte("18\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := Source{Host: filepath.Join(root, "upstream"), Port: 5432, User: "postgres", Database: "postgres", ExpectedSystemID: "123"}
	source.PasswordFile = filepath.Join(root, "source-secret")
	if err = os.WriteFile(source.PasswordFile, []byte("initial-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	slot := "pgws_10000000000040008000000000000001_g1"
	tools := Tools{}
	// The process died after disconnected controls were published, before
	// upstream credentials and streaming settings were complete.
	if err = tools.PrepareDisconnected(r); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(r.ControlDir, "source.pgpass"), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(r.ControlDir, "unexpected"), []byte("retain"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = tools.ResumeStreamingPreparation(r, source, slot); err == nil {
		t.Fatal("unknown partial control file removed")
	}
	if err = os.Remove(filepath.Join(r.ControlDir, "unexpected")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(r.DataDir, "postmaster.pid"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = tools.ResumeStreamingPreparation(r, source, slot); err == nil {
		t.Fatal("running generation was reconfigured")
	}
	if err = os.Remove(filepath.Join(r.DataDir, "postmaster.pid")); err != nil {
		t.Fatal(err)
	}
	if err = tools.ResumeStreamingPreparation(r, source, slot); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(r.ControlDir, "postgresql.conf"))
	if err != nil || strings.Count(string(before), "primary_slot_name = '"+slot+"'") != 1 {
		t.Fatal("streaming settings missing", err)
	}
	if err = tools.ResumeStreamingPreparation(r, source, slot); err != nil {
		t.Fatal("completed preparation replay", err)
	}
	after, err := os.ReadFile(filepath.Join(r.ControlDir, "postgresql.conf"))
	if err != nil || string(before) != string(after) {
		t.Fatal("retry changed completed controls", err)
	}
	changed := source
	changed.Port++
	if err = tools.ResumeStreamingPreparation(r, changed, slot); err == nil {
		t.Fatal("retry replaced upstream settings")
	}
	passfile := filepath.Join(r.ControlDir, "source.pgpass")
	old, err := os.Open(passfile)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	if err = os.WriteFile(source.PasswordFile, []byte("rotated:secret\\value"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = tools.RefreshStreamingSecret(r, changed, slot); err == nil {
		t.Fatal("secret rotation changed upstream")
	}
	if err = tools.RefreshStreamingSecret(r, source, slot); err != nil {
		t.Fatal(err)
	}
	prior, err := io.ReadAll(old)
	if err != nil || !strings.Contains(string(prior), "initial-secret") {
		t.Fatal("rotation truncated an already open passfile", err)
	}
	rotated, err := os.ReadFile(passfile)
	if err != nil || string(rotated) != "*:*:*:postgres:rotated\\:secret\\\\value\n" {
		t.Fatal("rotated passfile contents differ", err)
	}
	info, err := os.Stat(passfile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("rotated passfile is not private", err)
	}
	if err = os.WriteFile(source.PasswordFile, []byte("bad\nsecret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = tools.RefreshStreamingSecret(r, source, slot); err == nil {
		t.Fatal("invalid rotated secret accepted")
	}
	unchanged, err := os.ReadFile(passfile)
	if err != nil || string(unchanged) != string(rotated) {
		t.Fatal("failed rotation destroyed the prior passfile", err)
	}
	for _, name := range []string{"streaming-plan.json", "recovery-plan.json", "postgresql.conf"} {
		data, err := os.ReadFile(filepath.Join(r.ControlDir, name))
		if err != nil || strings.Contains(string(data), "initial-secret") || strings.Contains(string(data), "rotated:secret") {
			t.Fatal("streaming metadata contains a secret", err)
		}
	}
	if err = os.WriteFile(filepath.Join(r.ControlDir, "streaming-plan.json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = tools.ResumeStreamingPreparation(r, source, slot); err == nil {
		t.Fatal("incomplete streaming plan accepted")
	}
}
