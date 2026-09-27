package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgws/internal/lease"
	"pgws/internal/physical"
)

func TestLiveContainer(t *testing.T) {
	if os.Getenv("PGWS_OCI_LAB") != "1" {
		t.Skip("requires dedicated Linux lab VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root := t.TempDir()
	s := Spec{Identity: lease.Identity{Epoch: "test-epoch", Tenant: "10000000-0000-4000-8000-000000000001", Project: "10000000-0000-4000-8000-000000000002", Workspace: "10000000-0000-4000-8000-000000000003", Host: "lab", Generation: 1, Revision: 1}, DataDir: filepath.Join(root, "data"), ControlDir: filepath.Join(root, "control"), SocketDir: filepath.Join(root, "socket"), MemoryBytes: 512 << 20}
	for _, p := range []string{s.DataDir, s.ControlDir, s.SocketDir} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.Chown(p, 999, 999); e != nil {
			t.Fatal(e)
		}
	}
	o := OCI{Binary: "/usr/bin/docker", Image: PostgresImage}
	c, e := o.Ensure(ctx, s)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 20*time.Second)
		defer done()
		if e := o.Remove(cleanup, c); e != nil {
			t.Error(e)
		}
	}()
	tools := o.Tools(c)
	if e = tools.Require18(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = tools.Executor.Run(ctx, "initdb", nil, "-D", s.DataDir, "-U", "postgres", "--auth-local=trust", "--auth-host=reject", "--no-locale", "--encoding=UTF8"); e != nil {
		t.Fatal(e)
	}
	conf := "data_directory='" + s.DataDir + "'\nlisten_addresses=''\nunix_socket_directories='" + s.SocketDir + "'\nshared_buffers='32MB'\n"
	path := filepath.Join(s.ControlDir, "postgresql.conf")
	if e = os.WriteFile(path, []byte(conf), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = tools.Executor.Run(ctx, "pg_ctl", nil, "-D", s.DataDir, "-l", filepath.Join(s.ControlDir, "postgres.log"), "-o", "-c config_file="+path, "-w", "start"); e != nil {
		t.Fatal(e)
	}
	source := physical.Source{Host: s.SocketDir, Port: 5432, User: "postgres", Database: "postgres", ApprovedDatabases: []string{"postgres"}}
	conn, e := source.Connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(context.Background())
	var version int
	if e = conn.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&version); e != nil || version/10000 != 18 {
		t.Fatal(version, e)
	}
	if _, e = conn.Exec(ctx, "CREATE TABLE fixture(id int); INSERT INTO fixture VALUES (1)"); e != nil {
		t.Fatal(e)
	}
	if again, e := o.Ensure(ctx, s); e != nil || again.ID != c.ID {
		t.Fatal("runtime replay", again, e)
	}
	changed := s
	changed.MemoryBytes = 1 << 30
	if _, e = o.Ensure(ctx, changed); e == nil {
		t.Fatal("changed runtime spec accepted")
	}
	if e = tools.Stop(ctx, s.DataDir); e != nil {
		t.Fatal(e)
	}
}
