package zfs

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgws/internal/lease"
)

func TestLiveZFS(t *testing.T) {
	root := os.Getenv("PGWS_ZFS_ROOT")
	if root == "" {
		t.Skip("run scripts/zfs_lab.py on the dedicated lab VM")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	j, e := lease.OpenJournal(t.TempDir(), "live-epoch")
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	b, e := New("/usr/sbin/zfs", root, os.Getenv("PGWS_ZFS_MOUNTS"), j)
	if e != nil {
		t.Fatal(e)
	}
	c := lease.Command{Identity: lease.Identity{Epoch: "live-epoch", Host: "lab", Tenant: "10000000-0000-4000-8000-000000000001", Project: "10000000-0000-4000-8000-000000000002", Workspace: "10000000-0000-4000-8000-000000000003", Generation: 1, Revision: 1}, Operation: "create", Token: 1}
	baseline, e := b.EnsureBaseline(ctx, c)
	if e != nil {
		t.Fatal("baseline", e)
	}
	c.Token++
	c.Operation = "mount-baseline"
	path, e := b.Mount(ctx, c, baseline, 256<<20)
	if e != nil {
		t.Fatal("mount baseline", e)
	}
	if e = os.WriteFile(filepath.Join(path, "fixture"), []byte("captured"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(filepath.Join(path, "fixture"))
	if e != nil {
		t.Fatal(e)
	}
	e = f.Sync()
	f.Close()
	if e != nil {
		t.Fatal(e)
	}
	c.Token++
	c.Operation = "capture"
	snapshot, e := b.EnsureSnapshot(ctx, c, baseline, "10000000-0000-4000-8000-000000000004")
	if e != nil {
		t.Fatal("snapshot", e)
	}
	if e = os.WriteFile(filepath.Join(path, "fixture"), []byte("new baseline value"), 0600); e != nil {
		t.Fatal(e)
	}
	c.Workspace = "10000000-0000-4000-8000-000000000005"
	c.Token = 1
	c.Operation = "clone"
	clone, e := b.EnsureClone(ctx, c, snapshot)
	if e != nil {
		t.Fatal("clone", e)
	}
	c.Token++
	c.Operation = "mount-clone"
	clonePath, e := b.Mount(ctx, c, clone, 256<<20)
	if e != nil {
		t.Fatal("mount clone", e)
	}
	got, e := os.ReadFile(filepath.Join(clonePath, "fixture"))
	if e != nil || string(got) != "captured" {
		t.Fatal("snapshot bytes differ", string(got), e)
	}
	if e = os.WriteFile(filepath.Join(clonePath, "fixture"), []byte("workspace write"), 0600); e != nil {
		t.Fatal(e)
	}
	got, e = os.ReadFile(filepath.Join(path, "fixture"))
	if e != nil || string(got) != "new baseline value" {
		t.Fatal("clone modified baseline", e)
	}
	c.Token++
	c.Operation = "delete"
	if e = b.DestroyClone(ctx, c, clone); e != nil {
		t.Fatal("delete", e)
	}
	if e = b.DestroyClone(ctx, c, clone); e != nil {
		t.Fatal("delete replay", e)
	}
	evidence, _ := json.Marshal(map[string]any{"baseline": baseline, "snapshot": snapshot, "clone": clone, "independent_writes": true, "delete_replay": true})
	t.Log(string(evidence))
}
