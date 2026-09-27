package zfs

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"pgws/internal/lease"
)

func TestLiveProjectAllocation(t *testing.T) {
	root := os.Getenv("PGWS_ZFS_ROOT")
	if root == "" {
		t.Skip("requires the disposable OpenZFS lab")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	j, err := lease.OpenJournal(t.TempDir(), "quota-epoch")
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	b, err := New("/usr/sbin/zfs", root, os.Getenv("PGWS_ZFS_MOUNTS"), j)
	if err != nil {
		t.Fatal(err)
	}
	c := lease.Command{Identity: lease.Identity{Epoch: "quota-epoch", Host: "lab", Tenant: "20000000-0000-4000-8000-000000000001", Project: "20000000-0000-4000-8000-000000000002", Workspace: "20000000-0000-4000-8000-000000000003", Generation: 1, Revision: 1}, Operation: "baseline", Token: 1}
	project, err := b.EnsureProject(ctx, c, 128<<20, Ref{})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := b.EnsureBaseline(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	c.Token++
	path, err := b.Mount(ctx, c, baseline, 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	chunk := make([]byte, 1<<20)
	if _, err = rand.Read(chunk); err != nil {
		t.Fatal(err)
	}
	write := func(path string, megabytes int, allowQuota bool) int {
		t.Helper()
		file, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			t.Fatal(e)
		}
		defer file.Close()
		for n := 0; n < megabytes; n++ {
			_, e = file.Write(chunk)
			if e == nil {
				e = file.Sync()
			}
			if e != nil {
				if allowQuota && (errors.Is(e, syscall.EDQUOT) || errors.Is(e, syscall.ENOSPC)) {
					return n
				}
				t.Fatal(e)
			}
		}
		if allowQuota {
			t.Fatal("project quota did not stop physical growth")
		}
		return megabytes
	}
	write(filepath.Join(path, "origin"), 48, false)
	c.Token++
	snapshot, err := b.EnsureSnapshot(ctx, c, baseline, "20000000-0000-4000-8000-000000000004")
	if err != nil {
		t.Fatal(err)
	}
	before, err := b.ProjectAllocation(ctx, c, project)
	if err != nil {
		t.Fatal(err)
	}
	c.Workspace = "20000000-0000-4000-8000-000000000005"
	c.Token = 1
	clone, err := b.EnsureClone(ctx, c, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	c.Token++
	clonePath, err := b.Mount(ctx, c, clone, 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := b.ProjectAllocation(ctx, c, project)
	if err != nil || shared.Used-before.Used > 8<<20 {
		t.Fatal("shared origin charged twice", before.Used, shared.Used, err)
	}
	written := write(filepath.Join(clonePath, "growth"), 140, true)
	if written < 32 || written > 90 {
		t.Fatal("unexpected project growth allowance", written)
	}
	full, err := b.ProjectAllocation(ctx, c, project)
	if err != nil || full.Quota != 128<<20 || full.Used < 100<<20 {
		t.Fatal("project allocation evidence", full, err)
	}
	// Another project can still write: the failure was the parent quota, not a
	// full cell or the clone's deliberately larger 256 MiB refquota.
	other := c
	other.Project = "30000000-0000-4000-8000-000000000002"
	other.Workspace = "30000000-0000-4000-8000-000000000003"
	other.Token = 1
	if _, err = b.EnsureProject(ctx, other, 128<<20, Ref{}); err != nil {
		t.Fatal(err)
	}
	otherBase, err := b.EnsureBaseline(ctx, other)
	if err != nil {
		t.Fatal(err)
	}
	other.Token++
	otherPath, err := b.Mount(ctx, other, otherBase, 256<<20)
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(otherPath, "independent"), 4, false)
	c.Token++
	if err = b.DestroyClone(ctx, c, clone); err != nil {
		t.Fatal("quota cleanup", err)
	}
	recovered, err := b.ProjectAllocation(ctx, c, project)
	if err != nil || recovered.Available < 32<<20 {
		t.Fatal("deleting clone did not restore growth budget", recovered, err)
	}
	report, _ := json.Marshal(map[string]any{"project_quota": full.Quota, "clone_refquota": 256 << 20, "shared_origin_bytes": 48 << 20, "clone_growth_mib_before_quota": written, "parent_used_before_clone": before.Used, "parent_used_after_clone": shared.Used, "parent_used_at_quota": full.Used, "other_project_write": true, "available_after_cleanup": recovered.Available})
	t.Log(string(report))
}
