package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"pgws/internal/lease"
	"pgws/internal/policyapproval"
)

func TestApprovalReceiptCannotBeMountedOrBorrowed(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	c := Container{ID: "fixture", Spec: Spec{Identity: lease.Identity{Epoch: "epoch", Tenant: "tenant", Project: "project", Workspace: "source", Generation: 1}, DataDir: filepath.Join(root, "data"), ControlDir: filepath.Join(root, "control"), SocketDir: filepath.Join(root, "socket"), SourceSocket: filepath.Join(root, "upstream")}}
	for _, path := range []string{c.Spec.DataDir, c.Spec.ControlDir, c.Spec.SocketDir, c.Spec.SourceSocket} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	p := policyapproval.Permit{Binding: policyapproval.Binding{Authority: "epoch", Tenant: "tenant", Project: "project", Source: "source", SourceEpoch: 1}, Runtime: LogicalRuntimeDigest(c), Path: filepath.Join(root, "permit.json"), PublicKey: make([]byte, 32)}
	if err := ValidateApproval(c, p); err != nil {
		t.Fatal(err)
	}
	for _, mount := range []string{c.Spec.DataDir, c.Spec.ControlDir, c.Spec.SocketDir, c.Spec.SourceSocket} {
		changed := p
		changed.Path = filepath.Join(mount, "permit.json")
		if err := ValidateApproval(c, changed); err == nil {
			t.Fatal("receipt exposed inside container", mount)
		}
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(c.Spec.ControlDir, alias); err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.Path = filepath.Join(alias, "permit.json")
	if err := ValidateApproval(c, changed); err == nil {
		t.Fatal("receipt exposed via symlink")
	}
	borrowed := c
	borrowed.ID = "another-container"
	if err := ValidateApproval(borrowed, p); err == nil {
		t.Fatal("permit borrowed by a replacement container")
	}
	changed = p
	changed.Binding.Project = "other"
	if err := ValidateApproval(c, changed); err == nil {
		t.Fatal("foreign project permit accepted")
	}
}
