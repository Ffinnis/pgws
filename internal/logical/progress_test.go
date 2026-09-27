package logical

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestDurableAppliedReceipt(t *testing.T) {
	id := "12345678-1234-1234-1234-123456789abc"
	owned := SlotOwnership{Format: "pgws.logical-slot.v1", Source: Identity{Source: id, Epoch: 1, Timeline: 1, SystemID: "12345"}, Database: "source", Slot: "pgws_l_" + strings.ReplaceAll(id, "-", "") + "_1", Publication: "pgws_p_" + strings.ReplaceAll(id, "-", "") + "_1", PublicationOID: 123, Contract: strings.Repeat("a", 64), SeedLSN: "0/100", ObservedAt: time.Now().UTC()}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "slot.json")
	if err := WriteSlotOwnership(path, owned); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadApplied(path, owned); err == nil {
		t.Fatal("missing progress counted as completed seed")
	}
	for _, position := range []string{"0/0", "bad", "0/FF"} {
		if PersistApplied(path, position) == nil {
			t.Fatal("invalid progress accepted")
		}
	}
	for _, position := range []string{"0/100", "0/300", "0/200", "0/100"} {
		if err := PersistApplied(path, position); err != nil {
			t.Fatal(err)
		}
	}
	progress, err := ReadApplied(path, owned)
	if err != nil || progress.AppliedLSN != "0/300" {
		t.Fatal("replay lowered committed high water", err)
	}
	changed := owned
	changed.ObservedAt = changed.ObservedAt.Add(time.Second)
	if _, err = ReadApplied(path, changed); err == nil {
		t.Fatal("progress matched a different creation")
	}
	before, _ := os.ReadFile(path + ".applied")
	lock, err := os.OpenFile(path+".lock", os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if PersistApplied(path, "0/400") == nil {
		t.Fatal("concurrent writer bypassed progress lock")
	}
	lock.Close()
	after, _ := os.ReadFile(path + ".applied")
	if string(before) != string(after) {
		t.Fatal("failed writer changed receipt")
	}
	if err = os.Chmod(path+".applied", 0644); err != nil {
		t.Fatal(err)
	}
	if PersistApplied(path, "0/400") == nil {
		t.Fatal("public receipt was overwritten")
	}
	if err = os.Chmod(path+".applied", 0600); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(before), `"format":`, `"format":"pgws.logical-applied.v1","format":`, 1)
	if err = os.WriteFile(path+".applied", []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if PersistApplied(path, "0/400") == nil {
		t.Fatal("corrupt receipt was overwritten")
	}
	if err = os.Remove(path + ".applied"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path, path+".applied"); err != nil {
		t.Fatal(err)
	}
	if PersistApplied(path, "0/400") == nil {
		t.Fatal("symlink progress was replaced")
	}
	// The ownership bytes, including its contract, are part of every progress
	// record; substituting a generation cannot reuse historical apply evidence.
	if err = os.Remove(path + ".applied"); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".applied", before, 0600); err != nil {
		t.Fatal(err)
	}
	changed.Contract = strings.Repeat("b", 64)
	data, _ := json.Marshal(changed)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if PersistApplied(path, "0/400") == nil {
		t.Fatal("changed ownership reused prior progress")
	}
}
