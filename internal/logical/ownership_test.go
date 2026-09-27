package logical

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSlotOwnershipPrivateAtomicReceipt(t *testing.T) {
	id := "12345678-1234-1234-1234-123456789abc"
	r := SlotOwnership{Format: "pgws.logical-slot.v1", Source: Identity{Source: id, Epoch: 1, Timeline: 1, SystemID: "12345"}, Database: "source", Slot: "pgws_l_" + strings.ReplaceAll(id, "-", "") + "_1", Publication: "pgws_p_" + strings.ReplaceAll(id, "-", "") + "_1", PublicationOID: 123, Contract: strings.Repeat("a", 64), SeedLSN: "0/100", ObservedAt: time.Now().UTC()}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "slot.json")
	if err := os.WriteFile(path+".applied", []byte("abandoned"), 0600); err != nil {
		t.Fatal(err)
	}
	if CheckSlotOwnershipDestination(path) == nil {
		t.Fatal("new seed ignored abandoned progress")
	}
	if err := os.Remove(path + ".applied"); err != nil {
		t.Fatal(err)
	}
	if err := CheckSlotOwnershipDestination(path); err != nil {
		t.Fatal(err)
	}
	if err := WriteSlotOwnership(path, r); err != nil {
		t.Fatal(err)
	}
	if err := WriteSlotOwnership(path, r); err != nil {
		t.Fatal("exact receipt replay", err)
	}
	if err := CheckSlotOwnershipDestination(path); err == nil {
		t.Fatal("new seed adopted an old receipt destination")
	}
	loaded, err := ReadSlotOwnership(path)
	if err != nil || loaded != r {
		t.Fatal("ownership round trip differs", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r.SeedLSN = "0/200"
	if err = WriteSlotOwnership(path, r); err == nil {
		t.Fatal("changed ownership replaced a receipt")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing receipt changed")
	}
	link := filepath.Join(dir, "link.json")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadSlotOwnership(link); err == nil {
		t.Fatal("symlink receipt accepted")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadSlotOwnership(path); err == nil {
		t.Fatal("public receipt accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(before), `"format":`, `"format":"pgws.logical-slot.v1","format":`, 1)
	if err = os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadSlotOwnership(path); err == nil {
		t.Fatal("duplicate receipt field accepted")
	}
	if err = os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err = WriteSlotOwnership(filepath.Join(dir, "public-dir.json"), r); err == nil {
		t.Fatal("public receipt directory accepted")
	}
}
