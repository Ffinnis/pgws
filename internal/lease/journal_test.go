package lease

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestJournalPublicationFailurePoisonsUntilRestart(t *testing.T) {
	folder := t.TempDir()
	j, err := OpenJournal(folder, "epoch")
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	path := filepath.Join(folder, "journal.json")
	backup := filepath.Join(folder, "saved.json")
	if err = os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	c := Command{Identity: Identity{"epoch", "tenant", "project", "workspace", "host", 1, 1}, Operation: "operation", Token: 1, Kind: "clone", PayloadHash: strings.Repeat("a", 64)}
	if _, _, err = j.Accept(c); err == nil {
		t.Fatal("accepted an intent after publication failure")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(backup, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err = j.Accept(c); !errors.Is(err, ErrFence) {
		t.Fatal("poisoned journal admitted more work", err)
	}
	j.Close()
	j, err = OpenJournal(folder, "epoch")
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if _, replay, err := j.Accept(c); err != nil || replay {
		t.Fatal("failed intent appeared as durable on restart", replay, err)
	}
}

func TestJournalSurvivesRestartAndRejectsStaleCommands(t *testing.T) {
	folder := t.TempDir()
	j, e := OpenJournal(folder, "epoch")
	if e != nil {
		t.Fatal(e)
	}
	if second, e := OpenJournal(folder, "epoch"); e == nil {
		second.Close()
		t.Fatal("concurrent journal owner accepted")
	}
	c := Command{Identity: Identity{"epoch", "tenant", "project", "workspace", "host", 1, 1}, Operation: "operation-a", Token: 1, Kind: "clone", PayloadHash: strings.Repeat("a", 64)}
	if _, replay, e := j.Accept(c); e != nil || replay {
		t.Fatal("first intent", replay, e)
	}
	if e = j.Complete(c); e != nil {
		t.Fatal(e)
	}
	j.Close()
	j, e = OpenJournal(folder, "epoch")
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if record, replay, e := j.Accept(c); e != nil || !replay || !record.Completed {
		t.Fatal("durable replay", record, replay, e)
	}
	changed := c
	changed.Kind = "destroy"
	if _, _, e = j.Accept(changed); e == nil {
		t.Fatal("conflicting command accepted")
	}
	next := c
	next.Token = 2
	next.Revision = 2
	next.Operation = "operation-b"
	if _, _, e = j.Accept(next); e != nil {
		t.Fatal(e)
	}
	if e = j.Complete(c); e == nil {
		t.Fatal("old completion accepted")
	}
	if _, _, e = j.Accept(c); e == nil {
		t.Fatal("old fence accepted")
	}
	j.Close()
	if other, e := OpenJournal(folder, "new-epoch"); e == nil {
		other.Close()
		t.Fatal("silently adopted restored authority")
	}
	if e = os.WriteFile(filepath.Join(folder, "journal.json"), []byte("corrupted"), 0600); e != nil {
		t.Fatal(e)
	}
	if broken, e := OpenJournal(folder, "epoch"); e == nil {
		broken.Close()
		t.Fatal("corrupt journal accepted")
	}
}
