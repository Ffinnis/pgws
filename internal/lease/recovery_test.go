package lease

import (
	"strings"
	"testing"
)

func TestRecoveryJournalRetainsFenceAcrossEpochs(t *testing.T) {
	dir := t.TempDir()
	j, err := OpenJournal(dir, "old")
	if err != nil {
		t.Fatal(err)
	}
	command := Command{Identity: Identity{Epoch: "old", Tenant: "tenant", Project: "project", Workspace: "workspace", Host: "host", Generation: 7, Revision: 19}, Token: 213, Operation: "old-job", Kind: "create", PayloadHash: strings.Repeat("a", 64)}
	if _, _, err = j.Accept(command); err != nil {
		t.Fatal(err)
	}
	if second, err := OpenRecoveryJournal(dir, "old", "new"); err == nil {
		second.Close()
		t.Fatal("recovery raced running owner")
	}
	j.Close()
	j, err = OpenRecoveryJournal(dir, "old", "new")
	if err != nil {
		t.Fatal(err)
	}
	records, err := j.AdvanceEpoch("old", "new")
	if err != nil || len(records) != 1 || records[0].Command != command {
		t.Fatal("high-water mark lost", err)
	}
	if err = j.Complete(command); err == nil {
		t.Fatal("old completion crossed authority")
	}
	if _, _, err = j.Accept(command); err == nil {
		t.Fatal("old command crossed authority")
	}
	unseen := command
	unseen.Workspace = "new-resource"
	if _, _, err = j.Accept(unseen); err == nil {
		t.Fatal("old authority created an unseen resource")
	}
	j.Close()
	if stale, err := OpenJournal(dir, "old"); err == nil {
		stale.Close()
		t.Fatal("old configuration restarted")
	}
	j, err = OpenRecoveryJournal(dir, "old", "new")
	if err != nil {
		t.Fatal("resume partial recovery", err)
	}
	if _, err = j.AdvanceEpoch("old", "new"); err != nil {
		t.Fatal("repeat uncertain publication", err)
	}
	j.Close()
	j, err = OpenJournal(dir, "new")
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	current := command
	current.Epoch = "new"
	if _, _, err = j.Accept(current); err == nil {
		t.Fatal("restored low fence accepted")
	}
	current.Token++
	current.Revision++
	current.Operation = "new-job"
	if _, _, err = j.Accept(current); err != nil {
		t.Fatal("higher new authority rejected", err)
	}
}

func TestRecoveryCannotCreateMissingHighWaterJournal(t *testing.T) {
	if j, err := OpenRecoveryJournal(t.TempDir(), "old", "new"); err == nil {
		j.Close()
		t.Fatal("invented missing journal")
	}
}
