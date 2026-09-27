package atomicfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestReplaceAndPublicationFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state")
	for _, value := range []string{"first", "second"} {
		if err := Replace(path, []byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	want := errors.New("publication failed")
	if err := publish(path, []byte("discarded"), func(string, string) error { return want }); !errors.Is(err, want) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "second" {
		t.Fatalf("failed publication changed destination: %q %v", data, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private mode lost: %v %v", info, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v %v", entries, err)
	}
	if err := Replace(filepath.Join(dir, "absent", "file"), nil); !os.IsNotExist(err) {
		t.Fatalf("unexpected directory preparation: %v", err)
	}
	if err := Replace(dir, nil); err == nil {
		t.Fatal("replaced a directory")
	}
}

func TestCreateHasOneWinner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt")
	var group sync.WaitGroup
	winners := make(chan string, 32)
	for i := range 32 {
		group.Go(func() {
			value := fmt.Sprint(i)
			err := Create(path, []byte(value))
			if err == nil {
				winners <- value
			} else if !errors.Is(err, os.ErrExist) {
				t.Errorf("unexpected publication failure: %v", err)
			}
		})
	}
	group.Wait()
	close(winners)
	if len(winners) != 1 {
		t.Fatalf("got %d winners", len(winners))
	}
	winner := <-winners
	data, err := os.ReadFile(path)
	if err != nil || string(data) != winner {
		t.Fatalf("winner overwritten: %q %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files leaked: %v %v", entries, err)
	}
}
