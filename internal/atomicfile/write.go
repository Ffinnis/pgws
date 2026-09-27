// Package atomicfile publishes private files after syncing their contents.
// The caller owns directory preparation, serialization and synchronization.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Replace atomically replaces path and syncs its parent directory.
func Replace(path string, data []byte) error {
	return publish(path, data, os.Rename)
}

// Create publishes without replacing an existing path, returning os.ErrExist
// when another writer wins. Both modes create files with permission 0600.
func Create(path string, data []byte) error {
	return publish(path, data, os.Link)
}

// A directory sync error can occur after publication. Callers must treat such
// an error as uncertain durability, not proof that the destination is unchanged.
func publish(path string, data []byte, install func(string, string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".publish-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = install(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
