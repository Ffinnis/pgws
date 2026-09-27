package config

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixSocketRecoveryPreservesLiveListenersAndFiles(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "pgws-sock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "control.sock")
	l, err := ListenPrivateUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := ListenPrivateUnix(path); err == nil {
		second.Close()
		t.Fatal("stole active socket")
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	l, err = ListenPrivateUnix(path)
	if err != nil {
		t.Fatal("could not recover crashed socket", err)
	}
	l.Close()
	if err = os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if l, err = ListenPrivateUnix(path); err == nil {
		l.Close()
		t.Fatal("removed regular file")
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "keep" {
		t.Fatal("file changed", err)
	}
}
