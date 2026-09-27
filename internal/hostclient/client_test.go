package hostclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgws/internal/control"
)

func TestUncertainTransportIsDistinctFromHostRejection(t *testing.T) {
	// Keep the Unix path short on macOS too.
	dir, err := os.MkdirTemp("/tmp", "pgws-rpc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	client := Client{Socket: filepath.Join(dir, "rpc"), Token: strings.Repeat("x", 32)}
	if _, err = client.Execute(context.Background(), control.Task{}); !errors.Is(err, control.ErrHostUnavailable) {
		t.Fatal("missing host was reported as a definite rejection", err)
	}
	listener, err := net.Listen("unix", client.Socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/execute" {
			_, _ = w.Write([]byte(`{"phase":`))
		} else {
			w.WriteHeader(http.StatusConflict)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	if _, err = client.Execute(context.Background(), control.Task{}); !errors.Is(err, control.ErrHostUnavailable) {
		t.Fatal("partial host response was accepted as an outcome", err)
	}
	if err = client.Activate(context.Background(), control.Task{}, "test"); err == nil || errors.Is(err, control.ErrHostUnavailable) {
		t.Fatal("explicit host rejection became a transport retry", err)
	}
}
