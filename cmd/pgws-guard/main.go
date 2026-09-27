// pgws-guard is intentionally a separate process from the host worker.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"pgws/internal/config"
	"pgws/internal/ingress"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: pgws-guard CONFIG.json")
	}
	b, e := os.ReadFile(os.Args[1])
	if e != nil || len(b) > 16384 {
		return errors.New("guard configuration unavailable")
	}
	var c ingress.Config
	if e = json.Unmarshal(b, &c); e != nil {
		return errors.New("invalid guard configuration")
	}
	lock, e := os.OpenFile(c.StateFile+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("guard is already running")
	}
	s, e := ingress.New(c)
	if e != nil {
		return e
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	// The exclusive lock permits recovery of this guard's refused stale socket.
	control := filepath.Join(filepath.Dir(c.StateFile), "guard.sock")
	admin, e := config.ListenPrivateUnix(control)
	if e != nil {
		return e
	}
	defer admin.Close()
	defer os.Remove(control)
	if e = os.Chmod(control, 0600); e != nil {
		return e
	}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	defer listener.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /lease", func(w http.ResponseWriter, r *http.Request) {
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8192))
		if e != nil {
			http.Error(w, "lease rejected", 403)
			return
		}
		if e = s.Install(string(b)); e != nil {
			http.Error(w, e.Error(), 403)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /credential", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Username string    `json:"username"`
			Expiry   time.Time `json:"expires_at"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in) != nil {
			http.Error(w, "credential request invalid", 400)
			return
		}
		if err := s.RegisterCredential(in.Username, in.Expiry); err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /close", func(w http.ResponseWriter, r *http.Request) { _ = s.CloseAccess(); w.WriteHeader(204) })
	mux.HandleFunc("POST /revoke_credentials", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Usernames []string `json:"usernames"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in) != nil || s.RevokeCredentials(in.Usernames) != nil {
			http.Error(w, "credential revocation rejected", 403)
			return
		}
		w.WriteHeader(204)
	})
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, r *http.Request) { _ = s.CloseAccess(); w.WriteHeader(204); cancel() })
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": s.Active(), "address": listener.Addr().String(), "identity": c.Identity, "pid": os.Getpid()})
	})
	server := http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	defer server.Close()
	failed := make(chan error, 2)
	go func() { failed <- server.Serve(admin) }()
	go func() { failed <- s.Serve(ctx, listener) }()
	select {
	case <-ctx.Done():
		return nil
	case e := <-failed:
		cancel()
		return e
	}
}
