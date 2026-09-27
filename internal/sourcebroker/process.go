package sourcebroker

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"pgws/internal/config"
	"pgws/internal/lease"
)

type ProcessConfig struct {
	Identity lease.Identity `json:"identity"`
	Broker   Config         `json:"broker"`
	Socket   string         `json:"socket"`
	Control  string         `json:"control"`
}

type ProcessStatus struct {
	Config ProcessConfig `json:"config"`
	PID    int           `json:"pid"`
}

func RunProcess(ctx context.Context, plan ProcessConfig) error {
	if err := plan.Broker.Validate(); err != nil {
		return err
	}
	for _, path := range []string{plan.Socket, plan.Control} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("source broker paths must be canonical and absolute")
		}
	}
	if filepath.Dir(plan.Socket) == filepath.Dir(plan.Control) {
		return errors.New("source broker control must be outside the runtime socket mount")
	}
	lock, err := os.OpenFile(plan.Control+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("source broker is already running")
	}
	admin, err := config.ListenPrivateUnix(plan.Control)
	if err != nil {
		return err
	}
	defer admin.Close()
	defer os.Remove(plan.Control)
	if err = os.Chmod(plan.Control, 0600); err != nil {
		return err
	}
	listener, err := config.ListenPrivateUnix(plan.Socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(plan.Socket)
	// The enclosing directory is mode 0700 and mounted read-only only in the
	// baseline container. The root-owned socket permits that container's UID.
	if err = os.Chmod(plan.Socket, 0666); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(ProcessStatus{Config: plan, PID: os.Getpid()})
	})
	mux.HandleFunc("POST /shutdown", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent); cancel() })
	server := http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second}
	defer server.Close()
	failed := make(chan error, 2)
	go func() { failed <- server.Serve(admin) }()
	go func() { failed <- Serve(ctx, listener, plan.Broker) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		return err
	}
}
