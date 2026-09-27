package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/control"
	"pgws/internal/ingress"
	"pgws/internal/lease"
	"pgws/internal/physical"
)

type guardStatus struct {
	Active   bool           `json:"active"`
	PID      int            `json:"pid"`
	Address  string         `json:"address"`
	Identity lease.Identity `json:"identity"`
}

func guardRequest(ctx context.Context, folder, action string, body []byte, result any) error {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(folder, "guard.sock"))
	}}
	defer transport.CloseIdleConnections()
	method := "POST"
	if action == "status" {
		method = "GET"
	}
	r, err := http.NewRequestWithContext(ctx, method, "http://guard/"+action, bytes.NewReader(body))
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Do(r)
	if err != nil {
		return errors.New("independent guard unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 && response.StatusCode != 204 {
		detail := ""
		if action == "credential" || action == "lease" {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 512))
			reason := strings.TrimSpace(string(body))
			if strings.HasPrefix(reason, "credential outside serving authority:") || strings.HasPrefix(reason, "lease rejected:") || reason == "credential expiry is immutable" || reason == "credential quota reached" {
				detail = ": " + reason
			}
		}
		return fmt.Errorf("guard rejected %s (HTTP %d)%s", action, response.StatusCode, detail)
	}
	if result != nil {
		return json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(result)
	}
	return nil
}
func (h *Host) startGuard(ctx context.Context, t control.Task, s state) (json.RawMessage, error) {
	if !filepath.IsAbs(h.Config.GuardBinary) {
		return nil, errors.New("guard executable is required")
	}
	if err := os.MkdirAll(s.GuardDirectory, 0700); err != nil {
		return nil, err
	}
	c := ingress.Config{Identity: t.Command.Identity, Listen: "127.0.0.1:0", Database: s.Access.Databases[0], BackendSocket: filepath.Join(s.Recovery.SocketDir, ".s.PGSQL.5432"), Certificate: h.Config.Certificate, Key: h.Config.CertificateKey, AuthorityKey: h.Config.AuthorityKey, StateFile: filepath.Join(s.GuardDirectory, "receipt.json"), RuntimeStopFile: filepath.Join(h.folder(t), "safety-stop.json")}
	config := filepath.Join(s.GuardDirectory, "config.json")
	if raw, err := os.ReadFile(config); err == nil {
		var existing ingress.Config
		if json.Unmarshal(raw, &existing) != nil {
			return nil, errors.New("partial guard configuration is unreadable")
		}
		c.Listen = existing.Listen
		if existing != c {
			return nil, errors.New("partial guard configuration differs from its generation")
		}
	} else if os.IsNotExist(err) {
		if err = save(config, c); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	var before guardStatus
	if guardRequest(ctx, s.GuardDirectory, "status", nil, &before) != nil {
		if err := h.spawnGuard(config); err != nil {
			return nil, err
		}
	}
	for {
		var status guardStatus
		if guardRequest(ctx, s.GuardDirectory, "status", nil, &status) == nil {
			if status.Identity != t.Command.Identity || status.Active {
				return nil, errors.New("new guard must start closed with the exact identity")
			}
			host, port, err := net.SplitHostPort(status.Address)
			if err != nil {
				return nil, err
			}
			// A restart must bind the published address, never allocate another port.
			c.Listen = status.Address
			if err = save(config, c); err != nil {
				return nil, err
			}
			n, err := strconv.Atoi(port)
			if err != nil {
				return nil, err
			}
			return json.Marshal(map[string]any{"hostname": host, "port": n, "database": s.Access.Databases[0], "sslmode": "verify-full"})
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (h *Host) Activate(ctx context.Context, t control.Task, token string) error {
	unlock := h.lock(t.Command.Workspace)
	defer unlock()
	if err := checkStopped(h.folder(t)); err != nil {
		return err
	}
	current, ok := h.journal.Current(t.Command.Identity)
	if !ok || current.Command.Identity != t.Command.Identity || current.Command.Token != t.Command.Token {
		return errors.New("serving authority was superseded")
	}
	s, err := h.load(t)
	if err != nil {
		return err
	}
	if s.Task.Command.Identity != t.Command.Identity || s.Task.Command.Token != t.Command.Token {
		return errors.New("activation has stale host authority")
	}
	if s.Phase != "ready" && s.Phase != "paused" && s.Phase != "resuming" {
		return errors.New("generation is not prepared for activation")
	}
	var before guardStatus
	if guardRequest(ctx, s.GuardDirectory, "status", nil, &before) != nil {
		if err = h.restartGuard(ctx, s); err != nil {
			return err
		}
	}
	if err = guardRequest(ctx, s.GuardDirectory, "lease", []byte(token), nil); err != nil {
		return err
	}
	if s.Phase == "paused" {
		return guardRequest(ctx, s.GuardDirectory, "close", nil, nil)
	}
	if s.Phase == "resuming" {
		if err = h.resumeRuntime(ctx, s); err != nil {
			return err
		}
		s.Phase = "ready"
	}
	if !s.ServingStarted || t.Kind == "resume" {
		s.ServingStarted = true
		if err = h.save(t, s); err != nil {
			return err
		}
	}
	if err = checkStopped(h.folder(t)); err != nil {
		return err
	}
	var status guardStatus
	if err = guardRequest(ctx, s.GuardDirectory, "status", nil, &status); err != nil {
		return err
	}
	if !status.Active {
		return fmt.Errorf("serving lease was not installed")
	}
	if t.Kind == "refresh" {
		return nil
	}
	return h.probe(ctx, s, status.Address)
}

func (h *Host) probe(ctx context.Context, s state, address string) error {
	expiry := time.Now().Add(30 * time.Second)
	if expiry.After(s.Task.Expiry) {
		expiry = s.Task.Expiry
	}
	credential, err := physical.IssueCredential(ctx, s.Recovery, s.Access, "owner", expiry)
	if err != nil {
		return err
	}
	registration, _ := json.Marshal(map[string]any{"username": credential.Username, "expires_at": credential.ExpiresAt})
	if err = guardRequest(ctx, s.GuardDirectory, "credential", registration, nil); err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		admin := physical.Source{Host: s.Recovery.SocketDir, Port: 5432, User: s.Access.Admin, Database: "postgres"}
		if conn, e := admin.ConnectPrivateAdmin(cleanup); e == nil {
			for _, db := range s.Access.Databases {
				_, _ = conn.Exec(cleanup, "REVOKE CONNECT ON DATABASE "+pgx.Identifier{db}.Sanitize()+" FROM "+pgx.Identifier{credential.Username}.Sanitize())
			}
			_, _ = conn.Exec(cleanup, "DROP ROLE "+pgx.Identifier{credential.Username}.Sanitize())
			conn.Close(context.Background())
		}
	}()
	u := url.URL{Scheme: "postgresql", Host: address, User: url.UserPassword(credential.Username, credential.Password), Path: "/" + s.Access.Databases[0]}
	q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {h.Config.Certificate}, "connect_timeout": {"3"}}
	u.RawQuery = q.Encode()
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		return errors.New("TLS and credential endpoint probe failed")
	}
	defer conn.Close(context.Background())
	var recovery, readonly bool
	err = conn.QueryRow(ctx, `SELECT pg_is_in_recovery(),current_setting('transaction_read_only')='on'`).Scan(&recovery, &readonly)
	if err != nil || recovery || readonly {
		return errors.New("endpoint is not a writable application session")
	}
	return nil
}

func (h *Host) lifecycle(ctx context.Context, t control.Task) (control.Outcome, error) {
	s, err := h.load(t)
	if err != nil {
		return control.Outcome{}, err
	}
	if s.Task.Command.Generation != t.Command.Generation || s.Task.Command.Tenant != t.Command.Tenant || s.Task.Command.Project != t.Command.Project {
		return control.Outcome{}, errors.New("runtime ownership differs")
	}
	tools := h.oci.Tools(s.Container)
	out := control.Outcome{}
	switch t.Kind {
	case "pause":
		if err = guardRequest(ctx, s.GuardDirectory, "close", nil, nil); err != nil {
			return out, err
		}
		if err = tools.StopDisconnected(ctx, s.Recovery); err != nil {
			return out, err
		}
		out.Phase = "paused"
	case "resume":
		// Activation installs a fresh bounded lease before starting PostgreSQL.
		// An old expired lease must not race a legitimate resume from pause.
		out.Phase = "ready"
	case "extend_ttl":
		var a, prior control.Action
		if json.Unmarshal(t.Document, &a) != nil {
			return out, errors.New("invalid expiry action")
		}
		replayed := s.Task.Kind == t.Kind && s.Task.Command.Operation == t.Command.Operation && json.Unmarshal(s.Task.Document, &prior) == nil && reflect.DeepEqual(prior, a)
		if (!a.ExpectedExpiry.Equal(s.Task.Expiry) && !(replayed && a.Expiry.Equal(s.Task.Expiry))) || !a.Expiry.After(a.ExpectedExpiry) {
			return out, errors.New("invalid expiry compare")
		}
		out.Phase = s.Phase
		out.Expiry = &a.Expiry
		t.Expiry = a.Expiry
	}
	s.Task = t
	s.Phase = out.Phase
	if t.Kind == "resume" && s.Phase == "ready" {
		s.Phase = "resuming"
	}
	s.Outcome = out
	if err = h.save(t, s); err != nil {
		return out, err
	}
	return out, nil
}

func (h *Host) resumeRuntime(ctx context.Context, s state) error {
	if err := h.oci.Tools(s.Container).StartDisconnected(ctx, s.Recovery); err != nil {
		return err
	}
	for {
		admin := physical.Source{Host: s.Recovery.SocketDir, Port: 5432, User: s.Access.Admin, Database: "postgres"}
		if conn, err := admin.ConnectPrivateAdmin(ctx); err == nil {
			var recovering bool
			var system string
			err = conn.QueryRow(ctx, `SELECT pg_is_in_recovery(),(pg_control_system()).system_identifier::text`).Scan(&recovering, &system)
			conn.Close(context.Background())
			if err == nil {
				if recovering || system != s.Recovery.Barrier.SystemID {
					return errors.New("resumed generation identity changed")
				}
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (h *Host) spawnGuard(config string) error {
	cmd := exec.Command(h.Config.GuardBinary, config)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
func (h *Host) restartGuard(ctx context.Context, s state) error {
	path := filepath.Join(s.GuardDirectory, "config.json")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var c ingress.Config
	var endpoint struct {
		Hostname string
		Port     int
		Database string
	}
	if json.Unmarshal(b, &c) != nil || json.Unmarshal(s.Endpoint, &endpoint) != nil {
		return errors.New("guard restart metadata unavailable")
	}
	want := s.Task.Command.Identity
	want.Revision = c.Identity.Revision
	if c.Identity != want || c.Listen != net.JoinHostPort(endpoint.Hostname, strconv.Itoa(endpoint.Port)) || c.Database != endpoint.Database {
		return errors.New("guard restart identity changed")
	}
	if err = h.spawnGuard(path); err != nil {
		return err
	}
	for {
		var status guardStatus
		if guardRequest(ctx, s.GuardDirectory, "status", nil, &status) == nil {
			if status.Address != c.Listen || status.Identity != c.Identity {
				return errors.New("restarted guard identity differs")
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
