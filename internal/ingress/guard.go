// Package ingress gates both new PostgreSQL connections and existing sessions
// with short signed serving leases. It never opens an upstream TCP connection.
package ingress

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"pgws/internal/atomicfile"
	"regexp"
	"strings"
	"sync"
	"time"

	"pgws/internal/lease"
)

type Config struct {
	Identity        lease.Identity `json:"identity"`
	Listen          string         `json:"listen"`
	Database        string         `json:"database"`
	BackendSocket   string         `json:"backend_socket"`
	Certificate     string         `json:"certificate"`
	Key             string         `json:"key"`
	AuthorityKey    string         `json:"authority_key"`
	StateFile       string         `json:"state_file"`
	RuntimeStopFile string         `json:"runtime_stop_file,omitempty"`
}
type receipt struct {
	Identity    lease.Identity       `json:"identity"`
	LastIssued  time.Time            `json:"last_issued"`
	Expiry      time.Time            `json:"workspace_expiry"`
	Terminal    bool                 `json:"terminal"`
	Credentials map[string]time.Time `json:"credentials"`
	Revoked     map[string]bool      `json:"revoked,omitempty"`
	Runtime     *RuntimeAuthority    `json:"runtime,omitempty"`
}
type Server struct {
	mu          sync.Mutex
	config      Config
	key         ed25519.PublicKey
	tls         *tls.Config
	guard       lease.Guard
	state       receipt
	connections map[net.Conn]time.Time
	backends    map[net.Conn]net.Conn
	users       map[net.Conn]string
}

func New(c Config) (*Server, error) {
	host, _, err := net.SplitHostPort(c.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("ingress must listen on a loopback IP")
	}
	if c.Database == "" || strings.ContainsRune(c.Database, 0) {
		return nil, errors.New("workspace database required")
	}
	if !filepath.IsAbs(c.BackendSocket) || !filepath.IsAbs(c.StateFile) {
		return nil, errors.New("absolute private socket and state paths required")
	}
	if c.RuntimeStopFile != "" && !filepath.IsAbs(c.RuntimeStopFile) {
		return nil, errors.New("absolute runtime stop path required")
	}
	cert, err := tls.LoadX509KeyPair(c.Certificate, c.Key)
	if err != nil {
		return nil, errors.New("ingress TLS certificate unavailable")
	}
	key, err := base64.StdEncoding.DecodeString(c.AuthorityKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid serving authority public key")
	}
	s := &Server{config: c, key: key, tls: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, connections: map[net.Conn]time.Time{}, backends: map[net.Conn]net.Conn{}, users: map[net.Conn]string{}, state: receipt{Identity: c.Identity, Credentials: map[string]time.Time{}}}
	b, err := os.ReadFile(c.StateFile)
	if err == nil {
		if json.Unmarshal(b, &s.state) != nil {
			return nil, errors.New("corrupt ingress receipt")
		}
		want := c.Identity
		want.Revision = s.state.Identity.Revision
		if s.state.Identity != want {
			return nil, errors.New("ingress authority identity changed")
		}
		if !s.state.Expiry.IsZero() && !time.Now().Before(s.state.Expiry) {
			s.state.Terminal = true
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	// A persisted lease never opens ingress after restart. A new signed grant is required.
	if s.state.Credentials == nil {
		s.state.Credentials = map[string]time.Time{}
	}
	if s.state.Revoked == nil {
		s.state.Revoked = map[string]bool{}
	}
	return s, nil
}
func (s *Server) persist() error {
	b, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	return atomicfile.Replace(s.config.StateFile, b)
}
func (s *Server) closeLocked() {
	for c := range s.connections {
		s.closeConnectionLocked(c)
	}
}

func (s *Server) closeConnectionLocked(c net.Conn) {
	_ = c.Close()
	if backend := s.backends[c]; backend != nil {
		_ = backend.Close()
	}
	delete(s.backends, c)
	delete(s.users, c)
	delete(s.connections, c)
}

// Both directions carry the conservative serving deadline into netpoll. A
// stalled guard must not resume forwarding buffered SQL before its ticker runs.
// Renewals may extend the serving deadline, never the credential's deadline.
func (s *Server) connectionDeadlineLocked(c net.Conn) {
	deadline, ok := s.connections[c]
	if !ok {
		return
	}
	if s.guard.Deadline.Before(deadline) {
		deadline = s.guard.Deadline
	}
	if err := c.SetDeadline(deadline); err != nil {
		s.closeConnectionLocked(c)
		return
	}
	if backend := s.backends[c]; backend != nil {
		if err := backend.SetDeadline(deadline); err != nil {
			s.closeConnectionLocked(c)
		}
	}
}
func (s *Server) Install(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runtimeStopped() {
		return fmt.Errorf("lease rejected: runtime stopped: %w", lease.ErrLease)
	}
	var boot string
	var ticks int64
	if s.config.RuntimeStopFile != "" {
		var err error
		boot, ticks, err = lease.BootClock()
		if err != nil {
			return err
		}
	}
	if len(token) > 8192 {
		return lease.ErrLease
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return lease.ErrLease
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return lease.ErrLease
	}
	var untrusted lease.Claims
	if json.Unmarshal(b, &untrusted) != nil {
		return lease.ErrLease
	}
	want := s.config.Identity
	want.Revision = untrusted.Revision
	now := time.Now()
	claims, _, err := lease.Verify(s.key, token, want, now)
	if err != nil {
		return fmt.Errorf("lease rejected: signature, identity or validity interval: %w", err)
	}
	if claims.Revision < s.state.Identity.Revision || !claims.IssuedAt.After(s.state.LastIssued) || s.state.Terminal {
		return fmt.Errorf("lease rejected: stale_revision=%t stale_issuance=%t terminal=%t: %w", claims.Revision < s.state.Identity.Revision, !claims.IssuedAt.After(s.state.LastIssued), s.state.Terminal, lease.ErrLease)
	}
	if !s.state.Expiry.IsZero() && !now.Before(s.state.Expiry.Add(-5*time.Second)) {
		s.state.Terminal = true
		s.closeLocked()
		_ = s.persist()
		return fmt.Errorf("lease rejected: workspace expired: %w", lease.ErrLease)
	}
	if err = s.guard.Install(s.key, token, want, now); err != nil {
		return fmt.Errorf("lease rejected: monotonic guard: %w", err)
	}
	var runtimeAuthority *RuntimeAuthority
	if s.config.RuntimeStopFile != "" {
		if old := s.state.Runtime; old != nil && old.BootID == boot && ticks >= old.WorkspaceDeadlineNS {
			s.state.Terminal = true
			s.guard = lease.Guard{}
			s.closeLocked()
			_ = s.persist()
			return fmt.Errorf("lease rejected: previous boot-clock workspace expiry: %w", lease.ErrLease)
		}
		workspaceEnd := ticks + int64(claims.WorkspaceExpiry.Sub(now)-5*time.Second)
		if old := s.state.Runtime; old != nil && old.BootID == boot && claims.WorkspaceExpiry.Equal(s.state.Expiry) && old.WorkspaceDeadlineNS < workspaceEnd {
			workspaceEnd = old.WorkspaceDeadlineNS
		}
		if workspaceEnd <= ticks {
			s.state.Terminal = true
			s.guard = lease.Guard{}
			s.closeLocked()
			_ = s.persist()
			return fmt.Errorf("lease rejected: boot-clock workspace expiry: %w", lease.ErrLease)
		}
		runtimeAuthority = &RuntimeAuthority{Token: token, ReceivedAt: now, BootID: boot, ReceivedNS: ticks, DeadlineNS: min(ticks+int64(s.guard.Deadline.Sub(now)), workspaceEnd), WorkspaceDeadlineNS: workspaceEnd}
		s.guard.Deadline = now.Add(time.Duration(runtimeAuthority.DeadlineNS - ticks))
	}
	s.state = receipt{Identity: want, LastIssued: claims.IssuedAt, Expiry: claims.WorkspaceExpiry, Credentials: s.state.Credentials, Revoked: s.state.Revoked, Runtime: runtimeAuthority}
	if err = s.persist(); err != nil {
		s.guard = lease.Guard{}
		s.closeLocked()
		return err
	}
	if s.runtimeStopped() {
		s.guard = lease.Guard{}
		s.closeLocked()
		return fmt.Errorf("lease rejected: runtime stopped during installation: %w", lease.ErrLease)
	}
	for c := range s.connections {
		s.connectionDeadlineLocked(c)
	}
	return nil
}
func (s *Server) CloseAccess() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.guard = lease.Guard{}
	s.closeLocked()
	return nil
}
func (s *Server) validLocked(now time.Time) bool {
	for c, deadline := range s.connections {
		if !deadline.IsZero() && !now.Before(deadline) {
			s.closeConnectionLocked(c)
		}
	}
	if s.guard.Tick(now) {
		s.closeLocked()
		if !s.state.Expiry.IsZero() && !now.Before(s.state.Expiry.Add(-5*time.Second)) && !s.state.Terminal {
			s.state.Terminal = true
			_ = s.persist()
		}
		return false
	}
	return true
}
func (s *Server) Active() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.validLocked(time.Now()) }
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	defer l.Close()
	defer s.CloseAccess()
	closed := make(chan struct{})
	defer close(closed)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-closed:
				return
			case <-ctx.Done():
				_ = l.Close()
				_ = s.CloseAccess()
				return
			case <-ticker.C:
				s.mu.Lock()
				s.validLocked(time.Now())
				s.mu.Unlock()
			}
		}
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.mu.Lock()
		if !s.validLocked(time.Now()) || len(s.connections) >= 100 {
			s.mu.Unlock()
			conn.Close()
			continue
		}
		s.connections[conn] = time.Now().Add(5 * time.Second)
		s.connectionDeadlineLocked(conn)
		s.mu.Unlock()
		go s.forward(ctx, conn)
	}
}

var issuedRole = regexp.MustCompile(`^pgws_[a-f0-9]{32}$`)

type forwardingWriter struct {
	server *Server
	client net.Conn
	target io.Writer
}

func (w forwardingWriter) Write(p []byte) (int, error) {
	w.server.mu.Lock()
	valid := w.server.validLocked(time.Now())
	_, tracked := w.server.connections[w.client]
	w.server.mu.Unlock()
	if !valid || !tracked {
		return 0, lease.ErrLease
	}
	return w.target.Write(p)
}

// RegisterCredential is reachable only over the private host-owned control
// socket. It cannot extend or revive a previously issued credential identity.
func (s *Server) RegisterCredential(user string, expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !issuedRole.MatchString(user) || !expiry.After(time.Now()) || expiry.After(s.state.Expiry) || s.state.Terminal {
		return fmt.Errorf("credential outside serving authority: expired=%t exceeds_workspace=%t terminal=%t invalid_username=%t", !expiry.After(time.Now()), expiry.After(s.state.Expiry), s.state.Terminal, !issuedRole.MatchString(user))
	}
	if s.state.Revoked[user] {
		return errors.New("credential has been revoked")
	}
	if old, ok := s.state.Credentials[user]; ok {
		if !old.Equal(expiry) {
			return errors.New("credential expiry is immutable")
		}
		return nil
	}
	if len(s.state.Credentials) >= 10000 {
		return errors.New("credential quota reached")
	}
	s.state.Credentials[user] = expiry
	if err := s.persist(); err != nil {
		delete(s.state.Credentials, user)
		return err
	}
	return nil
}

func (s *Server) RevokeCredential(user string) error {
	return s.RevokeCredentials([]string{user})
}

func (s *Server) RevokeCredentials(users []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(users) == 0 || len(users) > 10000 {
		return errors.New("invalid credential revocation batch")
	}
	for _, user := range users {
		if !issuedRole.MatchString(user) {
			return errors.New("invalid credential identity")
		}
		if _, ok := s.state.Credentials[user]; !ok {
			return errors.New("credential is not registered")
		}
	}
	for _, user := range users {
		s.state.Revoked[user] = true
	}
	// Close even if receipt persistence fails; the control plane will retry.
	for c, owner := range s.users {
		if s.state.Revoked[owner] {
			s.closeConnectionLocked(c)
		}
	}
	return s.persist()
}

func readStartup(conn net.Conn) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(length[:])
	if n < 8 || n > 8192 {
		return nil, errors.New("invalid PostgreSQL startup length")
	}
	b := make([]byte, n)
	copy(b, length[:])
	_, err := io.ReadFull(conn, b[4:])
	return b, err
}
func validStartup(b []byte, database string) bool {
	if len(b) < 9 || binary.BigEndian.Uint32(b[4:8]) != 196608 || b[len(b)-1] != 0 {
		return false
	}
	parts := strings.Split(string(b[8:len(b)-1]), "\x00")
	if len(parts) < 3 || parts[len(parts)-1] != "" || len(parts)%2 != 1 {
		return false
	}
	seen := map[string]bool{}
	for i := 0; i < len(parts)-1; i += 2 {
		key, val := parts[i], parts[i+1]
		if seen[key] {
			return false
		}
		seen[key] = true
		switch key {
		case "user":
			if !issuedRole.MatchString(val) {
				return false
			}
		case "database":
			if val == "" || val != database {
				return false
			}
		case "application_name", "client_encoding":
		default:
			return false
		}
	}
	return seen["user"] && seen["database"]
}
func (s *Server) forward(ctx context.Context, raw net.Conn) {
	defer func() { s.mu.Lock(); s.closeConnectionLocked(raw); s.mu.Unlock() }()
	// PostgreSQL requests TLS with its 8-byte SSLRequest, before the startup packet.
	request, err := readStartup(raw)
	if err != nil || len(request) != 8 || binary.BigEndian.Uint32(request[4:]) != 80877103 {
		return
	}
	if _, err = raw.Write([]byte{'S'}); err != nil {
		return
	}
	secure := tls.Server(raw, s.tls)
	if err = secure.HandshakeContext(ctx); err != nil {
		return
	}
	startup, err := readStartup(secure)
	if err != nil || !validStartup(startup, s.config.Database) {
		return
	}
	s.mu.Lock()
	valid := s.validLocked(time.Now())
	parts := strings.Split(string(startup[8:len(startup)-1]), "\x00")
	var user string
	for i := 0; i < len(parts)-1; i += 2 {
		switch parts[i] {
		case "user":
			user = parts[i+1]
		}
	}
	expiry, issued := s.state.Credentials[user]
	valid = valid && issued && !s.state.Revoked[user] && time.Now().Before(expiry)
	if valid {
		s.users[raw] = user
		s.connections[raw] = time.Now().Add(time.Until(expiry))
		s.connectionDeadlineLocked(raw)
	}
	s.mu.Unlock()
	if !valid {
		return
	}
	backend, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", s.config.BackendSocket)
	if err != nil {
		return
	}
	defer backend.Close()
	s.mu.Lock()
	valid = s.validLocked(time.Now())
	_, tracked := s.connections[raw]
	if !tracked || !valid {
		s.mu.Unlock()
		return
	}
	s.backends[raw] = backend
	s.connectionDeadlineLocked(raw)
	s.mu.Unlock()
	toBackend := forwardingWriter{server: s, client: raw, target: backend}
	toClient := forwardingWriter{server: s, client: raw, target: secure}
	if _, err = toBackend.Write(startup); err != nil {
		return
	}
	finished := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(toBackend, bufio.NewReader(secure))
		_ = backend.Close()
		finished <- struct{}{}
	}()
	_, _ = io.Copy(toClient, backend)
	_ = raw.Close()
	_ = backend.Close()
	<-finished
}
