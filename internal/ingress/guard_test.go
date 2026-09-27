package ingress

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pgws/internal/lease"
)

func fixture(t *testing.T) (Config, ed25519.PrivateKey, *tls.Config) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pgws-guard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PGWS test"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); e != nil {
		t.Fatal(e)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return Config{Identity: lease.Identity{Epoch: "epoch", Tenant: "tenant", Project: "project", Workspace: "workspace", Host: "host", Generation: 1, Revision: 1}, Listen: "127.0.0.1:0", Database: "postgres", BackendSocket: filepath.Join(dir, "postgres.sock"), Certificate: certFile, Key: keyFile, AuthorityKey: base64.StdEncoding.EncodeToString(pub), StateFile: filepath.Join(dir, "receipt.json")}, key, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}
func startup(user string) []byte {
	body := []byte("user\x00" + user + "\x00database\x00postgres\x00\x00")
	b := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(b, uint32(len(b)))
	binary.BigEndian.PutUint32(b[4:], 196608)
	copy(b[8:], body)
	return b
}
func TestStartupRejectsAdministrativeAuthority(t *testing.T) {
	for _, user := range []string{"postgres", "pgws_admin", "", "pgws_123"} {
		if validStartup(startup(user), "postgres") {
			t.Fatal("accepted", user)
		}
	}
	if !validStartup(startup("pgws_10000000000040008000000000000001"), "postgres") {
		t.Fatal("issued role rejected")
	}
}
func TestStartupPinsWorkspaceDatabase(t *testing.T) {
	if validStartup(startup("pgws_10000000000040008000000000000001"), "another_database") {
		t.Fatal("startup selected a different database")
	}
}
func TestServingLeaseClosesEstablishedConnection(t *testing.T) {
	testForwardClosure(t, 7*time.Second, time.Minute, false, false, false)
}
func TestCredentialExpiryClosesOnlyItsSession(t *testing.T) {
	testForwardClosure(t, 10*time.Second, 700*time.Millisecond, true, false, false)
}
func TestRenewalExtendsServingIOButNotCredentialExpiry(t *testing.T) {
	testForwardClosure(t, 6*time.Second, 3*time.Second, true, true, false)
}
func TestCredentialRevocationClosesSessionAndSurvivesRestart(t *testing.T) {
	testForwardClosure(t, 10*time.Second, time.Minute, true, false, true)
}
func testForwardClosure(t *testing.T, leaseTTL, credentialTTL time.Duration, wantActive, renew, revoke bool) {
	c, key, tlsConfig := fixture(t)
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	if s.Active() {
		t.Fatal("startup opened without lease")
	}
	backend, e := net.Listen("unix", c.BackendSocket)
	if e != nil {
		t.Fatal(e)
	}
	defer backend.Close()
	go func() {
		conn, e := backend.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		if _, e = readStartup(conn); e != nil {
			return
		}
		_, _ = conn.Write([]byte("ready"))
		_, _ = io.Copy(conn, conn)
	}()
	l, e := net.Listen("tcp", c.Listen)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, l) }()
	defer func() { cancel(); <-done }()
	now := time.Now()
	claims := lease.Claims{Identity: c.Identity, IssuedAt: now, ExpiresAt: now.Add(leaseTTL), WorkspaceExpiry: now.Add(time.Minute)}
	token, e := lease.Sign(key, claims)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Install(token); e != nil {
		t.Fatal(e)
	}
	if e = s.RegisterCredential("pgws_10000000000040008000000000000001", now.Add(credentialTTL)); e != nil {
		t.Fatal(e)
	}
	raw, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	request := make([]byte, 8)
	binary.BigEndian.PutUint32(request, 8)
	binary.BigEndian.PutUint32(request[4:], 80877103)
	if _, e = raw.Write(request); e != nil {
		t.Fatal(e)
	}
	var response [1]byte
	if _, e = io.ReadFull(raw, response[:]); e != nil || response[0] != 'S' {
		t.Fatal("TLS required", e)
	}
	client := tls.Client(raw, tlsConfig)
	if e = client.Handshake(); e != nil {
		t.Fatal(e)
	}
	if _, e = client.Write(startup("pgws_10000000000040008000000000000001")); e != nil {
		t.Fatal(e)
	}
	var ready [5]byte
	if _, e = io.ReadFull(client, ready[:]); e != nil || string(ready[:]) != "ready" {
		t.Fatal("forwarding", e)
	}
	renewed := make(chan error, 1)
	if renew || revoke {
		go func() {
			time.Sleep(250 * time.Millisecond)
			if revoke {
				renewed <- s.RevokeCredential("pgws_10000000000040008000000000000001")
				return
			}
			next := claims
			next.IssuedAt = time.Now()
			next.ExpiresAt = next.IssuedAt.Add(10 * time.Second)
			token, err := lease.Sign(key, next)
			if err == nil {
				err = s.Install(token)
			}
			renewed <- err
		}()
	}
	if _, e = client.Read(response[:]); e == nil {
		t.Fatal("expired lease retained session")
	}
	if renew || revoke {
		if err := <-renewed; err != nil {
			t.Fatal("lease renewal", err)
		}
		if renew && time.Since(now) < 2*time.Second {
			t.Fatal("renewal did not update both I/O deadlines")
		}
		if time.Since(now) > 4*time.Second {
			t.Fatal("renewal extended credential expiry")
		}
	}
	if s.Active() != wantActive {
		t.Fatal("incorrect serving state after expiry")
	}
	restarted, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	if restarted.Active() {
		t.Fatal("persisted lease reopened after restart")
	}
	if revoke && restarted.RegisterCredential("pgws_10000000000040008000000000000001", now.Add(credentialTTL)) == nil {
		t.Fatal("revoked username revived after restart")
	}
	if restarted.Install(token) == nil {
		t.Fatal("old lease replay accepted after restart")
	}
}
func TestTerminalExpirySurvivesRestart(t *testing.T) {
	c, key, _ := fixture(t)
	s, e := New(c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	claims := lease.Claims{Identity: c.Identity, IssuedAt: now, ExpiresAt: now.Add(time.Minute), WorkspaceExpiry: now.Add(6 * time.Second)}
	token, _ := lease.Sign(key, claims)
	if e = s.Install(token); e != nil {
		t.Fatal(e)
	}
	time.Sleep(1100 * time.Millisecond)
	if s.Active() {
		t.Fatal("workspace past conservative expiry")
	}
	s, e = New(c)
	if e != nil {
		t.Fatal(e)
	}
	claims.IssuedAt = time.Now()
	claims.ExpiresAt = time.Now().Add(time.Minute)
	claims.WorkspaceExpiry = time.Now().Add(time.Hour)
	token, _ = lease.Sign(key, claims)
	if s.Install(token) == nil {
		t.Fatal("terminal workspace revived")
	}
}

func TestCredentialBatchRevocationValidatesBeforeChangingAuthority(t *testing.T) {
	c, key, _ := fixture(t)
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	token, _ := lease.Sign(key, lease.Claims{Identity: c.Identity, IssuedAt: now, ExpiresAt: now.Add(time.Minute), WorkspaceExpiry: now.Add(time.Hour)})
	if err = s.Install(token); err != nil {
		t.Fatal(err)
	}
	a, b, unknown := "pgws_10000000000040008000000000000001", "pgws_10000000000040008000000000000002", "pgws_10000000000040008000000000000003"
	expiry := now.Add(time.Minute)
	for _, user := range []string{a, b} {
		if err = s.RegisterCredential(user, expiry); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.RevokeCredentials([]string{a, unknown}); err == nil {
		t.Fatal("unknown credential accepted")
	}
	if err = s.RegisterCredential(a, expiry); err != nil {
		t.Fatal("invalid batch partially changed authority", err)
	}
	if err = s.RevokeCredentials([]string{a, b}); err != nil {
		t.Fatal(err)
	}
	s, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{a, b} {
		if err = s.RegisterCredential(user, expiry); err == nil {
			t.Fatal("batch tombstone was lost")
		}
	}
}
