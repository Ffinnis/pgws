package sourcebroker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func fixtureCertificate(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Source fixture"}, DNSNames: []string{"source.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(path, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return pair, path
}

func startup(user, replication string) []byte {
	body := []byte("user\x00" + user + "\x00replication\x00" + replication + "\x00application_name\x00pgws-test\x00\x00")
	data := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(data[:4], uint32(len(data)))
	binary.BigEndian.PutUint32(data[4:8], 196608)
	copy(data[8:], body)
	return data
}

func TestEndpointPinsAndStartup(t *testing.T) {
	endpoint := Endpoint{Hostname: "source.test", Port: 5432, Addresses: []string{"192.0.2.20"}}
	if err := endpoint.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := endpoint.Lookup(context.Background(), "elsewhere.test"); err == nil {
		t.Fatal("unapproved hostname resolved")
	}
	for _, address := range []string{"192.0.2.21:5432", "192.0.2.20:443", "source.test:5432"} {
		if conn, err := endpoint.DialContext(context.Background(), "tcp", address); err == nil {
			conn.Close()
			t.Fatal("unpinned dial accepted")
		}
	}
	for _, address := range []string{"169.254.169.254", "fe80::1", "fd00:ec2::254", "100.100.100.200", "::ffff:192.0.2.20", "0.0.0.0", "224.0.0.1"} {
		bad := endpoint
		bad.Addresses = []string{address}
		if bad.Validate() == nil {
			t.Fatal("unsafe destination accepted", address)
		}
	}
	if !validStartup(startup("replicator", "true"), "replicator") {
		t.Fatal("valid physical replication rejected")
	}
	for _, data := range [][]byte{startup("other", "true"), startup("replicator", "false"), startup("replicator", "database"), {0, 0, 0, 8, 4, 210, 22, 47}} {
		if validStartup(data, "replicator") {
			t.Fatal("SQL/foreign/cancel startup accepted")
		}
	}
	duplicate := startup("replicator", "true")
	duplicate = append(duplicate[:len(duplicate)-1], []byte("replication\x00database\x00\x00")...)
	if validStartup(duplicate, "replicator") {
		t.Fatal("duplicate parameters accepted")
	}
}

func TestTLSReplicationRelay(t *testing.T) {
	certificate, ca := fixtureCertificate(t)
	remote, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	var connections atomic.Int32
	go func() {
		for {
			conn, err := remote.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				var request [8]byte
				if _, err := io.ReadFull(conn, request[:]); err != nil || binary.BigEndian.Uint32(request[4:]) != 80877103 {
					return
				}
				_, _ = conn.Write([]byte{'S'})
				secure := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				if secure.Handshake() != nil {
					return
				}
				var header [4]byte
				if _, err := io.ReadFull(secure, header[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(header[:])
				if size > 8192 || size < 9 {
					return
				}
				data := make([]byte, size)
				copy(data, header[:])
				if _, err := io.ReadFull(secure, data[4:]); err != nil || !validStartup(data, "replicator") {
					return
				}
				_, _ = secure.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0})
				_, _ = secure.Write([]byte("verified"))
				_, _ = io.Copy(secure, secure)
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(remote.Addr().String())
	number, _ := strconv.Atoi(port)
	endpoint := Endpoint{Hostname: "source.test", Port: uint16(number), Addresses: []string{"127.0.0.1"}, RootCertificate: ca}
	for _, name := range []string{"wrong_hostname", "wrong_ca"} {
		t.Run(name, func(t *testing.T) {
			bad := endpoint
			if name == "wrong_hostname" {
				bad.Hostname = "wrong.test"
			} else {
				_, bad.RootCertificate = fixtureCertificate(t)
			}
			if conn, err := bad.DialTLS(context.Background()); err == nil {
				conn.Close()
				t.Fatal("unverified TLS source accepted")
			}
		})
	}
	local, err := net.Listen("unix", filepath.Join(t.TempDir(), "source.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, local, Config{Endpoint: endpoint, Username: "replicator"}) }()
	before := connections.Load()
	for _, replication := range []string{"false", "database"} {
		conn, err := net.Dial("unix", local.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write(startup("replicator", replication))
		var reply [1]byte
		if _, err = conn.Read(reply[:]); err == nil {
			t.Fatal("non-physical session forwarded")
		}
		conn.Close()
	}
	if connections.Load() != before {
		t.Fatal("rejected startup contacted upstream")
	}
	client, err := net.Dial("unix", local.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = client.Write(startup("replicator", "true")); err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 9)
	if _, err = io.ReadFull(client, auth); err != nil || !bytes.Equal(auth, []byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}) {
		t.Fatal("authentication relay", err)
	}
	reply := make([]byte, 8)
	if _, err = io.ReadFull(client, reply); err != nil || string(reply) != "verified" {
		t.Fatal("TLS relay", err)
	}
	if _, err = client.Write([]byte("WAL bytes")); err != nil {
		t.Fatal(err)
	}
	reply = make([]byte, 9)
	if _, err = io.ReadFull(client, reply); err != nil || string(reply) != "WAL bytes" {
		t.Fatal("duplex relay", err)
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("broker did not close active streams on shutdown")
	}
	if _, err = client.Read(reply); err == nil {
		t.Fatal("source stream survived broker shutdown")
	}
}

func TestBrokerSASLOffer(t *testing.T) {
	frame := func(body []byte) []byte {
		result := make([]byte, 5)
		result[0] = 'R'
		binary.BigEndian.PutUint32(result[1:], uint32(len(body)+4))
		return append(result, body...)
	}
	sasl := func(mechanisms string) []byte { return frame(append([]byte{0, 0, 0, 10}, []byte(mechanisms)...)) }
	want := sasl("SCRAM-SHA-256\x00\x00")
	for _, input := range [][]byte{want, sasl("SCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00")} {
		var output bytes.Buffer
		if err := relayAuthenticationOffer(&output, bytes.NewReader(input)); err != nil || !bytes.Equal(output.Bytes(), want) {
			t.Fatal("Unix client received unusable SASL offer", err)
		}
	}
	for _, input := range [][]byte{sasl("SCRAM-SHA-256-PLUS\x00\x00"), sasl("SCRAM-SHA-256\x00"), {'R', 0, 1, 0, 0}, {'R', 0, 0, 0, 3}} {
		var output bytes.Buffer
		if relayAuthenticationOffer(&output, bytes.NewReader(input)) == nil || output.Len() != 0 {
			t.Fatal("invalid source auth offer forwarded")
		}
	}
}

func TestTLSRequired(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	done := make(chan int, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- -1
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		var request [8]byte
		_, _ = io.ReadFull(conn, request[:])
		_, _ = conn.Write([]byte{'N'})
		var payload [1]byte
		n, _ := conn.Read(payload[:])
		done <- n
	}()
	endpoint := Endpoint{Hostname: "source.test", Port: uint16(number), Addresses: []string{"127.0.0.1"}}
	if conn, err := endpoint.DialTLS(context.Background()); err == nil {
		conn.Close()
		t.Fatal("plaintext source accepted")
	}
	if n := <-done; n != 0 {
		t.Fatal("sent startup after TLS refusal", n)
	}
}
