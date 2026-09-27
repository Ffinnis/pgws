package sourcebroker

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Endpoint Endpoint `json:"endpoint"`
	Username string   `json:"username"`
}

func (c Config) Validate() error {
	if c.Username == "" || len(c.Username) > 63 || strings.ContainsRune(c.Username, 0) {
		return errors.New("source replication username is invalid")
	}
	return c.Endpoint.Validate()
}

// Serve accepts at most eight physical replication sessions. The Unix socket
// and process lifetime belong to the host supervisor. No password is stored,
// logged or interpreted here; PostgreSQL authenticates the forwarded session.
func Serve(ctx context.Context, listener net.Listener, config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	done := make(chan struct{})
	defer close(done)
	var mu sync.Mutex
	connections := map[net.Conn]bool{}
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		listener.Close()
		mu.Lock()
		for conn := range connections {
			conn.Close()
		}
		mu.Unlock()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("source broker listener stopped")
		}
		mu.Lock()
		if ctx.Err() != nil || len(connections) >= 8 {
			mu.Unlock()
			conn.Close()
			continue
		}
		connections[conn] = true
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { conn.Close(); mu.Lock(); delete(connections, conn); mu.Unlock() }()
			relay(ctx, conn, config)
		}()
	}
}

func relay(ctx context.Context, client net.Conn, config Config) {
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	var header [4]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return
	}
	size := binary.BigEndian.Uint32(header[:])
	if size < 9 || size > 8192 {
		return
	}
	startup := make([]byte, size)
	copy(startup, header[:])
	if _, err := io.ReadFull(client, startup[4:]); err != nil || !validStartup(startup, config.Username) {
		return
	}
	upstream, err := config.Endpoint.DialTLS(ctx)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = upstream.Write(startup); err != nil {
		return
	}
	if err = relayAuthenticationOffer(client, upstream); err != nil {
		return
	}
	_ = upstream.SetDeadline(time.Time{})
	_ = client.SetDeadline(time.Time{})
	finished := make(chan struct{})
	go func() { _, _ = io.Copy(upstream, client); upstream.Close(); close(finished) }()
	_, _ = io.Copy(client, upstream)
	client.Close()
	<-finished
}

func validStartup(data []byte, username string) bool {
	if len(data) < 9 || data[len(data)-1] != 0 {
		return false
	}
	version := binary.BigEndian.Uint32(data[4:8])
	if version != 196608 && version != 196610 {
		return false
	}
	parts := strings.Split(string(data[8:len(data)-1]), "\x00")
	if len(parts) < 5 || len(parts)%2 != 1 || parts[len(parts)-1] != "" {
		return false
	}
	seen := map[string]bool{}
	for i := 0; i < len(parts)-1; i += 2 {
		key, value := parts[i], parts[i+1]
		if seen[key] {
			return false
		}
		seen[key] = true
		switch key {
		case "user":
			if value != username {
				return false
			}
		case "replication":
			if value != "true" {
				return false
			}
		case "application_name", "client_encoding", "database":
			if len(value) > 128 {
				return false
			}
		default:
			return false
		}
	}
	return seen["user"] && seen["replication"]
}
