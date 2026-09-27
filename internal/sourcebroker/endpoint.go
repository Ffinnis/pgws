// Package sourcebroker carries physical replication over a private Unix socket
// to a statically approved PostgreSQL TLS endpoint. It does not authorize sources.
package sourcebroker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Endpoint struct {
	Hostname        string   `json:"hostname"`
	Port            uint16   `json:"port"`
	Addresses       []string `json:"addresses"`
	RootCertificate string   `json:"root_certificate,omitempty"`
}

func (e Endpoint) Validate() error {
	if e.Hostname == "" || len(e.Hostname) > 253 || strings.ContainsAny(e.Hostname, "/\\\x00 \t\r\n") || e.Port == 0 || len(e.Addresses) == 0 || len(e.Addresses) > 8 {
		return errors.New("source endpoint needs a hostname, port and one to eight pinned addresses")
	}
	for _, value := range e.Addresses {
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" || ip != ip.Unmap() || ip.String() != value || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || value == "100.100.100.200" || value == "fd00:ec2::254" {
			return errors.New("source address is invalid, link-local or a metadata endpoint")
		}
	}
	if e.RootCertificate != "" && !filepath.IsAbs(e.RootCertificate) {
		return errors.New("source CA file must be absolute")
	}
	if ip, err := netip.ParseAddr(e.Hostname); err == nil && !slices.Contains(e.Addresses, ip.String()) {
		return errors.New("literal source hostname is outside its pinned addresses")
	}
	return nil
}

// Lookup and DialContext are also used by the host's pgx administrator client.
// DNS changes cannot silently change this source's approved network destination.
func (e Endpoint) Lookup(_ context.Context, hostname string) ([]string, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	if hostname != e.Hostname {
		return nil, errors.New("source hostname was not approved")
	}
	return slices.Clone(e.Addresses), nil
}

func (e Endpoint) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != strconv.Itoa(int(e.Port)) || network != "tcp" || !slices.Contains(e.Addresses, host) {
		return nil, errors.New("source connection outside pinned endpoint")
	}
	return (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", address)
}

func (e Endpoint) tlsConfig() (*tls.Config, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var roots *x509.CertPool
	if e.RootCertificate != "" {
		info, err := os.Stat(e.RootCertificate)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return nil, errors.New("source CA file is unavailable")
		}
		pem, err := os.ReadFile(e.RootCertificate)
		roots = x509.NewCertPool()
		if err != nil || !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("source CA file is invalid")
		}
	}
	return &tls.Config{ServerName: e.Hostname, RootCAs: roots, MinVersion: tls.VersionTLS12}, nil
}

func (e Endpoint) DialTLS(ctx context.Context) (net.Conn, error) {
	config, err := e.tlsConfig()
	if err != nil {
		return nil, err
	}
	connect, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, ip := range e.Addresses {
		plain, err := e.DialContext(connect, "tcp", net.JoinHostPort(ip, strconv.Itoa(int(e.Port))))
		if err != nil {
			continue
		}
		deadline, _ := connect.Deadline()
		_ = plain.SetDeadline(deadline)
		var request [8]byte
		binary.BigEndian.PutUint32(request[:4], 8)
		binary.BigEndian.PutUint32(request[4:], 80877103)
		_, err = plain.Write(request[:])
		var reply [1]byte
		if err == nil {
			_, err = io.ReadFull(plain, reply[:])
		}
		if err != nil || reply[0] != 'S' {
			plain.Close()
			continue
		}
		secure := tls.Client(plain, config)
		if err = secure.HandshakeContext(connect); err != nil {
			secure.Close()
			continue
		}
		_ = secure.SetDeadline(time.Time{})
		return secure, nil
	}
	return nil, errors.New("approved source TLS connection failed")
}
