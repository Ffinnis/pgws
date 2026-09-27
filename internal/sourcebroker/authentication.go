package sourcebroker

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"
)

// The broker terminates verified TLS; its Unix clients cannot bind SCRAM to
// that TLS session. Do not advertise SCRAM-PLUS on the non-TLS local hop.
// PostgreSQL still verifies ordinary SCRAM end to end. The host's direct SQL
// connection remains free to negotiate channel binding on its own TLS session.
func relayAuthenticationOffer(client io.Writer, upstream io.Reader) error {
	for range 8 {
		var header [5]byte
		if _, err := io.ReadFull(upstream, header[:]); err != nil {
			return err
		}
		size := binary.BigEndian.Uint32(header[1:])
		if size < 4 || size > 16384 {
			return errors.New("invalid source authentication frame")
		}
		body := make([]byte, size-4)
		if _, err := io.ReadFull(upstream, body); err != nil {
			return err
		}
		if header[0] == 'R' && len(body) >= 4 && binary.BigEndian.Uint32(body[:4]) == 10 {
			// The list ends with an empty mechanism, hence two trailing NULs.
			if len(body) < 6 || body[len(body)-1] != 0 || body[len(body)-2] != 0 {
				return errors.New("invalid source SASL mechanisms")
			}
			mechanisms := strings.Split(string(body[4:len(body)-2]), "\x00")
			found := false
			for _, mechanism := range mechanisms {
				if mechanism == "SCRAM-SHA-256" {
					found = true
				}
			}
			if !found {
				return errors.New("source does not offer ordinary SCRAM over the broker")
			}
			body = append(body[:4], []byte("SCRAM-SHA-256\x00\x00")...)
			binary.BigEndian.PutUint32(header[1:], uint32(len(body)+4))
		}
		if _, err := client.Write(header[:]); err != nil {
			return err
		}
		if _, err := client.Write(body); err != nil {
			return err
		}
		switch header[0] {
		case 'R':
			return nil
		case 'N', 'v': // A bounded notice or protocol negotiation may precede auth.
		default:
			return errors.New("source rejected replication startup")
		}
	}
	return errors.New("source authentication prelude exceeded its bound")
}
