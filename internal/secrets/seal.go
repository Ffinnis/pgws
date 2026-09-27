// Package secrets encrypts credential receipts with explicit project/principal
// binding. Keys are external configuration, never stored in management tables.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

func aead(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("a 32-byte encryption key is required")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func Seal(key, plain, aad []byte) (string, error) {
	g, e := aead(key)
	if e != nil {
		return "", e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return "", e
	}
	return base64.RawStdEncoding.EncodeToString(g.Seal(n, n, plain, aad)), nil
}
func Open(key []byte, sealed string, aad []byte) ([]byte, error) {
	g, e := aead(key)
	if e != nil {
		return nil, e
	}
	b, e := base64.RawStdEncoding.DecodeString(sealed)
	if e != nil || len(b) < g.NonceSize() {
		return nil, errors.New("invalid sealed credential")
	}
	return g.Open(nil, b[:g.NonceSize()], b[g.NonceSize():], aad)
}
