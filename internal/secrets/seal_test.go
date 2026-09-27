package secrets

import (
	"bytes"
	"testing"
)

func TestReceiptBinding(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	ciphertext, e := Seal(key, []byte("password"), []byte("tenant/project/principal/op"))
	if e != nil {
		t.Fatal(e)
	}
	if p, e := Open(key, ciphertext, []byte("tenant/project/principal/op")); e != nil || string(p) != "password" {
		t.Fatal(e)
	}
	if _, e = Open(key, ciphertext, []byte("other tenant")); e == nil {
		t.Fatal("receipt crossed scope")
	}
}
