package classify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"strings"
	"testing"
)

func TestPackBindsReviewedBytesAndStrictManifest(t *testing.T) {
	data, public := fixtureBundle(nil)
	n := int(binary.LittleEndian.Uint32(data[8:12]))
	metadata := data[12 : 12+n]
	manifest, err := DecodeManifest(metadata)
	if err != nil {
		t.Fatal(err)
	}
	weights := data[12+n : 12+n+WeightBytes]
	bias := data[12+n+WeightBytes : len(data)-64]
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	packed, err := Pack(manifest, weights, bias, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Load(bytes.NewReader(packed), public); err != nil {
		t.Fatal(err)
	}
	weights[0] ^= 1
	if _, err = Pack(manifest, weights, bias, key); err == nil {
		t.Fatal("signed changed weights under reviewed manifest")
	}
	for _, invalid := range []string{
		strings.Replace(string(metadata), `"auto_accept":false`, `"auto_accept":false,"auto_accept":false`, 1),
		strings.Replace(string(metadata), `,"auto_accept":false`, "", 1),
		strings.Replace(string(metadata), `"auto_accept":false`, `"auto_accept":null`, 1),
		strings.Replace(string(metadata), `"auto_accept":false`, `"AUTO_ACCEPT":false`, 1),
		string(metadata) + "{}",
		string(append([]byte{0xff}, metadata...)),
	} {
		if _, err = DecodeManifest([]byte(invalid)); err == nil {
			t.Fatal("ambiguous candidate manifest accepted")
		}
	}
}
