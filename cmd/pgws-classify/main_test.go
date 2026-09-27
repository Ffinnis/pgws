package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pgws/internal/privacy/classify"
	"pgws/internal/privacy/features"
)

func TestReviewOnlyCLI(t *testing.T) {
	root := t.TempDir()
	weights, bias := make([]byte, classify.WeightBytes), make([]byte, classify.BiasBytes)
	digest := func(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
	manifest := classify.Manifest{Format: "pgws.column-model.v1", Runtime: classify.Runtime, FeatureDigest: features.ContractDigest(), Labels: classify.Labels(), DatasetDigest: strings.Repeat("1", 64), SplitDigest: strings.Repeat("2", 64), TrainerRevision: strings.Repeat("3", 64), ModelCardDigest: strings.Repeat("4", 64), WeightsDigest: digest(weights), BiasDigest: digest(bias), Temperature: 1}
	encoded, _ := json.Marshal(manifest)
	bundle := append([]byte(classify.Magic), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(bundle[8:], uint32(len(encoded)))
	bundle = append(bundle, encoded...)
	bundle = append(bundle, weights...)
	bundle = append(bundle, bias...)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{6}, 32))
	bundle = append(bundle, ed25519.Sign(private, bundle)...)
	modelPath, keyPath := filepath.Join(root, "fixture.model"), filepath.Join(root, "release.pub")
	if err := os.WriteFile(modelPath, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))), 0600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../contracts/classifier/training-record.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Profile json.RawMessage `json:"profile"`
	}
	if err = json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	var profile, out bytes.Buffer
	json.Compact(&profile, record.Profile)
	if err = run(context.Background(), []string{modelPath, keyPath}, &profile, &out); err != nil {
		t.Fatal(err)
	}
	var result classify.Proposal
	if err = json.Unmarshal(out.Bytes(), &result); err != nil || !result.Review || result.Score != 1.0/24 || result.Margin != 0 {
		t.Fatal("uniform arithmetic fixture bypassed review", err)
	}
	out.Reset()
	bundle[len(bundle)-1] ^= 1
	if err = os.WriteFile(modelPath, bundle, 0600); err != nil {
		t.Fatal(err)
	}
	if err = run(context.Background(), []string{modelPath, keyPath}, strings.NewReader("{}"), &out); err == nil || out.Len() != 0 {
		t.Fatal("invalid model emitted a proposal")
	}
}
