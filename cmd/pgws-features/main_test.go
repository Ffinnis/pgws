package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"pgws/internal/privacy/features"
)

func TestFeatureExportUsesRFCProfile(t *testing.T) {
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
	var compact bytes.Buffer
	json.Compact(&compact, record.Profile)
	var out bytes.Buffer
	if err = run(strings.NewReader(compact.String()+"\n"+compact.String()+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || lines[0] != lines[1] {
		t.Fatal("batch export unstable")
	}
	var vector features.Vector
	if err = json.Unmarshal([]byte(lines[0]), &vector); err != nil || vector.Digest != features.ContractDigest() || !vector.Review {
		t.Fatal("contract/evidence omitted", err)
	}
	if strings.Contains(out.String(), "firstName") || strings.Contains(out.String(), "users") {
		t.Fatal("raw metadata leaked into sparse output")
	}
	out.Reset()
	if err = run(strings.NewReader(`{"raw_values":["private-canary"]}`), &out); err == nil || strings.Contains(err.Error(), "private-canary") || out.Len() != 0 {
		t.Fatal("invalid input exported or leaked")
	}
}
