package classify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"pgws/internal/privacy/features"
)

// Arithmetic fixture only. These parameters are not trained or distributed.
func fixtureBundle(edit func(*Manifest, []byte, []byte)) ([]byte, ed25519.PublicKey) {
	w, b := make([]byte, WeightBytes), make([]byte, BiasBytes)
	for class := 0; class < Classes; class++ {
		binary.LittleEndian.PutUint32(w[(class*features.Dimension+features.Hashed)*4:], math.Float32bits(float32(class)/8))
		binary.LittleEndian.PutUint32(b[class*4:], math.Float32bits(-float32(class)/16))
	}
	manifest := Manifest{Format: "pgws.column-model.v1", Runtime: Runtime, FeatureDigest: features.ContractDigest(), Labels: Labels(), DatasetDigest: strings.Repeat("1", 64), SplitDigest: strings.Repeat("2", 64), TrainerRevision: strings.Repeat("3", 64), ModelCardDigest: strings.Repeat("4", 64), Temperature: 2}
	if edit != nil {
		edit(&manifest, w, b)
	}
	manifest.WeightsDigest, manifest.BiasDigest = digest(w), digest(b)
	encoded, _ := json.Marshal(manifest)
	data := append([]byte(Magic), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(encoded)))
	data = append(data, encoded...)
	data = append(data, w...)
	data = append(data, b...)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	data = append(data, ed25519.Sign(key, data)...)
	return data, key.Public().(ed25519.PublicKey)
}
func vector() features.Vector {
	return features.Vector{Contract: features.ContractID, Digest: features.ContractDigest(), Entries: []features.Entry{{Index: features.Hashed, Value: 1}}}
}

func TestSignedModelScoresAndReviewOnly(t *testing.T) {
	b, key := fixtureBundle(nil)
	m, err := Load(bytes.NewReader(b), key)
	if err != nil {
		t.Fatal(err)
	}
	proposal, err := m.Score(context.Background(), vector())
	if err != nil {
		t.Fatal(err)
	}
	// Python reference: exp((class/8-class/16)/2-max_logit).
	const expectedLast = 0.05831087032766188
	if math.Abs(proposal.Score-expectedLast) > 1e-12 {
		t.Fatal("Python reference score parity", proposal.Score)
	}
	if proposal.Label != "other" || !proposal.Review || !slices.Contains(proposal.Flags, "unqualified_model") || proposal.ModelDigest != m.Digest() {
		t.Fatal("model bypassed review or lost identity")
	}
	var sum float64
	for _, p := range proposal.Scores {
		sum += p
	}
	if math.Abs(sum-1) > 1e-12 {
		t.Fatal("softmax normalization")
	}
	// Mutating the caller's bundle after loading cannot alter an active model.
	clear(b)
	again, err := m.Score(context.Background(), vector())
	if err != nil || again.Scores != proposal.Scores {
		t.Fatal("mutable model state", err)
	}
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			p, err := m.Score(context.Background(), vector())
			if err != nil || p.Scores != proposal.Scores {
				t.Error("concurrent immutable scoring", err)
			}
		}()
	}
	group.Wait()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = m.Score(ctx, vector()); err == nil {
		t.Fatal("cancelled inference ran")
	}
}

func TestModelRejectsCorruptOrUnqualifiedArtifacts(t *testing.T) {
	for _, kind := range []string{"signature", "shape", "trailing", "feature", "labels", "nan", "infinity", "temperature", "automatic", "dataset", "runtime"} {
		t.Run(kind, func(t *testing.T) {
			data, key := fixtureBundle(func(m *Manifest, w, b []byte) {
				switch kind {
				case "feature":
					m.FeatureDigest = strings.Repeat("0", 64)
				case "labels":
					m.Labels[0], m.Labels[1] = m.Labels[1], m.Labels[0]
				case "nan":
					binary.LittleEndian.PutUint32(w, 0x7fc00000)
				case "infinity":
					binary.LittleEndian.PutUint32(b, 0x7f800000)
				case "temperature":
					m.Temperature = 0
				case "automatic":
					m.AutoAccept = true
				case "dataset":
					m.DatasetDigest = "private-canary"
				case "runtime":
					m.Runtime = "python-pickle"
				}
			})
			switch kind {
			case "signature":
				data[len(data)-1] ^= 1
			case "shape":
				data = data[:len(data)-1]
			case "trailing":
				data = append(data, 0)
			}
			if _, err := Load(bytes.NewReader(data), key); err == nil || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("unsafe artifact accepted or echoed")
			}
		})
	}
	data, key := fixtureBundle(nil)
	key[0] ^= 1
	if _, err := Load(bytes.NewReader(data), key); err == nil {
		t.Fatal("untrusted release key accepted")
	}
	if _, err := Load(bytes.NewReader(make([]byte, MaxBundleBytes+1)), key); err == nil {
		t.Fatal("oversized model accepted")
	}
	if manifestKeys([]byte(`{"temperature":1,"temperature":2}`)) {
		t.Fatal("duplicate manifest fields accepted")
	}
}

func TestMalformedSparseInputs(t *testing.T) {
	data, key := fixtureBundle(nil)
	m, err := Load(bytes.NewReader(data), key)
	if err != nil {
		t.Fatal(err)
	}
	for _, entries := range [][]features.Entry{{{Index: features.Dimension, Value: 1}}, {{Index: 0, Value: 1}, {Index: 0, Value: 1}}, {{Index: 4, Value: 0.5}}, {{Index: 0, Value: float32(math.NaN())}}, {{Index: features.Hashed, Value: -1}}} {
		v := vector()
		v.Entries = entries
		if _, err = m.Score(context.Background(), v); err == nil {
			t.Fatal("invalid sparse input accepted")
		}
	}
	v := vector()
	v.Digest = strings.Repeat("0", 64)
	if _, err = m.Score(context.Background(), v); err == nil {
		t.Fatal("incompatible extractor accepted")
	}
}

func TestLabelOrderMatchesRFC(t *testing.T) {
	b, err := os.ReadFile("../../../contracts/classifier/spec.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Labels []string `json:"labels"`
	}
	if err = json.Unmarshal(b, &spec); err != nil || !slices.Equal(spec.Labels, Labels()) {
		t.Fatal("RFC class order differs", err)
	}
	order := Labels()
	order[0] = "changed"
	if Labels()[0] != "person_given_name" {
		t.Fatal("caller mutated class order")
	}
}
