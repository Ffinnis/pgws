// Package classify verifies signed data-only model bundles and scores sparse
// profiles locally. Every result requires review; scores never authorize copy.
package classify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"unicode/utf8"

	"pgws/internal/privacy/features"
)

const Classes = 24
const Runtime = "pgws-go-classifier-v1"
const Magic = "PGWSCLF1"
const MaxBundleBytes = 4 << 20
const WeightBytes = Classes * features.Dimension * 4
const BiasBytes = Classes * 4

// The signature covers magic, manifest length, exact manifest bytes, weights
// and biases. The public key comes from operator configuration, never the file.
type Manifest struct {
	Format          string   `json:"format"`
	Runtime         string   `json:"runtime"`
	FeatureDigest   string   `json:"feature_contract_digest"`
	Labels          []string `json:"labels"`
	DatasetDigest   string   `json:"dataset_digest"`
	SplitDigest     string   `json:"split_digest"`
	TrainerRevision string   `json:"trainer_revision"`
	ModelCardDigest string   `json:"model_card_digest"`
	WeightsDigest   string   `json:"weights_sha256"`
	BiasDigest      string   `json:"bias_sha256"`
	Temperature     float64  `json:"temperature"`
	AutoAccept      bool     `json:"auto_accept"`
}

type Model struct {
	weights     []float32
	bias        [Classes]float32
	temperature float64
	digest      string
}

func (m *Model) Digest() string { return m.digest }
func digest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func validDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

// Pack signs only a complete compatible review-only candidate. It verifies its
// own output through the runtime loader before returning any release bytes.
func Pack(manifest Manifest, weights, bias []byte, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || len(weights) != WeightBytes || len(bias) != BiasBytes {
		return nil, errors.New("invalid classifier export shape or signing key")
	}
	if manifest.WeightsDigest != digest(weights) || manifest.BiasDigest != digest(bias) {
		return nil, errors.New("classifier candidate checksum differs from reviewed manifest")
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, errors.New("invalid classifier export manifest")
	}
	data := append([]byte(Magic), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(encoded)))
	data = append(data, encoded...)
	data = append(data, weights...)
	data = append(data, bias...)
	data = append(data, ed25519.Sign(key, data)...)
	if _, err = Load(bytes.NewReader(data), key.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	return data, nil
}

func Load(r io.Reader, key ed25519.PublicKey) (*Model, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBundleBytes+1))
	if err != nil || len(data) > MaxBundleBytes || len(data) < 12+WeightBytes+BiasBytes+ed25519.SignatureSize || string(data[:8]) != Magic || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("invalid classifier bundle envelope")
	}
	n := int(binary.LittleEndian.Uint32(data[8:12]))
	if n < 2 || n > 64<<10 || len(data) != 12+n+WeightBytes+BiasBytes+ed25519.SignatureSize {
		return nil, errors.New("classifier bundle shape differs")
	}
	payload := data[:len(data)-ed25519.SignatureSize]
	if !ed25519.Verify(key, payload, data[len(payload):]) {
		return nil, errors.New("classifier release signature rejected")
	}
	manifest, err := DecodeManifest(data[12 : 12+n])
	if err != nil {
		return nil, err
	}
	w, b := data[12+n:12+n+WeightBytes], data[12+n+WeightBytes:len(payload)]
	if digest(w) != manifest.WeightsDigest || digest(b) != manifest.BiasDigest {
		return nil, errors.New("classifier data checksum differs")
	}
	m := &Model{weights: make([]float32, WeightBytes/4), temperature: manifest.Temperature, digest: digest(payload)}
	decode := func(data []byte, values []float32) bool {
		for i := range values {
			v := math.Float32frombits(binary.LittleEndian.Uint32(data[i*4:]))
			if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
				return false
			}
			values[i] = v
		}
		return true
	}
	if !decode(w, m.weights) || !decode(b, m.bias[:]) {
		return nil, errors.New("classifier contains non-finite parameters")
	}
	return m, nil
}

// DecodeManifest applies the same strict contract before signing and loading.
func DecodeManifest(data []byte) (Manifest, error) {
	var manifest Manifest
	if len(data) > 64<<10 || !utf8.Valid(data) || !manifestKeys(data) {
		return Manifest{}, errors.New("classifier manifest fields are ambiguous or incomplete")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF || manifest.Format != "pgws.column-model.v1" || manifest.Runtime != Runtime || manifest.FeatureDigest != features.ContractDigest() || !slices.Equal(manifest.Labels, labels[:]) || manifest.AutoAccept || !validDigest(manifest.DatasetDigest) || !validDigest(manifest.SplitDigest) || !validDigest(manifest.TrainerRevision) || !validDigest(manifest.ModelCardDigest) || manifest.Temperature <= 0 || math.IsNaN(manifest.Temperature) || math.IsInf(manifest.Temperature, 0) {
		return Manifest{}, errors.New("classifier manifest is incompatible or unqualified")
	}
	return manifest, nil
}

func manifestKeys(data []byte) bool {
	d := json.NewDecoder(bytes.NewReader(data))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	allowed := map[string]bool{"format": true, "runtime": true, "feature_contract_digest": true, "labels": true, "dataset_digest": true, "split_digest": true, "trainer_revision": true, "model_card_digest": true, "weights_sha256": true, "bias_sha256": true, "temperature": true, "auto_accept": true}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || !allowed[name] || seen[name] {
			return false
		}
		seen[name] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return false
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != 12 {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}

type Proposal struct {
	Label         string           `json:"label"`
	Score         float64          `json:"score"`
	Margin        float64          `json:"margin"`
	Scores        [Classes]float64 `json:"scores"`
	ModelDigest   string           `json:"model_digest"`
	FeatureDigest string           `json:"feature_contract_digest"`
	Review        bool             `json:"review_required"`
	Flags         []string         `json:"review_flags"`
}

// The package limit is shared across immutable model versions, so swapping a
// model while old jobs finish does not double the inference concurrency budget.
var inferenceSlots = make(chan struct{}, 8)

func (m *Model) Score(ctx context.Context, vector features.Vector) (Proposal, error) {
	var result Proposal
	if m == nil || len(m.weights) != Classes*features.Dimension || vector.Contract != features.ContractID || vector.Digest != features.ContractDigest() || len(vector.Entries) > 2048+32 {
		return result, errors.New("classifier input contract differs")
	}
	last := -1
	norm := float64(0)
	hashed := 0
	for _, entry := range vector.Entries {
		v := float64(entry.Value)
		if int(entry.Index) <= last || int(entry.Index) >= features.Dimension || math.IsNaN(v) || math.IsInf(v, 0) || v == 0 || v < -1 || v > 1 || int(entry.Index) >= features.Hashed && v < 0 {
			return result, errors.New("invalid classifier sparse input")
		}
		last = int(entry.Index)
		if int(entry.Index) < features.Hashed {
			norm += v * v
			hashed++
		}
	}
	if hashed > 2048 || hashed > 0 && math.Abs(norm-1) > 1e-5 {
		return result, errors.New("classifier hashed block is not normalized")
	}
	select {
	case inferenceSlots <- struct{}{}:
		defer func() { <-inferenceSlots }()
	case <-ctx.Done():
		return result, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	maxLogit := math.Inf(-1)
	for class := 0; class < Classes; class++ {
		logit := float64(m.bias[class])
		base := class * features.Dimension
		for _, entry := range vector.Entries {
			logit += float64(m.weights[base+int(entry.Index)]) * float64(entry.Value)
		}
		logit /= m.temperature
		if math.IsNaN(logit) || math.IsInf(logit, 0) {
			return Proposal{}, errors.New("classifier score exceeded finite bounds")
		}
		result.Scores[class] = logit
		maxLogit = math.Max(maxLogit, logit)
	}
	sum := float64(0)
	for i, logit := range result.Scores {
		p := math.Exp(logit - maxLogit)
		result.Scores[i] = p
		sum += p
	}
	best, second := 0, 1
	for i := range result.Scores {
		result.Scores[i] /= sum
	}
	if result.Scores[second] > result.Scores[best] {
		best, second = second, best
	}
	for i := 2; i < Classes; i++ {
		if result.Scores[i] > result.Scores[best] {
			second, best = best, i
		} else if result.Scores[i] > result.Scores[second] {
			second = i
		}
	}
	result.Label, result.Score, result.Margin = labels[best], result.Scores[best], result.Scores[best]-result.Scores[second]
	result.ModelDigest, result.FeatureDigest, result.Review = m.digest, vector.Digest, true
	result.Flags = []string{"unqualified_model"}
	// Do not echo arbitrary caller-supplied strings through a scoring result.
	if vector.Review || len(vector.Flags) > 0 {
		result.Flags = append(result.Flags, "profile_requires_review")
	}
	return result, nil
}
