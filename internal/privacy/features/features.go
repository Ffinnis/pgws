// Package features is the shared offline/runtime metadata encoder. Its numeric
// inputs are aggregate profiles, never sampled row values. It grants no policy.
package features

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const ContractID = "pgws-column-profile-v1"
const Hashed = 16384
const Dimension = 16416
const MaxProfileBytes = 64 << 10

//go:embed contract.json
var contract []byte

// Bind the implementation and golden checks so encoder changes invalidate old
// model compatibility even when the descriptive contract was not edited.
//
//go:embed features.go
var encoderSource []byte

//go:embed numeric.go
var numericSource []byte

//go:embed features_test.go
var goldenSource []byte

//go:embed profile.go
var profilerSource []byte

//go:embed profile_test.go
var profilerGoldenSource []byte

var contractHash = func() string {
	digest := sha256.Sum256(bytes.Join([][]byte{contract, encoderSource, numericSource, goldenSource, profilerSource, profilerGoldenSource}, []byte{0}))
	return hex.EncodeToString(digest[:])
}()

func ContractDigest() string { return contractHash }

type Evidence struct {
	SamplingStatus string   `json:"sampling_status"`
	ReviewFlags    []string `json:"review_flags"`
}
type Profile struct {
	Contract  string             `json:"feature_contract_id"`
	Table     string             `json:"table_name"`
	Column    string             `json:"column_name"`
	Type      string             `json:"postgres_type"`
	Neighbors []string           `json:"neighbor_columns"`
	Numeric   map[string]float64 `json:"numeric_features"`
	Evidence  Evidence           `json:"evidence"`
}
type Entry struct {
	Index uint16  `json:"index"`
	Value float32 `json:"value"`
}
type Vector struct {
	Contract string   `json:"feature_contract_id"`
	Digest   string   `json:"feature_contract_digest"`
	Entries  []Entry  `json:"entries"`
	Review   bool     `json:"review_required"`
	Flags    []string `json:"review_flags"`
}

var allowedFlags = map[string]bool{"non_ascii_identifier": true, "truncated_value": true, "incomplete_sample": true, "feature_overflow": true, "unsupported_type": true, "mixed_content": true, "rule_conflict": true, "unknown_json_path": true}

// Decode rejects unknown fields, duplicate object keys and oversized inputs.
// Errors deliberately never echo identifiers or supplied document fragments.
func Decode(data []byte) (Profile, error) {
	var p Profile
	if len(data) > MaxProfileBytes || !utf8.Valid(data) {
		return p, errors.New("invalid profile size or encoding")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueJSON(d, 0); err != nil {
		return p, errors.New("invalid or ambiguous profile JSON")
	}
	if _, err := d.Token(); err != io.EOF {
		return p, errors.New("profile must contain one document")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, errors.New("invalid profile fields")
	}
	if err := validate(p); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errors.New("depth")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("null")
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("delimiter")
	}
	seen := map[string]bool{}
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate key")
			}
			seen[name] = true
		}
		if err := uniqueJSON(d, depth+1); err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil {
		return err
	}
	if delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
		return errors.New("delimiter")
	}
	return nil
}

func validate(p Profile) error {
	if p.Contract != ContractID || len(p.Neighbors) > 32 || p.Neighbors == nil || len(p.Numeric) != 32 || p.Evidence.ReviewFlags == nil {
		return errors.New("profile contract or required fields differ")
	}
	for _, item := range []struct {
		text  string
		limit int
	}{{p.Table, 256}, {p.Column, 256}, {p.Type, 128}} {
		if len(item.text) == 0 || utf8.RuneCountInString(item.text) > item.limit || !utf8.ValidString(item.text) || strings.ContainsRune(item.text, 0) {
			return errors.New("invalid profile metadata")
		}
		for _, r := range item.text {
			if r < 32 || r == 127 {
				return errors.New("control characters in profile metadata")
			}
		}
	}
	for _, name := range p.Neighbors {
		if len(name) == 0 || utf8.RuneCountInString(name) > 256 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) {
			return errors.New("invalid neighbor metadata")
		}
		for _, r := range name {
			if r < 32 || r == 127 {
				return errors.New("control characters in neighbor metadata")
			}
		}
	}
	for i, name := range numericNames {
		v, ok := p.Numeric[name]
		if !ok || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 || ((i == 0 || i >= 25) && v != 0 && v != 1) {
			return errors.New("invalid numeric profile features")
		}
		if i > 0 && i < 25 && p.Numeric["sample_present"] == 0 && v != 0 {
			return errors.New("sample aggregates without sampled evidence")
		}
	}
	if p.Evidence.SamplingStatus != "none" && p.Evidence.SamplingStatus != "partial" && p.Evidence.SamplingStatus != "bounded_complete" {
		return errors.New("invalid sampling evidence")
	}
	if p.Evidence.SamplingStatus == "none" && p.Numeric["sample_present"] != 0 || p.Evidence.SamplingStatus == "bounded_complete" && p.Numeric["sample_present"] != 1 {
		return errors.New("sampling status contradicts aggregates")
	}
	seen := map[string]bool{}
	for _, flag := range p.Evidence.ReviewFlags {
		if !allowedFlags[flag] || seen[flag] {
			return errors.New("invalid review evidence")
		}
		seen[flag] = true
	}
	return nil
}

func upper(c byte) bool { return c >= 'A' && c <= 'Z' }
func lower(c byte) bool { return c >= 'a' && c <= 'z' }
func digit(c byte) bool { return c >= '0' && c <= '9' }
func words(s string) ([]string, bool) {
	for _, b := range []byte(s) {
		if b >= 128 {
			return nil, false
		}
	}
	var result []string
	start := -1
	for i := 0; i <= len(s); i++ {
		if i == len(s) || !(upper(s[i]) || lower(s[i]) || digit(s[i])) {
			if start >= 0 {
				result = append(result, strings.ToLower(s[start:i]))
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
			continue
		}
		if upper(s[i]) && (lower(s[i-1]) || digit(s[i-1]) || (upper(s[i-1]) && i+1 < len(s) && lower(s[i+1]))) {
			result = append(result, strings.ToLower(s[start:i]))
			start = i
		}
	}
	return result, true
}

func hash(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

func Extract(p Profile) (Vector, error) {
	if err := validate(p); err != nil {
		return Vector{}, err
	}
	flags := map[string]bool{}
	for _, flag := range p.Evidence.ReviewFlags {
		flags[flag] = true
	}
	if p.Evidence.SamplingStatus != "bounded_complete" {
		flags["incomplete_sample"] = true
	}
	emitted := map[string]int{}
	add := func(name string) {
		if _, ok := emitted[name]; !ok && len(emitted) >= 2048 {
			flags["feature_overflow"] = true
			return
		}
		emitted[name]++
	}
	emit := func(namespace, value string) []string {
		tokens, ascii := words(value)
		if !ascii {
			flags["non_ascii_identifier"] = true
			return nil
		}
		if len(tokens) == 0 {
			flags["mixed_content"] = true
		}
		for _, token := range tokens {
			add(namespace + ":w:" + token)
			for n := 2; n <= 5; n++ {
				for i := 0; i+n <= len(token); i++ {
					add(namespace + ":c" + strconv.Itoa(n) + ":" + token[i:i+n])
				}
			}
		}
		return tokens
	}
	column := emit("column", p.Column)
	table := emit("table", p.Table)
	for _, name := range p.Neighbors {
		emit("neighbor", name)
	}
	emit("type", p.Type)
	for _, role := range []string{"primary_key", "foreign_key", "unique_constraint"} {
		if p.Numeric[role] == 1 {
			add("key_role:w:" + role)
		}
	}
	for _, a := range table {
		for _, b := range column {
			add("table_column_interaction:w:" + a + "/" + b)
		}
	}
	switch strings.ToLower(p.Type) {
	case "text", "varchar", "character varying", "char", "character", "bpchar", "name", "uuid", "int2", "int4", "int8", "smallint", "integer", "bigint", "numeric", "decimal", "float4", "float8", "real", "double precision", "boolean", "bool", "date", "timestamp", "timestamptz", "timestamp without time zone", "timestamp with time zone", "json", "jsonb":
	default:
		flags["unsupported_type"] = true
	}
	if p.Numeric["structured_like"] == 1 || strings.EqualFold(p.Type, "json") || strings.EqualFold(p.Type, "jsonb") {
		flags["unknown_json_path"] = true
	}
	buckets := map[uint16]int{}
	for feature, count := range emitted {
		h := hash(feature)
		index := uint16(h & 16383)
		if h>>63 != 0 {
			count = -count
		}
		buckets[index] += count
	}
	indices := make([]int, 0, len(buckets))
	for index, value := range buckets {
		if value != 0 {
			indices = append(indices, int(index))
		}
	}
	slices.Sort(indices)
	norm := float64(0)
	for _, index := range indices {
		v := float64(buckets[uint16(index)])
		norm += v * v
	}
	norm = math.Sqrt(norm)
	out := Vector{Contract: ContractID, Digest: ContractDigest(), Entries: []Entry{}, Flags: []string{}}
	for _, index := range indices {
		out.Entries = append(out.Entries, Entry{uint16(index), float32(float64(buckets[uint16(index)]) / norm)})
	}
	for i, name := range numericNames {
		if value := p.Numeric[name]; value != 0 {
			out.Entries = append(out.Entries, Entry{uint16(Hashed + i), float32(value)})
		}
	}
	for flag := range flags {
		out.Flags = append(out.Flags, flag)
	}
	slices.Sort(out.Flags)
	out.Review = len(out.Flags) != 0
	return out, nil
}
