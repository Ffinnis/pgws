package features

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func fixture() Profile {
	p := Profile{Contract: ContractID, Table: "x", Column: "x", Type: "int8", Neighbors: []string{}, Numeric: map[string]float64{}, Evidence: Evidence{SamplingStatus: "none", ReviewFlags: []string{}}}
	for _, name := range numericNames {
		p.Numeric[name] = 0
	}
	return p
}

func TestNormalizationAndHashGolden(t *testing.T) {
	for _, test := range []struct {
		value string
		want  []string
		ascii bool
	}{{"HTTPServerID", []string{"http", "server", "id"}, true}, {"user2FA_name", []string{"user2", "fa", "name"}, true}, {"XMLHttpRequest", []string{"xml", "http", "request"}, true}, {"some__email.address", []string{"some", "email", "address"}, true}, {"---", nil, true}, {"имя", nil, false}} {
		got, ascii := words(test.value)
		if ascii != test.ascii || !slices.Equal(got, test.want) {
			t.Fatalf("normalization differs for %q: %v", test.value, got)
		}
	}
	if hash("hello") != 0xa430d84680aabd0b {
		t.Fatal("FNV-1a differs from published hello vector")
	}
	a, b := hash("column:w:fixture1565"), hash("column:w:fixture1950")
	if a&16383 != 5832 || b&16383 != 5832 || a>>63 == b>>63 {
		t.Fatal("fixed cancelling collision differs")
	}
	if hash("table:w:email") == hash("column:w:email") {
		t.Fatal("namespaces collapsed")
	}
}

func TestSparseVectorGolden(t *testing.T) {
	p := fixture()
	vector, err := Extract(p)
	if err != nil {
		t.Fatal(err)
	}
	indices := []uint16{850, 1007, 1882, 3252, 5996, 8843, 9697, 10226, 13475, 14363}
	signs := []float32{-1, 1, 1, 1, -1, -1, -1, 1, 1, 1}
	if len(vector.Entries) != len(indices) || !vector.Review || !slices.Equal(vector.Flags, []string{"incomplete_sample"}) {
		t.Fatal("golden shape or evidence differs", vector)
	}
	for i, entry := range vector.Entries {
		if entry.Index != indices[i] || entry.Value != signs[i]*float32(0.3162277638912201) {
			t.Fatal("fixed vector differs", entry)
		}
	}
	p.Numeric["nullable"] = 1
	p.Numeric["numeric_like"] = 1
	next, err := Extract(p)
	if err != nil || !slices.Equal(next.Entries[len(indices):], []Entry{{16409, 1}, {16414, 1}}) {
		t.Fatal("numeric block order differs", err)
	}
	for i := 0; i < 20; i++ {
		again, _ := Extract(p)
		if !reflect.DeepEqual(next, again) {
			t.Fatal("map order changed features")
		}
	}
}

func TestReviewBoundaries(t *testing.T) {
	for _, kind := range []string{"non_ascii_identifier", "feature_overflow", "unsupported_type", "unknown_json_path", "mixed_content"} {
		t.Run(kind, func(t *testing.T) {
			p := fixture()
			switch kind {
			case "non_ascii_identifier":
				p.Column = "имя"
			case "feature_overflow":
				for i := 0; i < 32; i++ {
					p.Neighbors = append(p.Neighbors, fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprint(i)))))
				}
			case "unsupported_type":
				p.Type = "private_type"
			case "unknown_json_path":
				p.Type = "jsonb"
				p.Numeric["structured_like"] = 1
			case "mixed_content":
				p.Column = "---"
			}
			v, err := Extract(p)
			if err != nil || !v.Review || !slices.Contains(v.Flags, kind) {
				t.Fatal("unsafe profile did not require review", v.Flags, err)
			}
			if len(v.Entries) > 2048+32 {
				t.Fatal("feature cap exceeded")
			}
		})
	}
}

func TestMalformedProfileDoesNotLeakInput(t *testing.T) {
	encoded, _ := json.Marshal(fixture())
	for _, bad := range [][]byte{
		[]byte(`{"raw_values":["private-canary"]}`),
		[]byte(strings.Replace(string(encoded), `"column_name":"x"`, `"column_name":"x","column_name":"private-canary"`, 1)),
		[]byte(strings.Replace(string(encoded), `"sample_present":0`, `"sample_present":null`, 1)),
		append(encoded, encoded...), []byte(strings.Repeat("x", MaxProfileBytes+1)),
	} {
		if _, err := Decode(bad); err == nil || strings.Contains(err.Error(), "private-canary") {
			t.Fatal("ambiguous profile accepted or echoed")
		}
	}
	for _, change := range []func(*Profile){func(p *Profile) { delete(p.Numeric, "nullable") }, func(p *Profile) { p.Numeric["nullable"] = 0.5 }, func(p *Profile) { p.Numeric["ascii_fraction"] = math.NaN() }, func(p *Profile) { p.Numeric["non_null_count_log"] = 1 }, func(p *Profile) { p.Neighbors = nil }, func(p *Profile) { p.Evidence.ReviewFlags = []string{"raw-value-canary"} }, func(p *Profile) { p.Evidence.SamplingStatus = "bounded_complete" }} {
		p := fixture()
		change(&p)
		if _, err := Extract(p); err == nil {
			t.Fatal("malformed aggregate accepted")
		}
	}
}

func TestPinnedNumericContract(t *testing.T) {
	var spec struct {
		Names []string `json:"numeric_features"`
	}
	if err := json.Unmarshal(contract, &spec); err != nil || !slices.Equal(spec.Names, NumericOrder()) {
		t.Fatal("descriptor and numeric order differ", err)
	}
	order := NumericOrder()
	order[0] = "changed"
	if NumericOrder()[0] != "sample_present" {
		t.Fatal("caller mutated contract")
	}
}

func FuzzDecodeAndExtract(f *testing.F) {
	encoded, _ := json.Marshal(fixture())
	f.Add(encoded)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Decode(b)
		if err != nil {
			return
		}
		v, err := Extract(p)
		if err != nil {
			t.Fatal(err)
		}
		last := -1
		for _, entry := range v.Entries {
			if int(entry.Index) <= last || int(entry.Index) >= Dimension || math.IsNaN(float64(entry.Value)) || math.IsInf(float64(entry.Value), 0) {
				t.Fatal("invalid sparse output")
			}
			last = int(entry.Index)
		}
	})
}
