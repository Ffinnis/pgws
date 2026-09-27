package features

import (
	"encoding/json"
	"math"
	"slices"
	"strings"
	"testing"
)

func sample(value string) Sample { return Sample{Value: &value} }
func metadata() Metadata {
	return Metadata{Table: "accounts", Column: "contact", Type: "text", Neighbors: []string{}, Nullable: true}
}

func TestProfileDenominatorsAndNoRawOutput(t *testing.T) {
	input := []Sample{{}, sample(""), sample("ABC"), sample("ABC"), sample("x@y.invalid"), {Value: sample("notcomplete").Value, Truncated: true}}
	p, err := ProfileSamples(metadata(), input, true)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{"sample_present": 1, "non_null_count_log": math.Log1p(5) / math.Log1p(64), "null_fraction": 1.0 / 6, "empty_fraction": 1.0 / 5, "mean_length_log": math.Log1p(28.0/5) / math.Log1p(256), "p95_length_log": math.Log1p(11) / math.Log1p(256), "max_length_log": math.Log1p(11) / math.Log1p(256), "sample_distinct_fraction": 3.0 / 4, "ascii_fraction": 1, "alphabetic_fraction": 2.0 / 3, "email_pattern_fraction": 1.0 / 3, "at_sign_fraction": 1.0 / 3, "nullable": 1, "text_like": 1}
	for _, name := range numericNames {
		if math.Abs(p.Numeric[name]-want[name]) > 1e-12 {
			t.Fatal("profile denominator differs", name, p.Numeric[name], want[name])
		}
	}
	if p.Evidence.SamplingStatus != "partial" || !slices.Equal(p.Evidence.ReviewFlags, []string{"incomplete_sample", "truncated_value"}) {
		t.Fatal("truncation evidence lost")
	}
	data, _ := json.Marshal(p)
	for _, value := range []string{"x@y.invalid", "notcomplete", "ABC"} {
		if strings.Contains(string(data), value) {
			t.Fatal("raw sample in profile")
		}
	}
	if _, err = Decode(data); err != nil {
		t.Fatal("profiler violated feature input contract", err)
	}
}

func TestProfileFormats(t *testing.T) {
	for _, test := range []struct{ value, feature string }{{"-.25e+2", "numeric_fraction"}, {"a.b@example.invalid", "email_pattern_fraction"}, {"+1 (202) 555-0100", "phone_pattern_fraction"}, {"10000000-0000-4000-8000-000000000001", "uuid_pattern_fraction"}, {"2001:db8::1", "ip_pattern_fraction"}, {"https://example.invalid/path", "url_pattern_fraction"}, {"2000-02-29", "iso_date_pattern_fraction"}, {"4242-4242-4242-4242", "payment_card_pattern_fraction"}, {"ghp_fixture_not_real_1234567890", "secret_marker_fraction"}, {"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", "high_entropy_fraction"}, {`{"example":true}`, "json_object_fraction"}, {`[1,2]`, "json_array_fraction"}, {"line\nline", "multiline_fraction"}} {
		t.Run(test.feature, func(t *testing.T) {
			p, err := ProfileSamples(metadata(), []Sample{sample(test.value)}, true)
			if err != nil || p.Numeric[test.feature] != 1 {
				t.Fatal("format fixture failed", test.feature, err)
			}
		})
	}
	for _, test := range []struct{ value, feature string }{{"not..valid@example.invalid", "email_pattern_fraction"}, {"123", "phone_pattern_fraction"}, {"fe80::1%eth0", "ip_pattern_fraction"}, {"2001-02-29", "iso_date_pattern_fraction"}, {"0000000000000000", "payment_card_pattern_fraction"}, {"4242424242424243", "payment_card_pattern_fraction"}, {"not-json", "json_object_fraction"}, {"https://private@example.invalid", "url_pattern_fraction"}} {
		p, err := ProfileSamples(metadata(), []Sample{sample(test.value)}, true)
		if err != nil || p.Numeric[test.feature] != 0 {
			t.Fatal("unsupported format accepted", test.feature, err)
		}
	}
}

func TestProfileQuantileAndBoundaries(t *testing.T) {
	var input []Sample
	for i := 1; i <= 20; i++ {
		input = append(input, sample(strings.Repeat("x", i)))
	}
	p, err := ProfileSamples(metadata(), input, true)
	if err != nil || math.Abs(p.Numeric["p95_length_log"]-math.Log1p(19)/math.Log1p(256)) > 1e-12 {
		t.Fatal("nearest rank p95 differs", err)
	}
	for _, input := range [][]Sample{nil, {{}, {}}} {
		p, err = ProfileSamples(metadata(), input, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range numericNames {
			if p.Numeric[name] < 0 || p.Numeric[name] > 1 || math.IsNaN(p.Numeric[name]) {
				t.Fatal("zero denominator produced invalid feature")
			}
		}
	}
	for _, input := range [][]Sample{make([]Sample, 65), {sample(strings.Repeat("private-canary", 30))}, {{Truncated: true}}, {sample(string([]byte{0xff}))}} {
		if _, err = ProfileSamples(metadata(), input, true); err == nil || strings.Contains(err.Error(), "private-canary") {
			t.Fatal("invalid sample accepted or leaked")
		}
	}
	m := metadata()
	m.Type = "jsonb"
	p, err = ProfileSamples(m, nil, false)
	if err != nil || p.Numeric["structured_like"] != 1 || !slices.Contains(p.Evidence.ReviewFlags, "unknown_json_path") {
		t.Fatal("container path evidence omitted", err)
	}
	m.Type = "opaque_custom_type"
	p, err = ProfileSamples(m, nil, false)
	if err != nil || !slices.Contains(p.Evidence.ReviewFlags, "unsupported_type") {
		t.Fatal("unsupported type silently profiled", err)
	}
}
