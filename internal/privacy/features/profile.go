package features

import (
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type Sample struct {
	Value     *string
	Truncated bool
}
type Metadata struct {
	Table, Column, Type                      string
	Neighbors                                []string
	Nullable, PrimaryKey, ForeignKey, Unique bool
}

var numberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
var emailPattern = regexp.MustCompile("^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ProfileSamples consumes a bounded, already returned sample. It performs no
// source query and makes no claim about representativeness or upstream I/O.
// Raw values never appear in its result, errors or persistent state.
func ProfileSamples(meta Metadata, samples []Sample, complete bool) (Profile, error) {
	if len(samples) > 64 {
		return Profile{}, errors.New("column sample exceeds row budget")
	}
	p := Profile{Contract: ContractID, Table: meta.Table, Column: meta.Column, Type: meta.Type, Neighbors: append([]string{}, meta.Neighbors...), Numeric: map[string]float64{}, Evidence: Evidence{SamplingStatus: "none", ReviewFlags: []string{}}}
	for _, name := range numericNames {
		p.Numeric[name] = 0
	}
	set := func(name string, yes bool) {
		if yes {
			p.Numeric[name] = 1
		}
	}
	set("nullable", meta.Nullable)
	set("primary_key", meta.PrimaryKey)
	set("foreign_key", meta.ForeignKey)
	set("unique_constraint", meta.Unique)
	flags := map[string]bool{}
	switch strings.ToLower(meta.Type) {
	case "text", "varchar", "character varying", "char", "character", "bpchar", "name":
		set("text_like", true)
	case "int2", "int4", "int8", "smallint", "integer", "bigint", "numeric", "decimal", "float4", "float8", "real", "double precision":
		set("numeric_like", true)
	case "json", "jsonb":
		set("structured_like", true)
		flags["unknown_json_path"] = true
	case "uuid", "bool", "boolean", "date", "timestamp", "timestamptz", "timestamp without time zone", "timestamp with time zone":
	default:
		flags["unsupported_type"] = true
	}
	if !complete || len(samples) == 0 {
		flags["incomplete_sample"] = true
	}
	var lengths []int
	distinct := map[string]bool{}
	counts := map[string]int{}
	nulls, empties, completeValues, nonempty, totalBytes := 0, 0, 0, 0, 0
	for _, sample := range samples {
		if sample.Value == nil {
			if sample.Truncated {
				return Profile{}, errors.New("NULL sample cannot be truncated")
			}
			nulls++
			continue
		}
		v := *sample.Value
		if len(v) > 256 || !utf8.ValidString(v) {
			return Profile{}, errors.New("sample exceeds byte or encoding budget")
		}
		lengths = append(lengths, len(v))
		totalBytes += len(v)
		if len(v) == 0 {
			empties++
		}
		if sample.Truncated {
			flags["truncated_value"] = true
			continue
		}
		completeValues++
		distinct[v] = true
		if len(v) == 0 {
			continue
		}
		nonempty++
		ascii, alpha, whitespace, multiline := true, true, false, false
		for _, b := range []byte(v) {
			ascii = ascii && b < 128
			alpha = alpha && (b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z')
			whitespace = whitespace || strings.ContainsRune(" \t\n\r\v\f", rune(b))
			multiline = multiline || b == '\n' || b == '\r'
		}
		count := func(name string, yes bool) {
			if yes {
				counts[name]++
			}
		}
		count("ascii_fraction", ascii)
		count("alphabetic_fraction", alpha)
		count("numeric_fraction", numberPattern.MatchString(v))
		count("whitespace_fraction", whitespace)
		count("at_sign_fraction", strings.Contains(v, "@"))
		count("multiline_fraction", multiline)
		local, _, hasAt := strings.Cut(v, "@")
		count("email_pattern_fraction", hasAt && emailPattern.MatchString(v) && !strings.HasPrefix(local, ".") && !strings.HasSuffix(local, ".") && !strings.Contains(local, ".."))
		count("phone_pattern_fraction", phone(v))
		count("uuid_pattern_fraction", uuidPattern.MatchString(v))
		_, ipErr := netip.ParseAddr(v)
		count("ip_pattern_fraction", ipErr == nil && !strings.Contains(v, "%"))
		u, urlErr := url.Parse(v)
		count("url_pattern_fraction", urlErr == nil && (u.Scheme == "https" || u.Scheme == "http" || u.Scheme == "ftp") && u.Hostname() != "" && u.User == nil)
		_, dateErr := time.Parse("2006-01-02", v)
		count("iso_date_pattern_fraction", dateErr == nil)
		count("payment_card_pattern_fraction", card(v))
		count("secret_marker_fraction", secretMarker(v))
		count("high_entropy_fraction", highEntropy(v))
		trimmed := strings.TrimSpace(v)
		validJSON := json.Valid([]byte(v))
		count("json_object_fraction", validJSON && strings.HasPrefix(trimmed, "{"))
		count("json_array_fraction", validJSON && strings.HasPrefix(trimmed, "["))
	}
	if len(samples) > 0 {
		p.Numeric["sample_present"] = 1
		p.Evidence.SamplingStatus = "partial"
		if complete {
			p.Evidence.SamplingStatus = "bounded_complete"
		}
		p.Numeric["null_fraction"] = float64(nulls) / float64(len(samples))
	}
	if flags["truncated_value"] {
		p.Evidence.SamplingStatus = "partial"
		flags["incomplete_sample"] = true
	}
	if len(lengths) > 0 {
		p.Numeric["non_null_count_log"] = math.Log1p(float64(len(lengths))) / math.Log1p(64)
		p.Numeric["empty_fraction"] = float64(empties) / float64(len(lengths))
		slices.Sort(lengths)
		lengthLog := func(n float64) float64 { return math.Min(1, math.Log1p(n)/math.Log1p(256)) }
		p.Numeric["mean_length_log"] = lengthLog(float64(totalBytes) / float64(len(lengths)))
		p.Numeric["p95_length_log"] = lengthLog(float64(lengths[int(math.Ceil(0.95*float64(len(lengths))))-1]))
		p.Numeric["max_length_log"] = lengthLog(float64(lengths[len(lengths)-1]))
	}
	if completeValues > 0 {
		p.Numeric["sample_distinct_fraction"] = float64(len(distinct)) / float64(completeValues)
	}
	if nonempty > 0 {
		for name, count := range counts {
			p.Numeric[name] = float64(count) / float64(nonempty)
		}
	}
	for flag := range flags {
		p.Evidence.ReviewFlags = append(p.Evidence.ReviewFlags, flag)
	}
	slices.Sort(p.Evidence.ReviewFlags)
	if err := validate(p); err != nil {
		return Profile{}, err
	}
	return p, nil
}

func phone(v string) bool {
	digits := 0
	for i, b := range []byte(v) {
		if b >= '0' && b <= '9' {
			digits++
			continue
		}
		if b == '+' && i == 0 {
			continue
		}
		if !strings.ContainsRune(" ()-.", rune(b)) {
			return false
		}
	}
	return digits >= 7 && digits <= 15
}
func card(v string) bool {
	var digits []int
	nonzero := false
	for _, b := range []byte(v) {
		if b == ' ' || b == '-' {
			continue
		}
		if b < '0' || b > '9' {
			return false
		}
		digits = append(digits, int(b-'0'))
		nonzero = nonzero || b != '0'
	}
	if len(digits) < 13 || len(digits) > 19 || !nonzero {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := digits[i]
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}
func secretMarker(v string) bool {
	for _, prefix := range []string{"ghp_", "gho_", "github_pat_", "xoxb-", "xoxp-", "Bearer ", "-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"} {
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	return false
}
func highEntropy(v string) bool {
	if len(v) < 20 {
		return false
	}
	var counts [256]int
	for _, b := range []byte(v) {
		counts[b]++
	}
	entropy := float64(0)
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(len(v))
			entropy -= p * math.Log2(p)
		}
	}
	return entropy >= 4
}
