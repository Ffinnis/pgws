// Package privacy compiles explicit policies into immutable deterministic plans.
// It has no raw fallback and does not accept classifier output as authorization.
package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Column struct {
	ID       int16  `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	MaxChars int    `json:"max_chars,omitempty"`
}
type ForeignKey struct {
	Columns           []int16 `json:"columns"`
	Table             uint32  `json:"table"`
	References        []int16 `json:"references"`
	Deferrable        bool    `json:"deferrable,omitempty"`
	InitiallyDeferred bool    `json:"initially_deferred,omitempty"`
}
type Table struct {
	ID          uint32       `json:"id"`
	Schema      string       `json:"schema"`
	Name        string       `json:"name"`
	Columns     []Column     `json:"columns"`
	PrimaryKey  []int16      `json:"primary_key"`
	Unique      [][]int16    `json:"unique,omitempty"`
	ForeignKeys []ForeignKey `json:"foreign_keys,omitempty"`
}
type Schema struct {
	Tables    []Table    `json:"tables"`
	Sequences []Sequence `json:"sequences,omitempty"`
}

// Sequence describes an owned positive, non-cycling identity or serial generator. Its
// source position is deliberately absent: branches use copied-value high water.
type Sequence struct {
	Table     uint32 `json:"table"`
	Column    int16  `json:"column"`
	Schema    string `json:"schema"`
	Name      string `json:"name"`
	Identity  string `json:"identity"`
	Start     int64  `json:"start"`
	Increment int64  `json:"increment"`
	Min       int64  `json:"min"`
	Max       int64  `json:"max"`
}
type Rule struct {
	Table   uint32  `json:"table"`
	Column  int16   `json:"column"`
	Action  string  `json:"action"`
	Domain  string  `json:"domain,omitempty"`
	Fixture *string `json:"fixture,omitempty"`
}
type Policy struct {
	Version    int    `json:"version"`
	SchemaHash string `json:"schema_hash"`
	KeyID      string `json:"key_id"`
	Rules      []Rule `json:"rules"`
}
type field struct {
	table  uint32
	column int16
}
type Compiled struct {
	schema     Schema
	rules      map[field]Rule
	key        [32]byte
	hash       string
	schemaHash string
}

var identifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`)
var domain = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,100}$`)
var uuid = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func canonical(s Schema) Schema {
	// Copy the complete schema so caller mutation cannot change an approved plan.
	b, _ := json.Marshal(s)
	var out Schema
	_ = json.Unmarshal(b, &out)
	slices.SortFunc(out.Tables, func(a, b Table) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for i := range out.Tables {
		slices.SortFunc(out.Tables[i].Columns, func(a, b Column) int { return int(a.ID) - int(b.ID) })
	}
	slices.SortFunc(out.Sequences, func(a, b Sequence) int {
		if a.Table < b.Table {
			return -1
		}
		if a.Table > b.Table {
			return 1
		}
		return int(a.Column) - int(b.Column)
	})
	return out
}
func SchemaHash(s Schema) string {
	b, _ := json.Marshal(canonical(s))
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
func (p *Compiled) Hash() string       { return p.hash }
func (p *Compiled) SchemaHash() string { return p.schemaHash }
func (p *Compiled) Schema() Schema     { return canonical(p.schema) }

func Compile(schema Schema, policy Policy, key []byte) (*Compiled, error) {
	if policy.Version != 1 || !domain.MatchString(policy.KeyID) || len(key) != 32 || len(schema.Tables) == 0 || len(schema.Tables) > 1000 || len(schema.Sequences) > 10000 || len(policy.Rules) > 10000 {
		return nil, errors.New("invalid policy envelope or budget")
	}
	schema = canonical(schema)
	if policy.SchemaHash != SchemaHash(schema) {
		return nil, errors.New("policy schema fingerprint differs")
	}
	p := &Compiled{schema: schema, schemaHash: policy.SchemaHash, rules: map[field]Rule{}}
	copy(p.key[:], key)
	columns := map[field]Column{}
	tables := map[uint32]Table{}
	names := map[string]bool{}
	for _, t := range schema.Tables {
		name := t.Schema + "." + t.Name
		if t.ID == 0 || !identifier.MatchString(t.Schema) || !identifier.MatchString(t.Name) || strings.HasPrefix(t.Schema, "pg_") || t.Schema == "information_schema" || len(t.Columns) == 0 || len(t.Columns) > 1600 || len(t.PrimaryKey) == 0 || tables[t.ID].ID != 0 || names[name] {
			return nil, errors.New("unsupported table identity or missing primary key")
		}
		tables[t.ID] = t
		names[name] = true
		seen := map[string]bool{}
		for _, c := range t.Columns {
			f := field{t.ID, c.ID}
			if c.ID < 1 || !identifier.MatchString(c.Name) || seen[c.Name] || columns[f].ID != 0 || c.MaxChars < 0 || c.MaxChars > 10485760 {
				return nil, errors.New("invalid column identity")
			}
			switch c.Type {
			case "text", "varchar", "uuid", "int2", "int4", "int8", "bool", "jsonb":
			default:
				return nil, errors.New("column type requires a qualified adapter")
			}
			if c.MaxChars != 0 && c.Type != "varchar" {
				return nil, errors.New("length constraint on unsupported type")
			}
			columns[f] = c
			seen[c.Name] = true
		}
	}
	if len(columns) != len(policy.Rules) {
		return nil, errors.New("every included column requires an explicit rule")
	}
	for _, r := range policy.Rules {
		f := field{r.Table, r.Column}
		c, exists := columns[f]
		if !exists || p.rules[f].Action != "" {
			return nil, errors.New("unknown or repeated policy field")
		}
		if r.Fixture != nil {
			value := *r.Fixture
			r.Fixture = &value
		}
		switch r.Action {
		case "copy_original":
			if r.Domain != "" || r.Fixture != nil {
				return nil, errors.New("invalid explicit copy rule")
			}
		case "null":
			if !c.Nullable || r.Domain != "" || r.Fixture != nil {
				return nil, errors.New("invalid null rule")
			}
		case "fixture":
			if r.Fixture == nil || r.Domain != "" || validate(c, *r.Fixture) != nil {
				return nil, errors.New("invalid approved fixture")
			}
		case "keyed_text", "keyed_email", "keyed_uuid":
			if !domain.MatchString(r.Domain) || r.Fixture != nil {
				return nil, errors.New("keyed transform requires an explicit domain")
			}
			if r.Action == "keyed_uuid" {
				if c.Type != "uuid" {
					return nil, errors.New("UUID mapping requires UUID column")
				}
			} else {
				required := 64
				if r.Action == "keyed_email" {
					required += len("@example.invalid")
				}
				if (c.Type != "text" && c.Type != "varchar") || (c.MaxChars != 0 && c.MaxChars < required) {
					return nil, errors.New("keyed output cannot fit the declared column")
				}
			}
		default:
			return nil, errors.New("unknown transformation; raw fallback is forbidden")
		}
		p.rules[f] = r
	}
	sequenceFields := map[field]bool{}
	for _, seq := range schema.Sequences {
		f := field{seq.Table, seq.Column}
		c := columns[f]
		name := seq.Schema + "." + seq.Name
		upper := map[string]int64{"int2": 32767, "int4": 2147483647, "int8": 9223372036854775807}[c.Type]
		if c.ID == 0 || c.Nullable || upper == 0 || sequenceFields[f] || names[name] || seq.Schema != tables[seq.Table].Schema || !identifier.MatchString(seq.Name) || (seq.Identity != "a" && seq.Identity != "d" && seq.Identity != "s") || seq.Min < 1 || seq.Max > upper || seq.Max <= seq.Min || seq.Start < seq.Min || seq.Start > seq.Max || seq.Increment < 1 || p.rules[f].Action != "copy_original" {
			return nil, errors.New("unsupported sequence or unapproved identity mapping")
		}
		sequenceFields[f], names[name] = true, true
	}
	for _, t := range schema.Tables {
		for _, group := range append([][]int16{t.PrimaryKey}, t.Unique...) {
			if len(group) == 0 {
				return nil, errors.New("empty uniqueness key")
			}
			seen := map[int16]bool{}
			for _, id := range group {
				c, exists := columns[field{t.ID, id}]
				r := p.rules[field{t.ID, id}]
				if !exists || seen[id] || (slices.Contains(t.PrimaryKey, id) && c.Nullable) || (r.Action != "copy_original" && !strings.HasPrefix(r.Action, "keyed_")) {
					return nil, errors.New("key transformation does not preserve identity")
				}
				seen[id] = true
			}
		}
		for _, fk := range t.ForeignKeys {
			other, ok := tables[fk.Table]
			if !ok || len(fk.Columns) == 0 || len(fk.Columns) != len(fk.References) || (fk.InitiallyDeferred && !fk.Deferrable) {
				return nil, errors.New("foreign key leaves the approved schema")
			}
			unique := slices.Equal(fk.References, other.PrimaryKey)
			for _, u := range other.Unique {
				unique = unique || slices.Equal(fk.References, u)
			}
			if !unique {
				return nil, errors.New("foreign key lacks a unique target")
			}
			for i, id := range fk.Columns {
				a, b := field{t.ID, id}, field{fk.Table, fk.References[i]}
				ra, rb := p.rules[a], p.rules[b]
				if columns[a].ID == 0 || columns[b].ID == 0 || columns[a].Type != columns[b].Type || ra.Action != rb.Action || ra.Domain != rb.Domain {
					return nil, errors.New("related fields have incompatible transformation domains")
				}
			}
		}
	}
	rules := make([]Rule, 0, len(p.rules))
	for _, r := range p.rules {
		rules = append(rules, r)
	}
	slices.SortFunc(rules, func(a, b Rule) int {
		if a.Table < b.Table {
			return -1
		}
		if a.Table > b.Table {
			return 1
		}
		return int(a.Column) - int(b.Column)
	})
	policy.Rules = rules
	b, _ := json.Marshal(struct {
		Policy         Policy
		KeyFingerprint [32]byte
	}{policy, sha256.Sum256(key)})
	p.hash = fmt.Sprintf("%x", sha256.Sum256(b))
	return p, nil
}

// Transform accepts PostgreSQL text-format scalar values. nil means SQL NULL.
// It returns no partial row when a field, value or policy validation fails.
func (p *Compiled) Transform(tableID uint32, row map[string]*string) (map[string]*string, error) {
	return p.transform(tableID, row, true)
}

// TransformPartial preserves omitted UPDATE fields, including unchanged TOAST.
// Only supplied, approved columns are transformed; omitted values are never raw.
func (p *Compiled) TransformPartial(tableID uint32, row map[string]*string) (map[string]*string, error) {
	return p.transform(tableID, row, false)
}
func (p *Compiled) transform(tableID uint32, row map[string]*string, complete bool) (map[string]*string, error) {
	var table *Table
	for i := range p.schema.Tables {
		if p.schema.Tables[i].ID == tableID {
			table = &p.schema.Tables[i]
			break
		}
	}
	if table == nil || (complete && len(row) != len(table.Columns)) {
		return nil, errors.New("row differs from approved schema")
	}
	out := map[string]*string{}
	for _, c := range table.Columns {
		value, exists := row[c.Name]
		if !exists {
			if complete {
				return nil, errors.New("row is missing an approved field")
			}
			continue
		}
		if value == nil {
			if !c.Nullable {
				return nil, errors.New("NULL in a required field")
			}
			out[c.Name] = nil
			continue
		}
		if validate(c, *value) != nil {
			return nil, errors.New("source value violates declared type or limit")
		}
		r := p.rules[field{tableID, c.ID}]
		var transformed string
		switch r.Action {
		case "copy_original":
			transformed = *value
		case "null":
			out[c.Name] = nil
			continue
		case "fixture":
			transformed = *r.Fixture
		default:
			h := hmac.New(sha256.New, p.key[:])
			b, _ := json.Marshal([]string{"pgws-transform-v1", r.Domain, c.Type, *value})
			_, _ = h.Write(b)
			sum := h.Sum(nil)
			transformed = hex.EncodeToString(sum)
			if r.Action == "keyed_email" {
				transformed += "@example.invalid"
			}
			if r.Action == "keyed_uuid" {
				sum[6] = sum[6]&15 | 128
				sum[8] = sum[8]&63 | 128
				transformed = fmt.Sprintf("%x-%x-%x-%x-%x", sum[:4], sum[4:6], sum[6:8], sum[8:10], sum[10:16])
			}
		}
		out[c.Name] = &transformed
	}
	if len(out) != len(row) {
		return nil, errors.New("row contains an unknown field")
	}
	return out, nil
}
func validate(c Column, value string) error {
	if len(value) > 1<<20 || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || (c.MaxChars != 0 && utf8.RuneCountInString(value) > c.MaxChars) {
		return errors.New("invalid field encoding or size")
	}
	switch c.Type {
	case "uuid":
		if !uuid.MatchString(value) {
			return errors.New("noncanonical UUID")
		}
	case "int2", "int4", "int8":
		bits := map[string]int{"int2": 16, "int4": 32, "int8": 64}[c.Type]
		n, err := strconv.ParseInt(value, 10, bits)
		if err != nil || strconv.FormatInt(n, 10) != value {
			return errors.New("noncanonical integer")
		}
	case "bool":
		if value != "t" && value != "f" {
			return errors.New("noncanonical boolean")
		}
	case "jsonb":
		if !json.Valid([]byte(value)) {
			return errors.New("invalid JSON")
		}
	}
	return nil
}

// CopiesOriginal exposes only the compiled action, not keys or fixture values.
func (p *Compiled) CopiesOriginal(table uint32, column int16) bool {
	if p == nil {
		return false
	}
	return p.rules[field{table, column}].Action == "copy_original"
}
