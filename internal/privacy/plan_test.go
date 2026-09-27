package privacy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func value(s string) *string { return &s }
func example() (Schema, Policy) {
	s := Schema{Tables: []Table{
		{ID: 1, Schema: "public", Name: "people", Columns: []Column{{ID: 1, Name: "id", Type: "uuid"}, {ID: 2, Name: "email", Type: "text"}, {ID: 3, Name: "bio", Type: "text", Nullable: true}}, PrimaryKey: []int16{1}, Unique: [][]int16{{2}}},
		{ID: 2, Schema: "public", Name: "orders", Columns: []Column{{ID: 1, Name: "id", Type: "int8"}, {ID: 2, Name: "person_id", Type: "uuid"}}, PrimaryKey: []int16{1}, ForeignKeys: []ForeignKey{{Columns: []int16{2}, Table: 1, References: []int16{1}}}},
	}}
	p := Policy{Version: 1, SchemaHash: SchemaHash(s), KeyID: "test-key-v1", Rules: []Rule{
		{Table: 1, Column: 1, Action: "keyed_uuid", Domain: "person"}, {Table: 1, Column: 2, Action: "keyed_email", Domain: "email"}, {Table: 1, Column: 3, Action: "fixture", Fixture: value("Example biography")},
		{Table: 2, Column: 1, Action: "copy_original"}, {Table: 2, Column: 2, Action: "keyed_uuid", Domain: "person"},
	}}
	return s, p
}
func TestRelatedMappingsAreStableAndPlanIsImmutable(t *testing.T) {
	s, p := example()
	key := bytes.Repeat([]byte{9}, 32)
	c, err := Compile(s, p, key)
	if err != nil {
		t.Fatal(err)
	}
	row := map[string]*string{"id": value("10000000-0000-4000-8000-000000000001"), "email": value("private@example.org"), "bio": value("source secret")}
	a, err := c.Transform(1, row)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Transform(2, map[string]*string{"id": value("1"), "person_id": row["id"]})
	if err != nil {
		t.Fatal(err)
	}
	if *a["id"] != *b["person_id"] || *a["id"] == *row["id"] || !strings.HasSuffix(*a["email"], "@example.invalid") || *a["bio"] != "Example biography" {
		t.Fatal("mapping contract failed")
	}
	copyPlan, err := Compile(s, p, key)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := copyPlan.Transform(1, row)
	if *again["email"] != *a["email"] || copyPlan.Hash() != c.Hash() {
		t.Fatal("restart changed mapping")
	}
	p.Rules[2].Fixture = value("changed")
	s.Tables[0].Columns[0].Name = "changed"
	key[0]++
	again, _ = c.Transform(1, row)
	if *again["bio"] != *a["bio"] {
		t.Fatal("caller mutated compiled policy")
	}
	encoded, _ := json.Marshal(c)
	if string(encoded) != "{}" {
		t.Fatal("compiled plan exposes private internals")
	}
}
func TestPolicyRejectsGapsDriftAndBrokenDomains(t *testing.T) {
	for _, kind := range []string{"gap", "drift", "domain", "action", "key_fixture", "length", "extra", "unsafe_schema"} {
		t.Run(kind, func(t *testing.T) {
			s, p := example()
			switch kind {
			case "gap":
				p.Rules = p.Rules[1:]
			case "drift":
				s.Tables[0].Columns = append(s.Tables[0].Columns, Column{ID: 4, Name: "new_secret", Type: "text"})
			case "domain":
				p.Rules[4].Domain = "another-person"
			case "action":
				p.Rules[2].Action = "model_says_safe"
			case "key_fixture":
				p.Rules[0] = Rule{Table: 1, Column: 1, Action: "fixture", Fixture: value("10000000-0000-4000-8000-000000000001")}
			case "length":
				s.Tables[0].Columns[1].Type = "varchar"
				s.Tables[0].Columns[1].MaxChars = 20
				p.SchemaHash = SchemaHash(s)
			case "extra":
				p.Rules = append(p.Rules, p.Rules[0])
			case "unsafe_schema":
				s.Tables[0].Schema = "pg_catalog"
				p.SchemaHash = SchemaHash(s)
			}
			if _, err := Compile(s, p, bytes.Repeat([]byte{1}, 32)); err == nil {
				t.Fatal("unsafe policy accepted")
			}
		})
	}
}
func TestRowRejectsUnknownAndMalformedValuesWithoutLeakingThem(t *testing.T) {
	s, p := example()
	c, err := Compile(s, p, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []map[string]*string{{"id": value("secret")}, {"id": value("1"), "person_id": value("secret")}, {"id": value("1"), "person_id": nil}, {"id": value("01"), "person_id": value("10000000-0000-4000-8000-000000000001")}} {
		out, err := c.Transform(2, row)
		if err == nil || out != nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("bad row was accepted or leaked")
		}
	}
}

func TestSequencePlanBinding(t *testing.T) {
	s, p := example()
	s.Sequences = []Sequence{{Table: 2, Column: 1, Schema: "public", Name: "order_ids", Identity: "a", Start: 7, Increment: 5, Min: 1, Max: 1000}}
	p.SchemaHash = SchemaHash(s)
	plan, err := Compile(s, p, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unknown", "text", "descending", "bounds", "duplicate", "cross_schema", "name", "identity", "fixture"} {
		t.Run(kind, func(t *testing.T) {
			changed := plan.Schema()
			policy := p
			policy.Rules = append([]Rule(nil), p.Rules...)
			switch kind {
			case "unknown":
				changed.Sequences[0].Column = 100
			case "text":
				changed.Sequences[0].Table = 1
				changed.Sequences[0].Column = 2
			case "descending":
				changed.Sequences[0].Increment = -1
			case "bounds":
				changed.Sequences[0].Min = 0
			case "duplicate":
				changed.Sequences = append(changed.Sequences, changed.Sequences[0])
			case "cross_schema":
				changed.Sequences[0].Schema = "other"
			case "name":
				changed.Sequences[0].Name = "people"
			case "identity":
				changed.Sequences[0].Identity = "unapproved"
			case "fixture":
				policy.Rules[3] = Rule{Table: 2, Column: 1, Action: "fixture", Fixture: value("9")}
			}
			policy.SchemaHash = SchemaHash(changed)
			if _, err := Compile(changed, policy, bytes.Repeat([]byte{7}, 32)); err == nil {
				t.Fatal("unsafe sequence accepted")
			}
		})
	}
	s.Sequences[0].Increment++
	if plan.Schema().Sequences[0].Increment != 5 || SchemaHash(s) == plan.SchemaHash() {
		t.Fatal("sequence drift or caller mutation missed")
	}
}
