package logical

import (
	"errors"
	"slices"

	"github.com/jackc/pglogrepl"
	"pgws/internal/privacy"
)

// Decoder accepts pgoutput v1 text tuples without streaming or two-phase mode.
// It releases a complete source transaction only after its matching COMMIT.
type Decoder struct {
	tables  map[uint32]privacy.Table
	known   map[uint32]bool
	last    pglogrepl.LSN
	final   pglogrepl.LSN
	pending *Transaction
	bytes   int
	failed  bool
}

func NewDecoder(plan *privacy.Compiled, appliedLSN string) (*Decoder, error) {
	if plan == nil {
		return nil, errors.New("logical plan required")
	}
	last, err := pglogrepl.ParseLSN(appliedLSN)
	if err != nil {
		return nil, errors.New("invalid applied position")
	}
	d := &Decoder{tables: map[uint32]privacy.Table{}, known: map[uint32]bool{}, last: last}
	for _, table := range plan.Schema().Tables {
		d.tables[table.ID] = table
	}
	return d, nil
}

var typeOIDs = map[string]uint32{"bool": 16, "int8": 20, "int2": 21, "int4": 23, "text": 25, "varchar": 1043, "uuid": 2950, "jsonb": 3802}

func (d *Decoder) Decode(raw []byte) (result *Transaction, err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("malformed logical message")
		}
		if err != nil {
			d.failed = true
			d.pending = nil
			result = nil
		}
	}()
	if d.failed {
		return nil, errors.New("decoder stopped at an invalid source boundary")
	}
	if err = validateFrame(raw); err != nil {
		return nil, err
	}
	message, err := pglogrepl.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid logical message")
	}
	d.bytes += len(raw)
	if d.bytes > 16<<20 {
		return nil, errors.New("logical transaction exceeds memory budget")
	}
	switch m := message.(type) {
	case *pglogrepl.BeginMessage:
		if d.pending != nil || m.FinalLSN <= d.last || m.Xid == 0 {
			return nil, errors.New("invalid source transaction begin")
		}
		d.final = m.FinalLSN
		d.pending = &Transaction{PreviousLSN: d.last.String()}
	case *pglogrepl.RelationMessage:
		t, ok := d.tables[m.RelationID]
		if !ok || m.Namespace != t.Schema || m.RelationName != t.Name || m.ReplicaIdentity != 'd' || len(m.Columns) != len(t.Columns) {
			return nil, errors.New("source relation differs from approved schema")
		}
		for i, c := range t.Columns {
			actual := m.Columns[i]
			typmod := int32(-1)
			if c.Type == "varchar" && c.MaxChars > 0 {
				typmod = int32(c.MaxChars + 4)
			}
			key := uint8(0)
			if slices.Contains(t.PrimaryKey, c.ID) {
				key = 1
			}
			if actual.Name != c.Name || actual.DataType != typeOIDs[c.Type] || actual.TypeModifier != typmod || actual.Flags != key {
				return nil, errors.New("source column type, name or key changed")
			}
		}
		d.known[m.RelationID] = true
	case *pglogrepl.InsertMessage:
		row, e := d.tuple(m.RelationID, m.Tuple, false)
		if e != nil {
			return nil, e
		}
		err = d.add(Change{Table: m.RelationID, Kind: "insert", Row: row})
	case *pglogrepl.UpdateMessage:
		row, e := d.tuple(m.RelationID, m.NewTuple, true)
		if e != nil {
			return nil, e
		}
		old := row
		if m.OldTuple != nil {
			old, e = d.tuple(m.RelationID, m.OldTuple, true)
			if e != nil {
				return nil, e
			}
		}
		keys, e := d.keys(m.RelationID, old)
		if e != nil {
			return nil, e
		}
		err = d.add(Change{Table: m.RelationID, Kind: "update", Row: row, OldKey: keys})
	case *pglogrepl.DeleteMessage:
		row, e := d.tuple(m.RelationID, m.OldTuple, true)
		if e != nil {
			return nil, e
		}
		keys, e := d.keys(m.RelationID, row)
		if e != nil {
			return nil, e
		}
		err = d.add(Change{Table: m.RelationID, Kind: "delete", OldKey: keys})
	case *pglogrepl.CommitMessage:
		if d.pending == nil || m.Flags != 0 || m.CommitLSN != d.final || m.TransactionEndLSN <= m.CommitLSN {
			return nil, errors.New("source commit boundary differs")
		}
		d.pending.EndLSN = m.TransactionEndLSN.String()
		result = d.pending
		d.pending = nil
		d.last = m.TransactionEndLSN
		d.bytes = 0
	default:
		return nil, errors.New("logical message requires an unsupported adapter")
	}
	return result, err
}
func (d *Decoder) add(c Change) error {
	if d.pending == nil || len(d.pending.Changes) >= 10000 {
		return errors.New("row outside a bounded source transaction")
	}
	d.pending.Changes = append(d.pending.Changes, c)
	return nil
}
func (d *Decoder) tuple(id uint32, tuple *pglogrepl.TupleData, partial bool) (map[string]*string, error) {
	t, ok := d.tables[id]
	if !ok || !d.known[id] || tuple == nil || len(tuple.Columns) != len(t.Columns) {
		return nil, errors.New("tuple has no matching approved relation")
	}
	row := map[string]*string{}
	for i, c := range tuple.Columns {
		switch c.DataType {
		case pglogrepl.TupleDataTypeNull:
			row[t.Columns[i].Name] = nil
		case pglogrepl.TupleDataTypeToast:
			if !partial {
				return nil, errors.New("insert contains an unavailable TOAST value")
			}
		case pglogrepl.TupleDataTypeText:
			value := string(c.Data)
			row[t.Columns[i].Name] = &value
		default:
			return nil, errors.New("unsupported tuple encoding")
		}
	}
	return row, nil
}
func (d *Decoder) keys(id uint32, row map[string]*string) (map[string]*string, error) {
	key := map[string]*string{}
	for _, name := range columnNames(d.tables[id], d.tables[id].PrimaryKey) {
		if row[name] == nil {
			return nil, errors.New("stable source key is absent")
		}
		key[name] = row[name]
	}
	return key, nil
}
