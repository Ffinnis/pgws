package discover

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type column struct {
	Number                                                 int16
	Name, Type                                             string
	OID                                                    uint32
	Modifier                                               int
	Builtin, Nullable, Primary, Foreign, Unique, Generated bool
}
type relation struct {
	ID       uint32
	Estimate float64
	Columns  []column
}

func catalog(ctx context.Context, tx pgx.Tx, schema, table string) (relation, error) {
	var result relation
	rows, err := tx.Query(ctx, `SELECT c.oid,c.reltuples::float8,a.attnum,a.attname,t.typname,t.oid,a.atttypmod,
 tn.nspname='pg_catalog',NOT a.attnotnull,a.attgenerated<>'',
 EXISTS(SELECT FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype='p' AND a.attnum=ANY(k.conkey)),
 EXISTS(SELECT FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype='f' AND a.attnum=ANY(k.conkey)),
 EXISTS(SELECT FROM pg_constraint k WHERE k.conrelid=c.oid AND k.contype IN ('p','u') AND k.conkey=ARRAY[a.attnum]),
 c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
 AND NOT EXISTS(SELECT FROM pg_inherits i WHERE i.inhrelid=c.oid OR i.inhparent=c.oid)
 AND NOT pg_has_role(current_user,c.relowner,'USAGE')
 AND NOT has_table_privilege(c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
 AND NOT has_column_privilege(c.oid,a.attnum,'INSERT,UPDATE,REFERENCES')
 AND has_column_privilege(c.oid,a.attnum,'SELECT')
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
 JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace
 WHERE n.nspname=$1 AND c.relname=$2 ORDER BY a.attnum LIMIT 65`, schema, table)
	if err != nil {
		return result, errors.New("discovery catalog unavailable")
	}
	defer rows.Close()
	for rows.Next() {
		var c column
		var safe bool
		if err = rows.Scan(&result.ID, &result.Estimate, &c.Number, &c.Name, &c.Type, &c.OID, &c.Modifier, &c.Builtin, &c.Nullable, &c.Generated, &c.Primary, &c.Foreign, &c.Unique, &safe); err != nil || !safe || !identifier(c.Name) || !identifier(c.Type) {
			return relation{}, errors.New("discovery relation or metadata requires private review")
		}
		result.Columns = append(result.Columns, c)
	}
	if rows.Err() != nil || len(result.Columns) == 0 || len(result.Columns) > MaxColumns {
		return relation{}, errors.New("discovery catalog exceeds supported scope")
	}
	return result, nil
}

// Only built-in, non-generated values with bounded logical size can be read.
// In UTF8, VARCHAR/CHAR(64) occupies at most 256 bytes before compression.
// Opaque, unlimited varlena, domains, arrays and custom output functions never
// enter the SELECT list. No substring of an unbounded TOAST value is attempted.
func bounded(c column) bool {
	if !c.Builtin || c.Generated {
		return false
	}
	switch c.OID {
	case 16, 20, 21, 23, 700, 701, 1082, 1114, 1184, 2950:
		return c.Modifier == -1 || (c.OID == 1114 || c.OID == 1184) && c.Modifier >= 0 && c.Modifier <= 6
	case 1042, 1043:
		return c.Modifier >= 5 && c.Modifier <= 68
	default:
		return false
	}
}
