package logical

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"pgws/internal/privacy"
)

func readSequences(ctx context.Context, tx pgx.Tx, schema *privacy.Schema) error {
	rows, err := tx.Query(ctx, `SELECT coalesce(d.refobjid,0),coalesce(d.refobjsubid,0)::smallint,n.nspname,c.relname,
 coalesce(nullif(a.attidentity::text,''),'s'),s.seqstart,s.seqincrement,s.seqmin,s.seqmax,
 coalesce(((d.deptype='i' AND a.attidentity IN ('a','d')) OR
 (d.deptype='a' AND a.attidentity='' AND EXISTS(SELECT FROM pg_attrdef ad WHERE ad.adrelid=a.attrelid AND ad.adnum=a.attnum AND pg_get_expr(ad.adbin,ad.adrelid)=format('nextval(%L::regclass)',s.seqrelid::regclass::text))))
 AND a.atttypid=s.seqtypid AND NOT s.seqcycle AND s.seqincrement>0 AND s.seqmin>0,false)
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_sequence s ON s.seqrelid=c.oid
 LEFT JOIN pg_depend d ON d.classid='pg_class'::regclass AND d.objid=c.oid AND d.objsubid=0 AND d.refclassid='pg_class'::regclass AND d.deptype IN ('a','i')
 LEFT JOIN pg_attribute a ON a.attrelid=d.refobjid AND a.attnum=d.refobjsubid
 WHERE c.relkind='S' AND n.nspname!~'^pg_' AND n.nspname<>'information_schema' ORDER BY c.oid LIMIT 10001`)
	if err != nil {
		return errors.New("source sequence inventory unavailable")
	}
	for rows.Next() {
		var s privacy.Sequence
		var valid bool
		if err = rows.Scan(&s.Table, &s.Column, &s.Schema, &s.Name, &s.Identity, &s.Start, &s.Increment, &s.Min, &s.Max, &valid); err != nil || !valid {
			rows.Close()
			return errors.New("source sequence requires a qualified identity adapter")
		}
		schema.Sequences = append(schema.Sequences, s)
	}
	rows.Close()
	if rows.Err() != nil || len(schema.Sequences) > 10000 {
		return errors.New("source sequence inventory exceeds budget")
	}
	var count int
	err = tx.QueryRow(ctx, `SELECT count(*) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema' AND (a.attidentity<>'' OR a.atthasdef)`).Scan(&count)
	if err != nil || count != len(schema.Sequences) {
		return errors.New("source identity ownership is incomplete")
	}
	return nil
}

// nextSequenceValue does not add before checking the remaining range. A source
// value may have been explicitly inserted outside the generator's bounds.
func nextSequenceValue(s privacy.Sequence, high int64) (int64, error) {
	if s.Min < 1 || s.Start < s.Min || s.Start > s.Max || s.Increment < 1 {
		return 0, errors.New("invalid sequence bounds")
	}
	if high < s.Start {
		return s.Start, nil
	}
	if high >= s.Max {
		return 0, errors.New("copied identity has exhausted its sequence")
	}
	steps := (high-s.Start)/s.Increment + 1
	if steps > (s.Max-s.Start)/s.Increment {
		return 0, errors.New("copied identity has exhausted its sequence")
	}
	return s.Start + steps*s.Increment, nil
}

// High water is ordinary transactional data, never setval, so failed apply and
// seed transactions roll it back together with rows and the source checkpoint.
func advanceSequences(ctx context.Context, tx pgx.Tx, table privacy.Table, sequences []privacy.Sequence, row map[string]*string) error {
	for _, s := range sequences {
		if s.Table != table.ID {
			continue
		}
		name := columnNames(table, []int16{s.Column})[0]
		v := row[name]
		if v == nil {
			continue
		}
		value, err := strconv.ParseInt(*v, 10, 64)
		if err != nil {
			return errors.New("identity high water is not an integer")
		}
		result, err := tx.Exec(ctx, `UPDATE _pgws_ingestion.sequence_watermarks SET high_water=greatest(high_water,$3::bigint) WHERE source_table=$1 AND source_column=$2`, s.Table, s.Column, value)
		if err != nil || result.RowsAffected() != 1 {
			return errors.New("identity high water could not be persisted")
		}
	}
	return nil
}

func (t Target) prepareSequences(ctx context.Context, tx pgx.Tx) error {
	schema := t.Plan.Schema()
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM _pgws_ingestion.sequence_watermarks`).Scan(&count); err != nil || count != len(schema.Sequences) {
		return errors.New("identity high water inventory differs from the plan")
	}
	for _, s := range schema.Sequences {
		var table privacy.Table
		for _, candidate := range schema.Tables {
			if candidate.ID == s.Table {
				table = candidate
				break
			}
		}
		column := pgx.Identifier{columnNames(table, []int16{s.Column})[0]}.Sanitize()
		var high int64
		// Include actual copied rows as a second check before exposure. Never
		// lower the journal high water when the largest row has been deleted.
		q := `SELECT greatest(high_water,coalesce((SELECT max(` + column + `) FROM ` + qualified(table) + `),0)) FROM _pgws_ingestion.sequence_watermarks WHERE source_table=$1 AND source_column=$2 FOR UPDATE`
		if err := tx.QueryRow(ctx, q, s.Table, s.Column).Scan(&high); err != nil {
			return errors.New("recovered identity high water unavailable")
		}
		next, err := nextSequenceValue(s, high)
		if err != nil {
			return err
		}
		mode := "BY DEFAULT"
		if s.Identity == "a" {
			mode = "ALWAYS"
		}
		if s.Identity == "s" {
			sequence := pgx.Identifier{s.Schema, s.Name}.Sanitize()
			var typ string
			for _, c := range table.Columns {
				if c.ID == s.Column {
					typ = c.Type
					break
				}
			}
			q = fmt.Sprintf("CREATE SEQUENCE %s AS %s START WITH %d INCREMENT BY %d MINVALUE %d MAXVALUE %d NO CYCLE CACHE 1 OWNED BY %s.%s", sequence, typ, s.Start, s.Increment, s.Min, s.Max, qualified(table), column)
			if _, err = tx.Exec(ctx, q); err != nil {
				return errors.New("clone serial generator creation failed")
			}
			q = fmt.Sprintf("ALTER SEQUENCE %s RESTART WITH %d", sequence, next)
			if _, err = tx.Exec(ctx, q); err != nil {
				return errors.New("clone serial initialization failed")
			}
			q = fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s SET DEFAULT pg_catalog.nextval('%s'::regclass)", qualified(table), column, strings.ReplaceAll(sequence, "'", "''"))
			if _, err = tx.Exec(ctx, q); err != nil {
				return errors.New("clone serial default installation failed")
			}
			continue
		}
		q = fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s ADD GENERATED %s AS IDENTITY (SEQUENCE NAME %s START WITH %d INCREMENT BY %d MINVALUE %d MAXVALUE %d NO CYCLE CACHE 1)", qualified(table), column, mode, pgx.Identifier{s.Schema, s.Name}.Sanitize(), s.Start, s.Increment, s.Min, s.Max)
		if _, err = tx.Exec(ctx, q); err != nil {
			return errors.New("clone identity generator creation failed")
		}
		q = fmt.Sprintf("ALTER TABLE %s ALTER COLUMN %s RESTART WITH %d", qualified(table), column, next)
		if _, err = tx.Exec(ctx, q); err != nil {
			return errors.New("clone identity initialization failed")
		}
	}
	return nil
}
