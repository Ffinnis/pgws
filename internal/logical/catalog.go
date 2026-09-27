package logical

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"pgws/internal/privacy"
)

// ReadCatalog runs inside the caller's consistent source transaction. The first
// adapter includes every application table and rejects unsupported objects;
// omitted relations are not silently treated as an approved exclusion policy.
func ReadCatalog(ctx context.Context, tx pgx.Tx) (privacy.Schema, error) {
	var schema privacy.Schema
	if _, err := tx.Exec(ctx, "SET LOCAL search_path=pg_catalog"); err != nil {
		return schema, errors.New("source catalog session could not be isolated")
	}
	var supported bool
	err := tx.QueryRow(ctx, `SELECT current_setting('server_version_num')::int / 10000 = 18
 AND current_setting('server_encoding')='UTF8'
 AND NOT pg_is_in_recovery()
 AND current_setting('wal_level')='logical'
 AND current_setting('max_prepared_transactions')::int=0
 AND EXISTS(SELECT FROM pg_database WHERE datname=current_database() AND datlocprovider='c' AND datcollate IN ('C','C.UTF-8','C.utf8','POSIX') AND datctype IN ('C','C.UTF-8','C.utf8','POSIX'))
 AND NOT EXISTS(SELECT FROM pg_largeobject_metadata)
 AND NOT EXISTS(SELECT FROM pg_subscription)
 AND NOT EXISTS(SELECT FROM pg_foreign_server)
 AND NOT EXISTS(SELECT FROM pg_inherits)
 AND NOT EXISTS(SELECT FROM pg_extension WHERE extname<>'plpgsql')
 AND NOT EXISTS(SELECT FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema' AND
   (c.relkind NOT IN ('r','i','S') OR c.relpersistence<>'p' OR c.relrowsecurity OR c.relforcerowsecurity OR (c.relkind='r' AND c.relreplident<>'d')))
 AND NOT EXISTS(SELECT FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema' AND NOT t.tgisinternal)
 AND NOT EXISTS(SELECT FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema')`).Scan(&supported)
	if err != nil || !supported {
		return schema, errors.New("source is outside the qualified logical object and locale matrix")
	}
	rows, err := tx.Query(ctx, `SELECT c.oid,n.nspname,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname!~'^pg_' AND n.nspname<>'information_schema' AND c.relkind='r' ORDER BY c.oid LIMIT 1001`)
	if err != nil {
		return schema, errors.New("source table inventory unavailable")
	}
	for rows.Next() {
		var table privacy.Table
		if err = rows.Scan(&table.ID, &table.Schema, &table.Name); err != nil {
			break
		}
		schema.Tables = append(schema.Tables, table)
	}
	rows.Close()
	if err != nil || rows.Err() != nil || len(schema.Tables) == 0 || len(schema.Tables) > 1000 {
		return privacy.Schema{}, errors.New("source table inventory exceeds the supported budget")
	}
	for i := range schema.Tables {
		t := &schema.Tables[i]
		if err = readColumns(ctx, tx, t); err != nil {
			return privacy.Schema{}, err
		}
		if err = readKeys(ctx, tx, t); err != nil {
			return privacy.Schema{}, err
		}
	}
	if err = readSequences(ctx, tx, &schema); err != nil {
		return privacy.Schema{}, err
	}
	return schema, nil
}

func readColumns(ctx context.Context, tx pgx.Tx, table *privacy.Table) error {
	rows, err := tx.Query(ctx, `SELECT a.attnum,a.attname,t.typname,NOT a.attnotnull,a.atttypmod,
 n.nspname='pg_catalog' AND a.attgenerated='' AND a.attidentity IN ('','a','d') AND NOT a.attisdropped
 AND (NOT a.atthasdef OR (a.attidentity='' AND EXISTS(
 SELECT FROM pg_attrdef ad JOIN pg_depend d ON d.refclassid='pg_class'::regclass AND d.refobjid=a.attrelid AND d.refobjsubid=a.attnum AND d.classid='pg_class'::regclass AND d.objsubid=0 AND d.deptype='a'
 JOIN pg_sequence s ON s.seqrelid=d.objid WHERE ad.adrelid=a.attrelid AND ad.adnum=a.attnum AND pg_get_expr(ad.adbin,ad.adrelid)=format('nextval(%L::regclass)',s.seqrelid::regclass::text))))
 AND (a.attcollation=0 OR a.attcollation=(SELECT oid FROM pg_collation WHERE collname='default' AND collnamespace='pg_catalog'::regnamespace))
 FROM pg_attribute a LEFT JOIN pg_type t ON t.oid=a.atttypid LEFT JOIN pg_namespace n ON n.oid=t.typnamespace
 WHERE a.attrelid=$1 AND a.attnum>0 ORDER BY a.attnum LIMIT 1601`, table.ID)
	if err != nil {
		return errors.New("source field inventory unavailable")
	}
	defer rows.Close()
	for rows.Next() {
		var c privacy.Column
		var typmod int
		var supported bool
		if err = rows.Scan(&c.ID, &c.Name, &c.Type, &c.Nullable, &typmod, &supported); err != nil || !supported || typeOIDs[c.Type] == 0 {
			return errors.New("source field requires an unsupported schema adapter")
		}
		if c.Type == "varchar" && typmod >= 5 {
			c.MaxChars = typmod - 4
		} else if typmod != -1 {
			return errors.New("unsupported source type modifier")
		}
		table.Columns = append(table.Columns, c)
	}
	if rows.Err() != nil || len(table.Columns) == 0 || len(table.Columns) > 1600 {
		return errors.New("source field inventory exceeds the supported budget")
	}
	return nil
}

func readKeys(ctx context.Context, tx pgx.Tx, table *privacy.Table) error {
	// A standalone, partial, expression or NULLS NOT DISTINCT unique index has
	// semantics the initial target builder cannot reproduce. Refuse it explicitly.
	var supported bool
	err := tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM pg_index i WHERE i.indrelid=$1 AND
 (NOT i.indisvalid OR NOT i.indisready OR i.indnullsnotdistinct OR (i.indisunique AND
 (i.indexprs IS NOT NULL OR i.indpred IS NOT NULL OR NOT EXISTS(SELECT FROM pg_constraint c WHERE c.conindid=i.indexrelid AND c.contype IN ('p','u'))))))`, table.ID).Scan(&supported)
	if err != nil || !supported {
		return errors.New("source index requires an unsupported identity adapter")
	}
	rows, err := tx.Query(ctx, `SELECT contype::text,conkey,confrelid,confkey,condeferrable,condeferred,convalidated AND coalesce((to_jsonb(pg_constraint)->>'conenforced')::boolean,true)
 AND (contype<>'f' OR (confupdtype='a' AND confdeltype='a' AND confmatchtype='s')) AND (contype NOT IN ('p','u') OR NOT condeferrable)
 FROM pg_constraint WHERE conrelid=$1 ORDER BY contype,conkey,confrelid,confkey LIMIT 1001`, table.ID)
	if err != nil {
		return errors.New("source relationship inventory unavailable")
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var kind string
		var key, references []int16
		var other uint32
		var deferrable, deferred bool
		if err = rows.Scan(&kind, &key, &other, &references, &deferrable, &deferred, &supported); err != nil || !supported {
			return errors.New("source constraint is not qualified")
		}
		count++
		switch kind {
		case "n":
			// Column nullability is already represented by attnotnull.
		case "p":
			table.PrimaryKey = key
		case "u":
			table.Unique = append(table.Unique, key)
		case "f":
			table.ForeignKeys = append(table.ForeignKeys, privacy.ForeignKey{Columns: key, Table: other, References: references, Deferrable: deferrable, InitiallyDeferred: deferred})
		default:
			return errors.New("source constraint requires an unsupported adapter")
		}
	}
	if rows.Err() != nil || count > 1000 || len(table.PrimaryKey) == 0 {
		return errors.New("source relationships exceed the budget or lack a stable identity")
	}
	return nil
}
