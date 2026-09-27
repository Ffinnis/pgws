package migrations

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed *.sql
var files embed.FS

// Apply serializes migration runners and rejects changes to applied SQL.
func Apply(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(70677783001)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.pgws_migrations (name text PRIMARY KEY, sha256 text NOT NULL)`); err != nil {
		return err
	}
	entries, _ := files.ReadDir(".")
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		sql, _ := files.ReadFile(e.Name())
		hash := fmt.Sprintf("%x", sha256.Sum256(sql))
		var prior string
		err = tx.QueryRow(ctx, `SELECT sha256 FROM public.pgws_migrations WHERE name=$1`, e.Name()).Scan(&prior)
		if err == nil {
			if prior != hash {
				return fmt.Errorf("migration checksum mismatch: %s", e.Name())
			}
			continue
		}
		if err != pgx.ErrNoRows {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %s: %w", e.Name(), err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO public.pgws_migrations VALUES ($1,$2)`, e.Name(), hash); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
