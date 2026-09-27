package discover

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"pgws/internal/privacy/features"
)

func sample(ctx context.Context, tx pgx.Tx, table string, columns []column, selected []int, rate float64) ([][]features.Sample, int, int, error) {
	values := make([][]features.Sample, len(columns))
	fields := make([]string, len(selected))
	for i, index := range selected {
		fields[i] = pgx.Identifier{columns[index].Name}.Sanitize() + "::pg_catalog.text"
	}
	rows, err := tx.Query(ctx, "SELECT "+strings.Join(fields, ",")+" FROM ONLY "+table+" TABLESAMPLE SYSTEM ($1) LIMIT 64", rate)
	if err != nil {
		return nil, 0, 0, errors.New("sample unavailable")
	}
	defer rows.Close()
	count, bytes := 0, 0
	for rows.Next() {
		count++
		if count > MaxRows {
			return nil, 0, 0, errors.New("sample row limit")
		}
		row := make([]*string, len(selected))
		dest := make([]any, len(selected))
		for i := range dest {
			dest[i] = &row[i]
		}
		if rows.Scan(dest...) != nil {
			return nil, 0, 0, errors.New("sample decoding failed")
		}
		for i, value := range row {
			if value != nil {
				if len(*value) > 256 || !utf8.ValidString(*value) {
					return nil, 0, 0, errors.New("sample value budget")
				}
				bytes += len(*value)
				if bytes > MaxBytes {
					return nil, 0, 0, errors.New("sample byte budget")
				}
			}
			values[selected[i]] = append(values[selected[i]], features.Sample{Value: value})
		}
	}
	if rows.Err() != nil {
		return nil, 0, 0, errors.New("sample interrupted")
	}
	return values, count, bytes, nil
}
