// Package discover reads bounded aggregate profiles through a dedicated local
// PostgreSQL connection. It neither approves field policies nor publishes data.
package discover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"pgws/internal/privacy/features"
)

const MaxColumns = 64
const MaxRows = 64
const MaxBytes = 8 << 20

type Request struct {
	Source           string        `json:"source_id"`
	Epoch            int64         `json:"source_epoch"`
	Schema           string        `json:"schema"`
	Table            string        `json:"table"`
	StatementTimeout time.Duration `json:"-"`
	JobTimeout       time.Duration `json:"-"`
}

type Result struct {
	Source           string             `json:"source_id"`
	Epoch            int64              `json:"source_epoch"`
	Relation         uint32             `json:"relation_oid"`
	SchemaHash       string             `json:"schema_hash"`
	Reader           string             `json:"reader_contract"`
	Profiles         []features.Profile `json:"profiles"`
	SampledRows      int                `json:"sampled_rows"`
	Attempts         int                `json:"attempts"`
	ReturnedBytes    int                `json:"returned_value_bytes"`
	IncompleteReason string             `json:"incomplete_reason,omitempty"`
	Review           bool               `json:"review_required"`
}

// Profile accepts only a private Unix socket; remote sources must first enter
// an independently approved local connection boundary. Caller-supplied tracing
// is removed because pgx traces can retain values or source error details.
func Profile(ctx context.Context, connection *pgx.ConnConfig, request Request) (Result, error) {
	if connection == nil || !filepath.IsAbs(connection.Host) || filepath.Clean(connection.Host) != connection.Host || len(connection.Fallbacks) != 0 || !sourceID(request.Source) || request.Epoch < 1 || !identifier(request.Schema) || !identifier(request.Table) || strings.HasPrefix(request.Schema, "pg_") || request.Schema == "information_schema" {
		return Result{}, errors.New("invalid private discovery scope")
	}
	if request.StatementTimeout == 0 {
		request.StatementTimeout = 500 * time.Millisecond
	}
	if request.JobTimeout == 0 {
		request.JobTimeout = 5 * time.Second
	}
	if request.StatementTimeout < time.Millisecond || request.StatementTimeout > 500*time.Millisecond || request.JobTimeout < request.StatementTimeout || request.JobTimeout > 30*time.Second {
		return Result{}, errors.New("discovery deadline exceeds allowed budget")
	}
	ctx, cancel := context.WithTimeout(ctx, request.JobTimeout)
	defer cancel()
	cfg := connection.Copy()
	cfg.MaxProtocolMessageBodyLen = 1 << 20
	cfg.Tracer = nil
	cfg.OnPgError = nil
	cfg.OnNotice = nil
	cfg.OnNotification = nil
	cfg.ConnectTimeout = request.StatementTimeout
	cfg.RuntimeParams = map[string]string{"application_name": "pgws-discovery", "search_path": "pg_catalog", "row_security": "off", "default_transaction_read_only": "on", "statement_timeout": strconv.FormatInt(request.StatementTimeout.Milliseconds(), 10), "lock_timeout": strconv.FormatInt(request.StatementTimeout.Milliseconds(), 10), "idle_in_transaction_session_timeout": strconv.FormatInt(request.JobTimeout.Milliseconds(), 10), "DateStyle": "ISO, YMD", "TimeZone": "UTC", "extra_float_digits": "3"}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return Result{}, errors.New("private discovery connection unavailable")
	}
	// A hard deadline closes the transport even if cancellation cannot reach the
	// backend. No connection from this job is returned to a pool.
	stopClose := context.AfterFunc(ctx, func() { _ = conn.PgConn().Conn().Close() })
	defer func() { stopClose(); _ = conn.PgConn().Conn().Close() }()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Result{}, errors.New("discovery snapshot unavailable")
	}
	var safe bool
	err = tx.QueryRow(ctx, `SELECT current_setting('server_encoding')='UTF8'
 AND current_setting('server_version_num')::int BETWEEN 140000 AND 189999
 AND NOT rolsuper AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolreplication AND NOT rolbypassrls
 FROM pg_roles WHERE rolname=current_user`).Scan(&safe)
	if err != nil || !safe {
		return Result{}, errors.New("discovery requires a restricted read-only identity")
	}
	name := pgx.Identifier{request.Schema, request.Table}.Sanitize()
	// Lock before reading attributes so concurrent type/name changes cannot turn
	// a bounded built-in cast into a different expression after inspection.
	if _, err = tx.Exec(ctx, "LOCK TABLE ONLY "+name+" IN ACCESS SHARE MODE"); err != nil {
		return Result{}, errors.New("discovery relation lock unavailable")
	}
	relation, err := catalog(ctx, tx, request.Schema, request.Table)
	if err != nil {
		return Result{}, err
	}
	encoded, _ := json.Marshal(struct {
		Schema, Table string
		ID            uint32
		Columns       []column
	}{request.Schema, request.Table, relation.ID, relation.Columns})
	digest := sha256.Sum256(encoded)
	result := Result{Source: request.Source, Epoch: request.Epoch, Relation: relation.ID, SchemaHash: hex.EncodeToString(digest[:]), Reader: "pgws-bounded-reader-v1", Review: true}
	selected := []int{}
	for i, c := range relation.Columns {
		if bounded(c) {
			selected = append(selected, i)
		}
	}
	values := make([][]features.Sample, len(relation.Columns))
	if len(selected) > 0 {
		rate := 1.0
		if relation.Estimate > 0 && !math.IsInf(relation.Estimate, 0) && !math.IsNaN(relation.Estimate) {
			rate = math.Min(100, 12800/relation.Estimate)
		}
		for attempt := 0; attempt < 2; attempt++ {
			result.Attempts++
			var rows, returned int
			values, rows, returned, err = sample(ctx, tx, name, relation.Columns, selected, rate)
			if err != nil {
				result.IncompleteReason = "sampling_failed_or_cancelled"
				break
			}
			result.SampledRows, result.ReturnedBytes = rows, returned
			if rows > 0 {
				break
			}
			rate = math.Min(100, rate*10)
		}
	} else {
		result.IncompleteReason = "no_bounded_columns"
	}
	if err != nil {
		values = make([][]features.Sample, len(relation.Columns))
	}
	for i, c := range relation.Columns {
		neighbors := []string{}
		for j, other := range relation.Columns {
			if i != j && len(neighbors) < 32 {
				neighbors = append(neighbors, other.Name)
			}
		}
		profile, profileErr := features.ProfileSamples(features.Metadata{Table: request.Table, Column: c.Name, Type: c.Type, Neighbors: neighbors, Nullable: c.Nullable, PrimaryKey: c.Primary, ForeignKey: c.Foreign, Unique: c.Unique}, values[i], err == nil && bounded(c) && result.SampledRows == MaxRows)
		if profileErr != nil {
			return Result{}, errors.New("discovery profile contract rejected")
		}
		if !bounded(c) {
			profile.Evidence.ReviewFlags = append(profile.Evidence.ReviewFlags, "unsupported_type")
			slices.Sort(profile.Evidence.ReviewFlags)
			profile.Evidence.ReviewFlags = slices.Compact(profile.Evidence.ReviewFlags)
		}
		if _, profileErr = features.Extract(profile); profileErr != nil {
			return Result{}, errors.New("discovery metadata requires private review")
		}
		result.Profiles = append(result.Profiles, profile)
	}
	if err == nil {
		if err = tx.Commit(ctx); err != nil {
			return Result{}, errors.New("discovery snapshot could not finish")
		}
	}
	if result.SampledRows < MaxRows && result.IncompleteReason == "" {
		result.IncompleteReason = "insufficient_sample"
	}
	return result, nil
}

func identifier(value string) bool {
	return len(value) > 0 && len(value) <= 63 && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n\t@") && !strings.Contains(value, "://") && !strings.Contains(value, "sk_live_") && !strings.Contains(value, "AKIA")
}

func sourceID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(value, "-", ""))
	return err == nil && len(raw) == 16 && strings.ToLower(value) == value
}
