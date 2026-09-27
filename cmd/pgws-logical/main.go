// pgws-logical operates private ingestion candidates. It cannot publish an
// endpoint or approve a privacy policy for the public workspace service.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"pgws/internal/policyapproval"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/config"
	"pgws/internal/control"
	"pgws/internal/logical"
	"pgws/internal/privacy"
)

type settings struct {
	SourceDSN         string           `json:"source_dsn"`
	TargetDSN         string           `json:"target_dsn"`
	Identity          logical.Identity `json:"identity"`
	Policy            privacy.Policy   `json:"policy"`
	KeyFile           string           `json:"transform_key_file"`
	DDLFrozen         bool             `json:"ddl_frozen"`
	MarkerTable       uint32           `json:"marker_relation_oid"`
	MarkerWriter      string           `json:"marker_writer_dsn"`
	BarrierID         string           `json:"barrier_id"`
	BarrierExpires    time.Time        `json:"barrier_expires_at"`
	SlotOwnershipFile string           `json:"slot_ownership_file"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 2 || (args[0] != "discover" && args[0] != "seed" && args[0] != "run" && args[0] != "barrier" && args[0] != "status") {
		return errors.New("usage: pgws-logical discover|seed|run|barrier|status PRIVATE_CONFIG.json")
	}
	text, err := config.PrivateText(args[1])
	if err != nil {
		return err
	}
	var cfg settings
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || !control.ValidID(cfg.Identity.Source) || cfg.Identity.Epoch < 1 {
		return errors.New("invalid logical administrator configuration")
	}
	if encoded := os.Getenv("PGWS_LOGICAL_RUNTIME_BINDING"); encoded != "" {
		var admitted logical.Identity
		if json.Unmarshal([]byte(encoded), &admitted) != nil || cfg.Identity.Source != admitted.Source || cfg.Identity.Epoch != admitted.Epoch || cfg.Identity.Baseline != admitted.Baseline || cfg.Identity.Generation != admitted.Generation {
			return errors.New("logical configuration differs from admitted baseline generation")
		}
	}
	source, err := privateConnection(cfg.SourceDSN)
	if err != nil {
		return err
	}
	if args[0] == "status" {
		owned, e := logical.ReadSlotOwnership(cfg.SlotOwnershipFile)
		if e != nil {
			return e
		}
		if owned.Source != cfg.Identity {
			return errors.New("logical status generation differs from ownership receipt")
		}
		observation, e := logical.InspectSlot(ctx, source, cfg.SlotOwnershipFile)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(observation)
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(inspectCtx, source)
	if err != nil {
		return errors.New("source discovery connection unavailable")
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(inspectCtx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return errors.New("source discovery snapshot unavailable")
	}
	defer tx.Rollback(context.Background())
	schema, err := logical.ReadCatalog(inspectCtx, tx)
	if err != nil {
		return err
	}
	identity := cfg.Identity
	err = tx.QueryRow(inspectCtx, "SELECT (pg_control_system()).system_identifier::text,(pg_control_checkpoint()).timeline_id").Scan(&identity.SystemID, &identity.Timeline)
	if err != nil {
		return errors.New("source discovery lineage unavailable")
	}
	if err = tx.Rollback(inspectCtx); err != nil {
		return errors.New("source discovery could not finish")
	}
	conn.Close(inspectCtx)
	if args[0] == "discover" {
		return json.NewEncoder(out).Encode(struct {
			Identity   logical.Identity `json:"identity"`
			Database   string           `json:"database"`
			Schema     privacy.Schema   `json:"schema"`
			SchemaHash string           `json:"schema_hash"`
		}{identity, source.Database, schema, privacy.SchemaHash(schema)})
	}
	if identity != cfg.Identity {
		return errors.New("source lineage differs from the approved configuration")
	}
	if args[0] == "seed" && !cfg.DDLFrozen {
		return errors.New("initial seed requires an operator-established source DDL freeze")
	}
	key, err := config.Key(cfg.KeyFile, 32)
	if err != nil {
		return err
	}
	plan, err := privacy.Compile(schema, cfg.Policy, key)
	keyHash := fmt.Sprintf("%x", sha256.Sum256(key))
	clear(key)
	if err != nil {
		return err
	}
	if encoded := os.Getenv("PGWS_LOGICAL_APPROVAL_BINDING"); encoded != "" {
		var approved policyapproval.Binding
		if json.Unmarshal([]byte(encoded), &approved) != nil || approved.Source != identity.Source || approved.SourceEpoch != identity.Epoch || approved.SystemID != identity.SystemID || approved.Timeline != identity.Timeline || approved.PlanHash != plan.Hash() || approved.SchemaHash != plan.SchemaHash() || approved.KeyFingerprint != keyHash || approved.Compiler != "pgws-transform-v1" {
			return errors.New("compiled ingestion differs from host policy approval")
		}
	}
	destination, err := privateConnection(cfg.TargetDSN)
	if err != nil {
		return err
	}
	if destination.Host == source.Host && destination.Port == source.Port && destination.Database == source.Database {
		return errors.New("logical source and target must be distinct databases")
	}
	poolConfig, err := pgxpool.ParseConfig(cfg.TargetDSN)
	if err != nil {
		return errors.New("invalid private target pool configuration")
	}
	poolConfig.ConnConfig = destination
	poolConfig.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("private target pool unavailable")
	}
	defer pool.Close()
	target := logical.Target{Pool: pool, Plan: plan, Identity: cfg.Identity, MarkerTable: cfg.MarkerTable}
	connector := logical.Connector{Source: source, Target: target}
	if cfg.SlotOwnershipFile != "" {
		if args[0] == "seed" {
			if e := logical.CheckSlotOwnershipDestination(cfg.SlotOwnershipFile); e != nil {
				return e
			}
		}
		connector.AfterSlotCreated = func(receipt logical.SlotOwnership) error {
			return logical.WriteSlotOwnership(cfg.SlotOwnershipFile, receipt)
		}
		connector.AfterDurableApply = func(position string) error {
			return logical.PersistApplied(cfg.SlotOwnershipFile, position)
		}
		if args[0] != "seed" {
			receipt, e := logical.ReadSlotOwnership(cfg.SlotOwnershipFile)
			if e != nil {
				return e
			}
			if e = connector.MatchSlotOwnership(receipt); e != nil {
				return e
			}
			var match bool
			if e = pool.QueryRow(ctx, "SELECT seed_lsn=$1::pg_lsn FROM _pgws_ingestion.checkpoint WHERE singleton", receipt.SeedLSN).Scan(&match); e != nil || !match {
				return errors.New("logical seed differs from the durable slot ownership receipt")
			}
		}
	}
	if args[0] == "barrier" {
		writer, e := privateConnection(cfg.MarkerWriter)
		if e != nil {
			return e
		}
		boundary, e := connector.Barrier(ctx, writer, cfg.BarrierID, cfg.BarrierExpires)
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(boundary)
	}
	if args[0] == "run" {
		return connector.Run(ctx)
	}
	if err = target.Initialize(ctx); err != nil {
		return err
	}
	receipt, err := connector.Seed(ctx)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct {
		Seed     logical.SeedReceipt `json:"seed"`
		PlanHash string              `json:"plan_hash"`
		Eligible bool                `json:"eligible_for_publication"`
	}{receipt, plan.Hash(), false})
}

func privateConnection(dsn string) (*pgx.ConnConfig, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("explicit private PostgreSQL connection required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || !filepath.IsAbs(cfg.Host) || filepath.Clean(cfg.Host) != cfg.Host || len(cfg.Fallbacks) != 0 || cfg.Database == "" || cfg.User == "" {
		return nil, errors.New("logical administrator tool requires one private Unix socket connection")
	}
	cfg.ConnectTimeout = 5 * time.Second
	cfg.RuntimeParams["search_path"] = "pg_catalog"
	cfg.RuntimeParams["row_security"] = "off"
	cfg.RuntimeParams["statement_timeout"] = "30000"
	return cfg, nil
}
