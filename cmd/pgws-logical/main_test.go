package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/control"
	"pgws/internal/logical"
	"pgws/internal/privacy"
)

func TestPrivateConnectionBoundary(t *testing.T) {
	for _, dsn := range []string{"", "host=127.0.0.1 user=postgres dbname=app", "host=/tmp,/other user=postgres dbname=app", "host=/tmp/../secret user=postgres dbname=app"} {
		if _, err := privateConnection(dsn); err == nil {
			t.Fatal("accepted a non-private or ambiguous connection")
		}
	}
}

func TestAdministratorCLI(t *testing.T) {
	if os.Getenv("PGWS_LOGICAL_CLI_LAB") != "1" {
		t.Skip("requires the disposable private Unix PostgreSQL 18 lab")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, os.Getenv("PGWS_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	names := []string{"cli_src_" + strings.ReplaceAll(control.ID(), "-", ""), "cli_dst_" + strings.ReplaceAll(control.ID(), "-", "")}
	for _, name := range names {
		if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()+" TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"); err != nil {
			t.Fatal(err)
		}
		defer admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	}
	dsn := func(name string) string {
		return fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable", admin.Config().Host, admin.Config().Port, admin.Config().User, name)
	}
	source, err := pgx.Connect(ctx, dsn(names[0]))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close(context.Background())
	if _, err = source.Exec(ctx, "CREATE TABLE people(id bigint PRIMARY KEY,email text NOT NULL);INSERT INTO people VALUES(1,'raw@example.org'); CREATE SCHEMA _pgws_barriers; CREATE TABLE _pgws_barriers.marker(id bigint PRIMARY KEY,token uuid NOT NULL,expires_at bigint NOT NULL); INSERT INTO _pgws_barriers.marker VALUES(1,'00000000-0000-0000-0000-000000000000',0)"); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err = os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "logical.json")
	cfg := settings{SourceDSN: dsn(names[0]), TargetDSN: dsn(names[1]), Identity: logical.Identity{Source: control.ID(), Epoch: 1}, KeyFile: filepath.Join(dir, "transform.key"), DDLFrozen: true, SlotOwnershipFile: filepath.Join(dir, "slot.json")}
	writeConfig := func() {
		t.Helper()
		data, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig()
	var output bytes.Buffer
	if err = run(ctx, []string{"discover", path}, &output); err != nil {
		t.Fatal(err)
	}
	var discovery struct {
		Identity   logical.Identity `json:"identity"`
		Schema     privacy.Schema   `json:"schema"`
		SchemaHash string           `json:"schema_hash"`
	}
	if json.Unmarshal(output.Bytes(), &discovery) != nil || len(discovery.Schema.Tables) != 2 {
		t.Fatal("invalid discovery receipt")
	}
	cfg.Identity = discovery.Identity
	cfg.Policy = privacy.Policy{Version: 1, SchemaHash: discovery.SchemaHash, KeyID: "cli-v1"}
	for _, table := range discovery.Schema.Tables {
		if table.Schema == "_pgws_barriers" {
			cfg.MarkerTable = table.ID
		}
		for _, column := range table.Columns {
			rule := privacy.Rule{Table: table.ID, Column: column.ID, Action: "copy_original"}
			if column.Name == "email" {
				rule.Action, rule.Domain = "keyed_email", "email"
			}
			cfg.Policy.Rules = append(cfg.Policy.Rules, rule)
		}
	}
	role := "cli_marker_" + strings.ReplaceAll(control.ID(), "-", "")
	if _, err = source.Exec(ctx, "CREATE ROLE "+pgx.Identifier{role}.Sanitize()+" LOGIN; GRANT USAGE ON SCHEMA _pgws_barriers TO "+pgx.Identifier{role}.Sanitize()+"; GRANT SELECT(id),UPDATE(token,expires_at) ON _pgws_barriers.marker TO "+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	// Remove grants held by the disposable role before its database is dropped.
	defer func() {
		source.Exec(context.Background(), "DROP OWNED BY "+pgx.Identifier{role}.Sanitize())
		admin.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{role}.Sanitize())
	}()
	cfg.MarkerWriter = fmt.Sprintf("host=%s port=%d user=%s dbname=%s sslmode=disable", admin.Config().Host, admin.Config().Port, role, names[0])
	cfg.BarrierID = control.ID()
	cfg.BarrierExpires = time.Now().Add(10 * time.Minute).Truncate(time.Second)
	if err = os.WriteFile(cfg.KeyFile, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))), 0600); err != nil {
		t.Fatal(err)
	}
	writeConfig()
	defer source.Exec(context.Background(), "SELECT pg_drop_replication_slot($1)", "pgws_l_"+strings.ReplaceAll(cfg.Identity.Source, "-", "")+"_1")
	output.Reset()
	if err = run(ctx, []string{"seed", path}, &output); err != nil {
		t.Fatal(err)
	}
	if owned, e := logical.ReadSlotOwnership(cfg.SlotOwnershipFile); e != nil || owned.Source != cfg.Identity {
		t.Fatal("CLI lost confirmed slot ownership", e)
	} else if progress, e := logical.ReadApplied(cfg.SlotOwnershipFile, owned); e != nil || progress.AppliedLSN != owned.SeedLSN {
		t.Fatal("CLI lost committed seed progress", e)
	}
	if !strings.Contains(output.String(), `"eligible_for_publication":false`) {
		t.Fatal("seed falsely declared publication eligibility")
	}
	target, err := pgx.Connect(ctx, dsn(names[1]))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close(context.Background())
	var email string
	if err = target.QueryRow(ctx, "SELECT email FROM people WHERE id=1").Scan(&email); err != nil || !strings.HasSuffix(email, "@example.invalid") {
		t.Fatal("CLI seed did not transform its source", err)
	}
	if _, err = source.Exec(ctx, "INSERT INTO people VALUES(2,'second-raw@example.org')"); err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- run(runCtx, []string{"run", path}, &output) }()
	for {
		var count int
		if err = target.QueryRow(ctx, "SELECT count(*) FROM people WHERE id=2").Scan(&count); err == nil && count == 1 {
			break
		}
		select {
		case e := <-done:
			t.Fatal("CLI stream stopped before its committed change", e)
		case <-ctx.Done():
			t.Fatal("CLI stream deadline exceeded")
		case <-time.After(20 * time.Millisecond):
		}
	}
	var markerOutput bytes.Buffer
	if err = run(ctx, []string{"barrier", path}, &markerOutput); err != nil {
		t.Fatal(err)
	}
	var marker logical.MarkerBoundary
	if json.Unmarshal(markerOutput.Bytes(), &marker) != nil || marker.ID != cfg.BarrierID || marker.LSN == "" || marker.Source != cfg.Identity {
		t.Fatal("CLI barrier lost durable source binding")
	}
	stop()
	if e := <-done; !errors.Is(e, context.Canceled) {
		t.Fatal("CLI did not stop on cancellation", e)
	}
	// Independent status needs neither a target connection nor a transform key.
	cfg.TargetDSN, cfg.KeyFile = "", ""
	writeConfig()
	output.Reset()
	if err = run(ctx, []string{"status", path}, &output); err != nil {
		t.Fatal(err)
	}
	var status logical.SlotObservation
	if json.Unmarshal(output.Bytes(), &status) != nil || status.Reason != "" || !status.SeedCommitted || status.Source != cfg.Identity {
		t.Fatal("private CLI status lost durable ownership")
	}
}
