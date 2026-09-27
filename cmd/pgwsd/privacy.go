package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/config"
	"pgws/internal/control"
)

func privacyCommand(parent context.Context, pool *pgxpool.Pool, command string, args []string) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	epoch := os.Getenv("PGWS_AUTHORITY_EPOCH")
	var record control.PolicyRecord
	var err error
	if command == "policy-create" {
		if len(args) != 1 {
			return errors.New("usage: pgwsd policy-create PRIVATE_REVIEW.json")
		}
		text, e := config.PrivateText(args[0])
		if e != nil {
			return e
		}
		var review struct {
			Draft   control.PolicyDraft `json:"draft"`
			KeyFile string              `json:"transform_key_file"`
		}
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&review) != nil || decoder.Decode(new(any)) != io.EOF {
			return errors.New("invalid private policy review")
		}
		key, e := config.Key(review.KeyFile, 32)
		if e != nil {
			return e
		}
		defer clear(key)
		record, err = control.CreatePrivacyPolicy(ctx, pool, epoch, review.Draft, key)
	} else {
		flags := flag.NewFlagSet(command, flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		tenant := flags.String("tenant", "", "tenant UUID")
		project := flags.String("project", "", "project UUID")
		id := flags.String("id", "", "policy UUID")
		hash := flags.String("hash", "", "reviewed plan hash")
		schema := flags.String("schema-hash", "", "reviewed schema hash")
		if flags.Parse(args) != nil || flags.NArg() != 0 {
			return errors.New("invalid policy flags")
		}
		switch command {
		case "policy-show":
			if *hash != "" || *schema != "" {
				return errors.New("policy-show accepts only scope and identity")
			}
			record, err = control.GetPrivacyPolicy(ctx, pool, *tenant, *project, *id)
		case "policy-approve":
			record, err = control.ApprovePrivacyPolicy(ctx, pool, epoch, *tenant, *project, *id, *hash, *schema)
		case "policy-revoke":
			if *schema != "" {
				return errors.New("policy-revoke does not accept a schema hash")
			}
			record, err = control.RevokePrivacyPolicy(ctx, pool, epoch, *tenant, *project, *id, *hash)
		case "policy-sign":
			if *schema != "" {
				return errors.New("policy-sign binds the approved schema automatically")
			}
			key, e := config.Key(os.Getenv("PGWS_SIGNING_KEY_FILE"), 64)
			if e != nil {
				return e
			}
			defer clear(key)
			claims, token, e := control.SignPrivacyPolicy(ctx, pool, epoch, *tenant, *project, *id, *hash, key)
			if e != nil {
				return e
			}
			return json.NewEncoder(os.Stdout).Encode(control.Object{"approval": claims, "approval_token": token})
		default:
			return errors.New("unknown policy command")
		}
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(record)
}
