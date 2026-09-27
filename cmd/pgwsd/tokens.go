package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/control"
)

func tokenCommand(ctx context.Context, pool *pgxpool.Pool, command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	tenant := f.String("tenant", "", "tenant UUID")
	project := f.String("project", "", "project UUID")
	principal := f.String("principal", "", "principal UUID")
	id := f.String("id", "", "token UUID")
	raw := f.Bool("raw", false, "allow raw data")
	admin := f.Bool("admin", false, "allow source administration")
	ttl := f.Duration("ttl", 24*time.Hour, "token lifetime")
	limit := f.Int("limit", 100, "maximum returned tokens")
	after := f.String("after", "", "token UUID cursor")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return errors.New("invalid token flags")
	}
	allowed := map[string]bool{"tenant": true, "project": true}
	switch command {
	case "token-create":
		allowed["principal"], allowed["raw"], allowed["admin"], allowed["ttl"] = true, true, true, true
	case "token-rotate":
		allowed["id"], allowed["ttl"] = true, true
	case "token-list":
		allowed["limit"], allowed["after"] = true, true
	case "token-revoke":
		allowed["id"] = true
	case "principal-revoke":
		allowed["principal"] = true
	default:
		return errors.New("unknown token command")
	}
	valid := true
	f.Visit(func(v *flag.Flag) {
		if !allowed[v.Name] {
			valid = false
		}
	})
	if !valid {
		return errors.New("flag does not apply to this token command")
	}
	work, done := context.WithTimeout(ctx, 10*time.Second)
	defer done()
	epoch := os.Getenv("PGWS_AUTHORITY_EPOCH")
	switch command {
	case "token-create", "token-rotate":
		if command == "token-rotate" && !control.ValidID(*id) {
			return errors.New("token rotation requires --id")
		}
		grant, token, err := control.CreateAPIToken(work, pool, epoch, control.TokenGrant{Tenant: *tenant, Project: *project, Principal: *principal, Raw: *raw, Admin: *admin}, *ttl, *id)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(control.Object{"grant": grant, "token": token})
	case "token-list":
		items, err := control.ListAPITokens(work, pool, *tenant, *project, *after, *limit)
		if err != nil {
			return err
		}
		result := control.Object{"items": items}
		if len(items) == *limit {
			result["next_cursor"] = items[len(items)-1].ID
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	default:
		count, err := control.RevokeAPITokens(work, pool, epoch, *tenant, *project, *id, *principal)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(control.Object{"revoked_tokens": count})
	}
}
