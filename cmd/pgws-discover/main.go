// pgws-discover emits private aggregate profiles, never field approvals.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"pgws/internal/config"
	"pgws/internal/privacy/discover"
)

type settings struct {
	DSN         string           `json:"source_dsn"`
	Request     discover.Request `json:"relation"`
	StatementMS int              `json:"statement_timeout_ms"`
	JobMS       int              `json:"job_timeout_ms"`
}

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: pgws-discover PRIVATE_CONFIG.json")
	}
	text, err := config.PrivateText(args[0])
	if err != nil {
		return errors.New("private discovery configuration unavailable")
	}
	var cfg settings
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || strings.TrimSpace(cfg.DSN) == "" || cfg.StatementMS < 0 || cfg.StatementMS > 500 || cfg.JobMS < 0 || cfg.JobMS > 30000 {
		return errors.New("invalid private discovery configuration")
	}
	connection, err := pgx.ParseConfig(cfg.DSN)
	if err != nil {
		return errors.New("invalid private source connection")
	}
	cfg.Request.StatementTimeout = time.Duration(cfg.StatementMS) * time.Millisecond
	cfg.Request.JobTimeout = time.Duration(cfg.JobMS) * time.Millisecond
	result, err := discover.Profile(ctx, connection, cfg.Request)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
