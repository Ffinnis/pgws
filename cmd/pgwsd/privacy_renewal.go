package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/config"
	"pgws/internal/control"
	"pgws/internal/hostclient"
)

func renewPolicyCommand(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: pgwsd policy-renew PRIVATE_RENEWAL.json")
	}
	text, err := config.PrivateText(args[0])
	if err != nil {
		return err
	}
	var cfg struct {
		Candidate control.PolicyRenewal `json:"candidate"`
		Socket    string                `json:"socket"`
		TokenFile string                `json:"token_file"`
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF || !filepath.IsAbs(cfg.Socket) {
		return errors.New("invalid policy renewal configuration")
	}
	token, err := config.PrivateText(cfg.TokenFile)
	if err != nil {
		return err
	}
	if len(token) < 32 {
		return errors.New("private approval channel credential required")
	}
	key, err := config.Key(os.Getenv("PGWS_SIGNING_KEY_FILE"), 64)
	if err != nil {
		return err
	}
	defer clear(key)
	epoch := os.Getenv("PGWS_AUTHORITY_EPOCH")
	if cfg.Candidate.Binding.Authority != epoch || !control.ValidID(epoch) {
		return errors.New("policy renewal authority differs")
	}
	relay := hostclient.Client{Socket: cfg.Socket, Token: token}
	// Independent from API and the job worker. Stopping this loop cannot extend
	// host authority; the permit and separate watchdog enforce its deadline.
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = control.RenewPrivacyPolicy(attempt, pool, epoch, cfg.Candidate, key, relay)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Error("policy renewal failed; candidate retains its existing expiry")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
