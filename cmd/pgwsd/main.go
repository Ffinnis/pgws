package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/config"
	"pgws/internal/control"
	"pgws/internal/hostclient"
	"pgws/internal/migrations"
)

func main() {
	if e := run(); e != nil {
		slog.Error(e.Error())
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) > 1 && os.Args[1] == "recovery-init" {
		return initRecovery(os.Args[2:])
	}
	if len(os.Args) < 2 || len(os.Args) > 2 && !strings.HasPrefix(os.Args[1], "token-") && !strings.HasPrefix(os.Args[1], "policy-") && !strings.HasPrefix(os.Args[1], "recovery-") && os.Args[1] != "principal-revoke" {
		return errors.New("usage: pgwsd migrate|bootstrap|serve|worker|token-create|token-list|token-rotate|token-revoke|principal-revoke|policy-create|policy-show|policy-approve|policy-revoke|policy-sign|policy-renew|recovery-init|recovery-begin|recovery-finish")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dsn := os.Getenv("PGWS_DATABASE_URL")
	if dsn == "" {
		return errors.New("PGWS_DATABASE_URL is required")
	}
	pool, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return errors.New("invalid management database configuration")
	}
	defer pool.Close()
	check, stop := context.WithTimeout(ctx, 5*time.Second)
	e = pool.Ping(check)
	stop()
	if e != nil {
		return errors.New("management database unavailable")
	}
	switch os.Args[1] {
	case "migrate":
		if e = migrations.Apply(ctx, pool); e != nil {
			return errors.New("migration failed; verify owner privileges and immutable migration files")
		}
		slog.Info("migrations applied")
		return nil
	case "bootstrap":
		return bootstrap(ctx, pool)
	case "token-create", "token-list", "token-rotate", "token-revoke", "principal-revoke":
		return tokenCommand(ctx, pool, os.Args[1], os.Args[2:])
	case "policy-create", "policy-show", "policy-approve", "policy-revoke", "policy-sign":
		return privacyCommand(ctx, pool, os.Args[1], os.Args[2:])
	case "policy-renew":
		return renewPolicyCommand(ctx, pool, os.Args[2:])
	case "recovery-begin", "recovery-finish":
		return recoveryCommand(ctx, pool, os.Args[1], os.Args[2:])
	}
	epoch := os.Getenv("PGWS_AUTHORITY_EPOCH")
	if !control.ValidID(epoch) {
		return errors.New("PGWS_AUTHORITY_EPOCH must be a UUID from external configuration")
	}
	switch os.Args[1] {
	case "serve":
		addr := os.Getenv("PGWS_LISTEN")
		if addr == "" {
			addr = "127.0.0.1:8080"
		}
		host, _, e := net.SplitHostPort(addr)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("initial HTTP server must bind a loopback IP; use a TLS reverse proxy for remote access")
		}
		api := &control.Server{Pool: pool, Epoch: epoch, Log: slog.Default(), Physical: os.Getenv("PGWS_PHYSICAL_ENABLED") == "true"}
		if api.Physical {
			api.AuthorityKey, e = config.Key(os.Getenv("PGWS_AUTHORITY_KEY_FILE"), 32)
			if e != nil {
				return e
			}
			api.SecretKey, e = config.Key(os.Getenv("PGWS_SECRET_KEY_FILE"), 32)
			if e != nil {
				return e
			}
			if e = control.CheckAuthorityKey(ctx, pool, epoch, api.AuthorityKey); e != nil {
				return e
			}
		}
		handler := api.Handler()
		srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
		done := make(chan error, 1)
		go func() { done <- srv.ListenAndServe() }()
		slog.Info("control API listening", "address", addr, "physical_configured", api.Physical)
		select {
		case e := <-done:
			if errors.Is(e, http.ErrServerClosed) {
				return nil
			}
			return errors.New("HTTP listener failed")
		case <-ctx.Done():
			shut, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			return srv.Shutdown(shut)
		}
	case "worker":
		worker := control.Worker{Pool: pool, Epoch: epoch, ID: control.ID()}
		if socket := os.Getenv("PGWS_HOST_SOCKET"); socket != "" {
			token, e := config.PrivateText(os.Getenv("PGWS_HOST_TOKEN_FILE"))
			if e != nil {
				return e
			}
			key, e := config.Key(os.Getenv("PGWS_SIGNING_KEY_FILE"), 64)
			if e != nil {
				return e
			}
			worker.Backend = hostclient.Client{Socket: socket, Token: token}
			worker.HostID = os.Getenv("PGWS_HOST_ID")
			worker.SigningKey = key
			if e = control.CheckAuthorityKey(ctx, pool, epoch, ed25519.PrivateKey(key).Public().(ed25519.PublicKey)); e != nil {
				return e
			}
			if worker.HostID == "" {
				return errors.New("PGWS_HOST_ID is required")
			}
			// Serving renewal gets its own loop and deadline. GC and expiry database
			// contention must not consume the guard renewal window.
			go maintain(ctx, "serving lease refresh", 20*time.Second, worker.RefreshServing)
			go maintain(ctx, "serving authorization revocation", time.Second, worker.ReconcileRevocations)
			go maintain(ctx, "credential authorization revocation", time.Second, worker.ReconcileCredentialRevocations)
			go maintain(ctx, "host safety reconciliation", 10*time.Second, worker.ReconcileHost)
			go maintain(ctx, "capacity measurement collection", time.Minute, worker.CollectUsage)
			go maintain(ctx, "resource cleanup", time.Minute, func(ctx context.Context) error {
				_, expiryErr := worker.SweepExpired(ctx)
				_, gcErr := worker.SweepSnapshots(ctx)
				return errors.Join(expiryErr, gcErr)
			})
		}
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				jobctx, stop := context.WithTimeout(ctx, 20*time.Minute)
				_, e := worker.Once(jobctx)
				stop()
				if e != nil {
					slog.Error("worker iteration failed", "error", e)
				}
			}
		}
	default:
		return errors.New("unknown command")
	}
}
func bootstrap(ctx context.Context, pool *pgxpool.Pool) error {
	tx, e := pool.Begin(ctx)
	if e != nil {
		return errors.New("bootstrap transaction unavailable")
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(70677783002)`); e != nil {
		return errors.New("bootstrap lock unavailable")
	}
	var exists bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pgws_control.authority)`).Scan(&exists); e != nil {
		return errors.New("apply migrations before bootstrap")
	}
	if exists {
		return errors.New("authority already exists; bootstrap cannot overwrite a live or restored authority")
	}
	tenant, project, principal, epoch := control.ID(), control.ID(), control.ID(), control.ID()
	tokenID := control.ID()
	var secret [32]byte
	if _, e = rand.Read(secret[:]); e != nil {
		return e
	}
	token := hex.EncodeToString(secret[:])
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(token)))
	statements := []struct {
		q string
		a []any
	}{
		{`INSERT INTO pgws_control.tenants(id,name) VALUES($1,'Local development')`, []any{tenant}},
		{`INSERT INTO pgws_control.projects(tenant_id,id,name) VALUES($1,$2,'Development')`, []any{tenant, project}},
		{`INSERT INTO pgws_control.authority(epoch,reconciled) VALUES($1,true)`, []any{epoch}},
		{`INSERT INTO pgws_control.api_tokens(id,token_hash,principal_id,tenant_id,project_id,is_admin,allow_raw,expires_at) VALUES($1,$2,$3,$4,$5,true,true,now()+interval '24 hours')`, []any{tokenID, hash, principal, tenant, project}},
	}
	for _, s := range statements {
		if _, e = tx.Exec(ctx, s.q, s.a...); e != nil {
			return errors.New("bootstrap failed")
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return errors.New("bootstrap commit failed")
	}
	// This is the explicit one-time credential output, not a service log.
	return json.NewEncoder(os.Stdout).Encode(control.Object{"tenant_id": tenant, "project_id": project, "principal_id": principal, "authority_epoch": epoch, "token_id": tokenID, "token": token, "token_valid_hours": 24})
}

func maintain(ctx context.Context, name string, interval time.Duration, run func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		iteration, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := run(iteration)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Error(name + " failed")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
