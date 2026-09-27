package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"pgws/internal/config"
	"pgws/internal/host"
	"runtime"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error(e.Error())
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 || runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("usage: pgws-watchdog HOST_CONFIG.json on the dedicated Linux host")
	}
	text, e := config.PrivateText(os.Args[1])
	if e != nil {
		return e
	}
	var c host.Config
	if json.Unmarshal([]byte(text), &c) != nil || !filepath.IsAbs(c.Root) || c.ID == "" || c.Epoch == "" {
		return errors.New("invalid watchdog host configuration")
	}
	if e = os.MkdirAll(c.Root, 0700); e != nil {
		return e
	}
	lock, e := os.OpenFile(filepath.Join(c.Root, "watchdog.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return errors.New("watchdog is already running")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	servingDone := make(chan struct{})
	go func() {
		defer close(servingDone)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			check, done := context.WithTimeout(ctx, 3*time.Second)
			if host.WatchdogServingOnce(check, c) != nil && ctx.Err() == nil {
				slog.Error("serving watchdog check failed; generation needs inspection")
			}
			done()
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	defer func() { cancel(); <-servingDone }()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			check, done := context.WithTimeout(ctx, 10*time.Second)
			if host.WatchdogOnce(check, c) != nil {
				slog.Error("watchdog check failed; source and generation need inspection")
			}
			done()
		}
	}
}
