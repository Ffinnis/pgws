package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"pgws/internal/config"
	"pgws/internal/control"
	"pgws/internal/host"
	"pgws/internal/sourcebroker"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) == 5 && os.Args[1] == "recover" {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return errors.New("host recovery requires Linux root")
		}
		var old, next host.Config
		var plan control.RecoveryPlan
		for i, target := range []any{&old, &next, &plan} {
			text, err := config.PrivateText(os.Args[i+2])
			if err != nil {
				return err
			}
			decoder := json.NewDecoder(strings.NewReader(text))
			decoder.DisallowUnknownFields()
			if decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
				return errors.New("invalid private recovery configuration")
			}
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		report, err := host.RecoverAuthority(ctx, old, next, plan)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	if len(os.Args) != 3 {
		return errors.New("usage: pgws-host CONFIG.json RPC_TOKEN_FILE | pgws-host capacity CONFIG.json | pgws-host source-broker CONFIG.json | pgws-host recover OLD_CONFIG.json NEW_CONFIG.json RECOVERY_PLAN.json")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("host helper requires a dedicated Linux host and root storage/runtime privileges")
	}
	if os.Args[1] == "source-broker" {
		text, err := config.PrivateText(os.Args[2])
		if err != nil {
			return err
		}
		var plan sourcebroker.ProcessConfig
		if json.Unmarshal([]byte(text), &plan) != nil {
			return errors.New("invalid source broker configuration")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return sourcebroker.RunProcess(ctx, plan)
	}
	configPath := os.Args[1]
	if configPath == "capacity" {
		configPath = os.Args[2]
	}
	text, e := config.PrivateText(configPath)
	if e != nil {
		return e
	}
	var c host.Config
	if json.Unmarshal([]byte(text), &c) != nil {
		return errors.New("invalid host configuration")
	}
	if c.SourceBrokerBinary == "" {
		c.SourceBrokerBinary, e = os.Executable()
		if e != nil {
			return e
		}
	}
	if os.Args[1] == "capacity" {
		ctx, done := context.WithTimeout(context.Background(), 30*time.Second)
		defer done()
		report, err := host.InspectCapacity(ctx, c)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(report)
	}
	token, e := config.PrivateText(os.Args[2])
	if e != nil || len(token) < 32 {
		return errors.New("host RPC credential unavailable")
	}
	h, e := host.Open(c)
	if e != nil {
		return e
	}
	defer h.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var lastWarning time.Time
		for {
			if err := h.MaintainSources(ctx); err != nil && ctx.Err() == nil && time.Since(lastWarning) >= time.Minute {
				fmt.Fprintln(os.Stderr, "source maintenance incomplete; retrying")
				lastWarning = time.Now()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	defer func() { cancel(); <-maintenanceDone }()
	socket := filepath.Join(c.Root, "host.sock")
	mode := os.FileMode(0600)
	if c.RPCSocket != "" {
		socket = c.RPCSocket
	}
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || c.RPCGroup < 0 {
		return errors.New("invalid host RPC path or group")
	}
	if c.RPCGroup != 0 {
		if filepath.Dir(socket) == c.Root {
			return errors.New("group-accessible RPC requires a separate directory from private host state")
		}
		dir := filepath.Dir(socket)
		if e = os.MkdirAll(dir, 0750); e != nil {
			return e
		}
		if e = os.Chown(dir, 0, c.RPCGroup); e != nil {
			return e
		}
		if e = os.Chmod(dir, 0750); e != nil {
			return e
		}
		mode = 0660
	}
	listener, e := config.ListenPrivateUnix(socket)
	if e != nil {
		return e
	}
	defer listener.Close()
	defer os.Remove(socket)
	if c.RPCGroup != 0 {
		if e = os.Chown(socket, 0, c.RPCGroup); e != nil {
			return e
		}
	}
	if e = os.Chmod(socket, mode); e != nil {
		return e
	}
	server := http.Server{Handler: h.Handler(token), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case e := <-done:
		return e
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		return server.Shutdown(shutdown)
	}
}
