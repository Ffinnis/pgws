package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"path/filepath"
	"pgws/internal/config"
	"pgws/internal/host"
	"pgws/internal/policyapproval"
	oci "pgws/internal/runtime"
)

func main() {
	if err := run(); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	mode := "watch"
	if len(args) > 1 {
		mode = args[0]
		args = args[1:]
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || len(args) < 1 || len(args) > 2 || (mode != "watch" && mode != "approve" && mode != "relay" && mode != "seed" && mode != "run") || (mode == "approve" || mode == "relay") != (len(args) == 2) {
		return errors.New("usage: pgws-logical-watchdog [watch|seed|run] CANDIDATE.json | approve CANDIDATE.json SIGNED_APPROVAL.json | relay CANDIDATE.json RPC_TOKEN_FILE, private files on Linux as root")
	}
	text, err := config.PrivateText(args[0])
	if err != nil {
		return err
	}
	var candidate host.LogicalCandidate
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&candidate) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid private logical candidate")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if mode != "watch" {
		if candidate.Approval == nil {
			return errors.New("signed approval configuration required")
		}
		if err = oci.ValidateApproval(candidate.Container, *candidate.Approval); err != nil {
			return err
		}
		if mode == "relay" {
			token, e := config.PrivateText(args[1])
			if e != nil || len(token) < 32 {
				return errors.New("private approval channel credential required")
			}
			socket := candidate.Approval.Path + ".sock"
			lock, e := os.OpenFile(socket+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
			if e != nil {
				return e
			}
			defer lock.Close()
			info, e := lock.Stat()
			if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
				return errors.New("approval relay requires a private process lock")
			}
			if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
				return errors.New("approval relay already running")
			}
			listener, e := config.ListenPrivateUnix(socket)
			if e != nil {
				return e
			}
			defer listener.Close()
			defer os.Remove(socket)
			if e = os.Chmod(socket, 0600); e != nil {
				return e
			}
			server := http.Server{Handler: host.LogicalApprovalHandler(candidate, token), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
			done := make(chan error, 1)
			go func() { done <- server.Serve(listener) }()
			select {
			case e := <-done:
				return e
			case <-ctx.Done():
				return server.Close()
			}
		}
		o := oci.OCI{Binary: "/usr/bin/docker", Image: oci.PostgresImage}
		if mode == "approve" {
			if _, e := os.Lstat(filepath.Join(candidate.Container.Spec.ControlDir, "logical-stop.json")); !os.IsNotExist(e) {
				return errors.New("terminal logical runtime cannot receive approval")
			}
			if err = o.Verify(ctx, candidate.Container); err != nil {
				return err
			}
			text, e := config.PrivateText(args[1])
			if e != nil {
				return e
			}
			var signed struct {
				Approval policyapproval.Claims `json:"approval"`
				Token    string                `json:"approval_token"`
			}
			decoder := json.NewDecoder(strings.NewReader(text))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&signed) != nil || decoder.Decode(new(any)) != io.EOF {
				return errors.New("invalid signed approval document")
			}
			return candidate.Approval.Install(signed.Token)
		}
		output, e := o.IngestApproved(ctx, candidate.Container, mode, *candidate.Approval)
		if e != nil {
			return e
		}
		_, e = os.Stdout.Write(output)
		return e
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		if err = host.WatchLogicalOnce(ctx, candidate); err != nil && ctx.Err() == nil {
			slog.Error("logical candidate needs source or runtime reconciliation")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}
