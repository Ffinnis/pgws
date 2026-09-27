// pgws-physical is a local administrator tool. It does not publish workspaces.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pgws/internal/physical"
)

type config struct {
	BinDir     string             `json:"bin_directory"`
	Source     physical.Source    `json:"source"`
	Root       string             `json:"root"`
	SourceID   string             `json:"source_id"`
	Generation int64              `json:"generation"`
	MaxBytes   int64              `json:"max_archive_bytes"`
	Recovery   *physical.Recovery `json:"recovery"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: pgws-physical inspect|barrier|seed|recover|stop --config FILE [--timeout 5m]")
	}
	command := os.Args[1]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "", "local administrator JSON configuration")
	timeout := flags.Duration("timeout", 5*time.Minute, "operation deadline")
	if e := flags.Parse(os.Args[2:]); e != nil {
		return e
	}
	if *path == "" || *timeout <= 0 || flags.NArg() != 0 {
		return errors.New("configuration and positive timeout required")
	}
	f, e := os.Open(*path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("configuration must be a regular file of at most 1 MiB")
	}
	decoder := json.NewDecoder(io.LimitReader(f, (1<<20)+1))
	decoder.DisallowUnknownFields()
	var c config
	if e = decoder.Decode(&c); e != nil {
		return errors.New("invalid configuration JSON")
	}
	if e = decoder.Decode(new(any)); e != io.EOF {
		return errors.New("configuration must contain one JSON object")
	}
	parent, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, done := context.WithTimeout(parent, *timeout)
	defer done()
	t := physical.Tools{BinDir: c.BinDir}
	var result any
	switch command {
	case "inspect":
		result, e = c.Source.Inspect(ctx)
	case "barrier":
		result, e = c.Source.CaptureBarrier(ctx)
	case "seed":
		result, e = t.Seed(ctx, c.Source, c.Root, c.SourceID, c.Generation, c.MaxBytes)
	case "recover":
		if c.Recovery == nil {
			return errors.New("recovery configuration required")
		}
		if e = t.PrepareDisconnected(*c.Recovery); e != nil {
			return e
		}
		if e = t.StartDisconnected(ctx, *c.Recovery); e == nil {
			result, e = t.PromoteAndVerify(ctx, *c.Recovery)
		}
		if e != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
			defer stop()
			_ = t.Stop(cleanup, c.Recovery.DataDir)
		}
	case "stop":
		if c.Recovery == nil {
			return errors.New("recovery configuration required")
		}
		if e = physical.ValidateRecoveryPlan(*c.Recovery); e != nil {
			return e
		}
		e = t.Stop(ctx, c.Recovery.DataDir)
		result = map[string]bool{"stopped": e == nil}
	default:
		return errors.New("unknown physical command")
	}
	if e != nil {
		return e
	}
	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	return out.Encode(result)
}
