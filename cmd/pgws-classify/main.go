// pgws-classify produces review-only proposals from an operator-signed model.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"pgws/internal/config"
	"pgws/internal/privacy/classify"
	"pgws/internal/privacy/features"
)

func run(ctx context.Context, args []string, in io.Reader, out io.Writer) error {
	if len(args) != 2 {
		return errors.New("usage: pgws-classify SIGNED_MODEL PINNED_PUBLIC_KEY < profiles.ndjson")
	}
	key, err := config.Key(args[1], ed25519.PublicKeySize)
	if err != nil {
		return errors.New("pinned classifier release key unavailable")
	}
	file, err := os.Open(args[0])
	if err != nil {
		return errors.New("classifier model unavailable; automatic discovery disabled")
	}
	model, err := classify.Load(file, key)
	file.Close()
	if err != nil {
		return err
	}
	scan := bufio.NewScanner(in)
	scan.Buffer(make([]byte, 4096), features.MaxProfileBytes+1)
	encoder := json.NewEncoder(out)
	for scan.Scan() {
		profile, err := features.Decode(scan.Bytes())
		if err != nil {
			return err
		}
		vector, err := features.Extract(profile)
		if err != nil {
			return err
		}
		proposal, err := model.Score(ctx, vector)
		if err != nil {
			return err
		}
		if err = encoder.Encode(proposal); err != nil {
			return errors.New("classifier output unavailable")
		}
	}
	if scan.Err() != nil {
		return errors.New("classifier profile unavailable or exceeds byte limit")
	}
	return ctx.Err()
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
