package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"pgws/internal/control"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: pgws create|get|action|delete|baselines|usage|source|source-get|source-action|barrier|credentials|operation|wait [flags]")
	}
	command := os.Args[1]
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	id := f.String("id", "", "resource ID")
	file := f.String("file", "", "JSON request file, or - for stdin")
	key := f.String("key", "", "stable idempotency key for this request")
	generation := f.Int64("generation", 0, "expected generation for delete")
	limit := f.Int("limit", 100, "page size for baselines or usage")
	cursor := f.String("cursor", "", "pagination cursor for baselines or usage")
	timeout := f.Duration("timeout", 30*time.Second, "request or wait deadline")
	if e := f.Parse(os.Args[2:]); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	project := os.Getenv("PGWS_PROJECT_ID")
	token := os.Getenv("PGWS_TOKEN")
	if !control.ValidID(project) || token == "" {
		return errors.New("PGWS_PROJECT_ID and PGWS_TOKEN are required")
	}
	base := os.Getenv("PGWS_URL")
	if base == "" {
		base = "http://127.0.0.1:8080"
	}
	u, e := url.Parse(base)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid PGWS_URL")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return errors.New("use HTTPS or a loopback HTTP address")
		}
	}
	path := "/v1/projects/" + project
	method := "GET"
	switch command {
	case "baselines", "usage":
		path += "/" + command
		path += "?" + url.Values{"limit": {fmt.Sprint(*limit)}}.Encode()
		if *cursor != "" {
			path += "&" + url.Values{"cursor": {*cursor}}.Encode()
		}
	case "create":
		method = "POST"
		path += "/workspaces"
	case "source":
		method = "POST"
		path += "/sources"
	case "operation", "wait":
		path += "/operations/" + *id
	case "get", "action", "delete", "credentials":
		path += "/workspaces/" + *id
		if command == "action" {
			method = "POST"
			path += "/actions"
		}
		if command == "credentials" {
			method = "POST"
			path += "/credentials"
		}
		if command == "delete" {
			method = "DELETE"
			if *generation < 1 {
				return errors.New("--generation is required")
			}
			path += fmt.Sprintf("?expected_generation=%d", *generation)
		}
	case "source-get":
		path += "/sources/" + *id
	case "source-action":
		method = "POST"
		path += "/sources/" + *id + "/actions"
	case "barrier":
		method = "POST"
		path += "/sources/" + *id + "/barriers"
	default:
		return errors.New("unknown command")
	}
	if command != "baselines" && command != "usage" && command != "create" && command != "source" && !control.ValidID(*id) {
		return errors.New("--id must be a UUID")
	}
	var body []byte
	if method == "POST" {
		if *file == "" {
			return errors.New("--file is required")
		}
		if *file == "-" {
			body, e = io.ReadAll(io.LimitReader(os.Stdin, 1<<20+1))
		} else {
			body, e = os.ReadFile(*file)
		}
		if e != nil {
			return errors.New("cannot read request file")
		}
		if len(body) > 1<<20 || !json.Valid(body) {
			return errors.New("request must be valid JSON of at most 1 MiB")
		}
	}
	if method != "GET" && *key == "" {
		return errors.New("--key is required; reuse it when retrying the same request")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, bytes.NewReader(body))
		if e != nil {
			return errors.New("invalid request URL")
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		if *key != "" {
			req.Header.Set("Idempotency-Key", *key)
		}
		resp, e := client.Do(req)
		if e != nil {
			return errors.New("request failed or deadline exceeded")
		}
		raw, e := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if e != nil {
			return errors.New("response read failed")
		}
		if resp.StatusCode >= 300 {
			os.Stdout.Write(raw)
			return fmt.Errorf("API returned HTTP %d", resp.StatusCode)
		}
		if command != "wait" {
			_, e = os.Stdout.Write(raw)
			return e
		}
		var op struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(raw, &op) != nil {
			return errors.New("invalid operation response")
		}
		switch op.Status {
		case "succeeded":
			_, e = os.Stdout.Write(raw)
			return e
		case "failed", "cancelled":
			os.Stdout.Write(raw)
			return errors.New("operation " + op.Status)
		case "queued", "running":
		default:
			return errors.New("unknown operation status")
		}
		select {
		case <-ctx.Done():
			return errors.New("wait deadline exceeded; operation remains recorded")
		case <-time.After(time.Second):
		}
	}
}
