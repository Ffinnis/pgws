package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"pgws/internal/config"
	"pgws/internal/control"
	"pgws/internal/hostclient"
)

func readRecoveryJSON(path string, target any) error {
	text, err := config.PrivateText(path)
	if err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid private recovery document")
	}
	return nil
}

// This command runs before opening any management connection. The fresh key
// and epoch cannot come from a restored database or its backup manifest.
func initRecovery(args []string) error {
	f := flag.NewFlagSet("recovery-init", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dir := f.String("directory", "", "new private output directory")
	hosts := f.String("hosts", "", "comma-separated exhaustive host inventory")
	operator := f.String("operator", "", "current operator identity")
	restored := f.String("restored-epoch", "", "expected database epoch when restoring a backup older than the current host authority")
	if f.Parse(args) != nil || f.NArg() != 0 || !filepath.IsAbs(*dir) || filepath.Clean(*dir) != *dir {
		return errors.New("recovery-init requires --directory ABSOLUTE_NEW_DIRECTORY --hosts HOST[,HOST] --operator ID")
	}
	key, err := config.Key(os.Getenv("PGWS_AUTHORITY_KEY_FILE"), ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(private)
	hostList := strings.Split(*hosts, ",")
	sort.Strings(hostList)
	plan := control.RecoveryPlan{Epoch: control.ID(), Previous: os.Getenv("PGWS_AUTHORITY_EPOCH"), Restored: *restored, PublicKey: public, PreviousKey: key, Hosts: hostList, Operator: *operator, CreatedAt: time.Now().UTC()}
	if err = plan.Validate(); err != nil {
		return err
	}
	if err = os.Mkdir(*dir, 0700); err != nil {
		return errors.New("recovery output directory must be new")
	}
	planData, _ := json.MarshalIndent(plan, "", "  ")
	files := []struct {
		name string
		data []byte
	}{{"plan.json", planData}, {"signing.key", []byte(base64.StdEncoding.EncodeToString(private))}, {"authority.key", []byte(base64.StdEncoding.EncodeToString(public))}}
	for _, item := range files {
		file, e := os.OpenFile(filepath.Join(*dir, item.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = file.Write(item.data)
		if e == nil {
			e = file.Sync()
		}
		closeErr := file.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	for _, path := range []string{*dir, filepath.Dir(*dir)} {
		d, e := os.Open(path)
		if e != nil {
			return e
		}
		e = d.Sync()
		d.Close()
		if e != nil {
			return e
		}
	}
	return json.NewEncoder(os.Stdout).Encode(control.Object{"authority_epoch": plan.Epoch, "plan_hash": plan.Hash(), "plan_file": filepath.Join(*dir, "plan.json"), "signing_key_file": filepath.Join(*dir, "signing.key"), "authority_key_file": filepath.Join(*dir, "authority.key")})
}

func recoveryCommand(ctx context.Context, pool *pgxpool.Pool, command string, args []string) error {
	if len(args) < 1 || len(args) > 2 || command == "recovery-begin" && len(args) != 1 || command == "recovery-finish" && len(args) != 2 {
		return errors.New("usage: pgwsd recovery-begin PLAN.json | pgwsd recovery-finish PLAN.json HOST_CHANNELS.json")
	}
	var plan control.RecoveryPlan
	if err := readRecoveryJSON(args[0], &plan); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if command == "recovery-begin" {
		if err := control.BeginRecovery(ctx, pool, plan); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(control.Object{"authority_epoch": plan.Epoch, "reconciled": false, "plan_hash": plan.Hash()})
	}
	if command != "recovery-finish" {
		return errors.New("unknown recovery command")
	}
	var channels []struct {
		Host      string `json:"host"`
		Socket    string `json:"socket"`
		TokenFile string `json:"token_file"`
	}
	if err := readRecoveryJSON(args[1], &channels); err != nil {
		return err
	}
	hosts := map[string]control.RecoveryHost{}
	for _, channel := range channels {
		if hosts[channel.Host] != nil {
			return errors.New("duplicate recovery host channel")
		}
		token, err := config.PrivateText(channel.TokenFile)
		if err != nil {
			return err
		}
		hosts[channel.Host] = hostclient.Client{Socket: channel.Socket, Token: token}
	}
	if err := control.FinishRecovery(ctx, pool, plan, hosts); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(control.Object{"authority_epoch": plan.Epoch, "reconciled": true, "old_generations": "quarantined", "plan_hash": plan.Hash()})
}
