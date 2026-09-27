// pgws-model-pack signs an explicit operator-reviewed local candidate.
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"pgws/internal/config"
	"pgws/internal/privacy/classify"
)

func readBounded(path string, limit int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("model candidate input unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil, errors.New("model candidate input exceeds size limit")
	}
	return data, nil
}
func run(args []string) error {
	if len(args) != 5 {
		return errors.New("usage: pgws-model-pack MANIFEST WEIGHTS BIAS PRIVATE_SIGNING_KEY NEW_OUTPUT")
	}
	metadata, err := readBounded(args[0], 64<<10)
	if err != nil {
		return err
	}
	manifest, err := classify.DecodeManifest(metadata)
	if err != nil {
		return err
	}
	weights, err := readBounded(args[1], classify.WeightBytes)
	if err != nil {
		return err
	}
	bias, err := readBounded(args[2], classify.BiasBytes)
	if err != nil {
		return err
	}
	key, err := config.Key(args[3], ed25519.PrivateKeySize)
	if err != nil {
		return errors.New("private classifier signing key unavailable")
	}
	defer clear(key)
	bundle, err := classify.Pack(manifest, weights, bias, key)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(args[4], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("model output exists or cannot be created")
	}
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(args[4])
		}
	}()
	if _, err = file.Write(bundle); err != nil {
		return errors.New("model output write failed")
	}
	if err = file.Sync(); err != nil {
		return errors.New("model output sync failed")
	}
	if err = file.Close(); err != nil {
		return errors.New("model output close failed")
	}
	dir, err := os.Open(filepath.Dir(args[4]))
	if err != nil {
		return errors.New("model output directory unavailable")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("model output directory sync failed")
	}
	ok = true
	return nil
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
