// pgws-features emits bounded sparse vectors from NDJSON ColumnProfile records.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"pgws/internal/privacy/features"
)

func run(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), features.MaxProfileBytes+1)
	encoder := json.NewEncoder(out)
	line := 0
	for scanner.Scan() {
		line++
		p, err := features.Decode(scanner.Bytes())
		if err != nil {
			return fmt.Errorf("profile %d rejected: %w", line, err)
		}
		vector, err := features.Extract(p)
		if err != nil {
			return fmt.Errorf("profile %d rejected: %w", line, err)
		}
		if err = encoder.Encode(vector); err != nil {
			return errors.New("feature output unavailable")
		}
	}
	if scanner.Err() != nil {
		return errors.New("profile input unavailable or exceeds byte limit")
	}
	return nil
}
func main() {
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: pgws-features < profiles.ndjson > vectors.ndjson")
		os.Exit(1)
	}
	if err := run(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
