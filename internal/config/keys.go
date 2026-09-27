package config

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"
)

func PrivateText(path string) (string, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		return "", errors.New("configuration secret must be a private regular file")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(b)), nil
}
func Key(path string, size int) ([]byte, error) {
	text, e := PrivateText(path)
	if e != nil {
		return nil, e
	}
	b, e := base64.StdEncoding.DecodeString(text)
	if e != nil || len(b) != size {
		return nil, errors.New("invalid configured key size")
	}
	return b, nil
}
