//go:build !linux

package lease

import "errors"

func BootClock() (string, int64, error) {
	return "", 0, errors.New("runtime lease supervision requires Linux CLOCK_BOOTTIME")
}
