//go:build linux

package lease

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// BootClock is shared by processes and includes time spent in system suspend.
// Its values are meaningful only within the returned Linux boot identity.
func BootClock() (string, int64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return "", 0, err
	}
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", 0, err
	}
	id := strings.TrimSpace(string(b))
	if len(id) != 36 || ts.Sec < 0 || ts.Sec > 1<<32 {
		return "", 0, errors.New("invalid Linux boot clock")
	}
	return id, ts.Nano(), nil
}
