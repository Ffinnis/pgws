package config

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// ListenPrivateUnix requires the caller to hold its exclusive process lock.
// Only a refused socket owned by this UID can be removed after a crash.
func ListenPrivateUnix(path string) (net.Listener, error) {
	info, err := os.Lstat(path)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != uint32(os.Geteuid()) {
			return nil, errors.New("existing control path is not an owned socket")
		}
		conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, errors.New("control socket is already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) && !errors.Is(dialErr, os.ErrNotExist) {
			return nil, errors.New("existing control socket state is uncertain")
		}
		if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return net.Listen("unix", path)
}
