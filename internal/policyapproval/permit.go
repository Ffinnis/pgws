package policyapproval

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"pgws/internal/config"
	"pgws/internal/lease"
)

// Permit is trusted host configuration, stored outside all container mounts.
// Runtime is the digest of the exact container ID and immutable specification.
type Permit struct {
	Binding   Binding `json:"binding"`
	PublicKey []byte  `json:"public_key"`
	Path      string  `json:"receipt_file"`
	Runtime   string  `json:"runtime_sha256"`
}

type receipt struct {
	Runtime    string    `json:"runtime_sha256"`
	Token      string    `json:"token"`
	ReceivedAt time.Time `json:"received_at"`
	Boot       string    `json:"boot_id"`
	ReceivedNS int64     `json:"received_ns"`
	DeadlineNS int64     `json:"deadline_ns"`
}

// Validate checks host-owned configuration only. It does not assert that a
// receipt exists or that its signed permission is current.
func (p Permit) Validate() error { return p.valid() }

func (p Permit) valid() error {
	if !filepath.IsAbs(p.Path) || filepath.Clean(p.Path) != p.Path || !digest.MatchString(p.Runtime) || len(p.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid host policy permit configuration")
	}
	info, err := os.Lstat(filepath.Dir(p.Path))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("policy receipt requires a private host directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("policy receipt directory has a different owner")
	}
	return nil
}

func (p Permit) read() (receipt, error) {
	var r receipt
	text, err := config.PrivateText(p.Path)
	if err != nil || json.Unmarshal([]byte(text), &r) != nil {
		return r, errors.New("policy receipt unavailable")
	}
	canonical, _ := json.Marshal(r)
	if string(canonical) != text {
		return r, errors.New("policy receipt encoding differs")
	}
	return r, nil
}

func (p Permit) check(r receipt, boot string, ticks int64) (Claims, error) {
	c, err := Verify(p.PublicKey, r.Token, p.Binding, r.ReceivedAt)
	maximum := c.ExpiresAt.Add(-5 * time.Second).Sub(r.ReceivedAt)
	if err != nil || r.Runtime != p.Runtime || r.Boot == "" || r.Boot != boot || ticks < r.ReceivedNS || r.ReceivedNS < 0 || r.DeadlineNS <= r.ReceivedNS || r.DeadlineNS-r.ReceivedNS > int64(maximum) || ticks >= r.DeadlineNS {
		return Claims{}, errors.New("policy runtime permission expired or differs")
	}
	return c, nil
}

// Check uses CLOCK_BOOTTIME, so wall-clock rollback, suspend and process restart
// cannot extend an installed approval. A host reboot requires a new candidate.
func (p Permit) Check() error {
	if err := p.valid(); err != nil {
		return err
	}
	r, err := p.read()
	if err != nil {
		return err
	}
	boot, ticks, err := lease.BootClock()
	if err != nil {
		return err
	}
	_, err = p.check(r, boot, ticks)
	return err
}

// Install serializes renewals and refuses replay or renewal after the previous
// permission expired. Only strictly newer authority decisions can extend it.
// The caller must enforce terminal runtime stops before attempting installation.
func (p Permit) Install(token string) error {
	if err := p.valid(); err != nil {
		return err
	}
	fd, err := unix.Open(p.Path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return errors.New("policy renewal lock unavailable")
	}
	f := os.NewFile(uintptr(fd), p.Path+".lock")
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("invalid policy renewal lock")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("policy renewal already in progress")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	boot, ticks, err := lease.BootClock()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	claims, err := Verify(p.PublicKey, token, p.Binding, now)
	if err != nil {
		return err
	}
	r := receipt{Runtime: p.Runtime, Token: token, ReceivedAt: now, Boot: boot, ReceivedNS: ticks, DeadlineNS: ticks + int64(claims.ExpiresAt.Add(-5*time.Second).Sub(now))}
	var previous *receipt
	if _, err = os.Lstat(p.Path); err == nil {
		old, e := p.read()
		if e != nil {
			return e
		}
		previous = &old
		prior, e := p.check(old, boot, ticks)
		if e != nil {
			return e
		}
		if old.Token == token {
			return syncPermitDirectory(p.Path)
		}
		if !claims.IssuedAt.After(prior.IssuedAt) {
			return errors.New("policy renewal is older than installed decision")
		}
	} else if !os.IsNotExist(err) {
		return errors.New("policy receipt unavailable")
	}
	data, _ := json.Marshal(r)
	tmp, err := os.CreateTemp(filepath.Dir(p.Path), ".policy-permit-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	// Slow disk I/O must not publish a renewal after the old grant expired.
	currentBoot, currentTicks, e := lease.BootClock()
	if e != nil {
		return e
	}
	if _, e = p.check(r, currentBoot, currentTicks); e != nil {
		return e
	}
	if previous != nil {
		if _, e = p.check(*previous, currentBoot, currentTicks); e != nil {
			return e
		}
	}
	if err = os.Rename(tmp.Name(), p.Path); err != nil {
		return err
	}
	return syncPermitDirectory(p.Path)
}
func syncPermitDirectory(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
