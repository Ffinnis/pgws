package logical

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"pgws/internal/config"
	"pgws/internal/control"
	"pgws/internal/physical"
)

// SlotOwnership records a confirmed source-side creation, not seed completion
// or current authority to delete. Supervisors must also fence the owner, verify
// current source/slot identity and reconcile any intervening removal.
type SlotOwnership struct {
	Format         string    `json:"format"`
	Source         Identity  `json:"source"`
	Database       string    `json:"database"`
	Slot           string    `json:"slot"`
	Publication    string    `json:"publication"`
	PublicationOID uint32    `json:"publication_oid"`
	Contract       string    `json:"target_contract"`
	SeedLSN        string    `json:"seed_lsn"`
	ObservedAt     time.Time `json:"observed_at"`
}

func (s SlotOwnership) valid() bool {
	slot, publication, namesErr := sourceObjectNames(s.Source)
	system, e1 := strconv.ParseUint(s.Source.SystemID, 10, 64)
	position, e2 := physical.ParseLSN(s.SeedLSN)
	digest, e3 := hex.DecodeString(s.Contract)
	return s.Format == "pgws.logical-slot.v1" && s.PublicationOID > 0 && control.ValidID(s.Source.Source) && s.Source.Epoch > 0 && s.Source.Timeline > 0 && e1 == nil && system > 0 && e2 == nil && position > 0 && e3 == nil && len(digest) == 32 && hex.EncodeToString(digest) == s.Contract && namesErr == nil && s.Slot == slot && s.Publication == publication && len(s.Database) > 0 && len(s.Database) <= 63 && utf8.ValidString(s.Database) && !strings.ContainsRune(s.Database, 0) && !s.ObservedAt.IsZero()
}

func ReadSlotOwnership(path string) (SlotOwnership, error) {
	text, err := config.PrivateText(path)
	if err != nil || len(text) > 4096 {
		return SlotOwnership{}, errors.New("private logical ownership receipt unavailable")
	}
	var receipt SlotOwnership
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF || !receipt.valid() {
		return SlotOwnership{}, errors.New("invalid logical slot ownership receipt")
	}
	// Receipts are written only by this canonical writer. Requiring exact bytes
	// also rejects duplicate/case-folded keys and altered nested JSON fields.
	canonical, _ := json.Marshal(receipt)
	if text != string(canonical) {
		return SlotOwnership{}, errors.New("noncanonical logical slot ownership receipt")
	}
	return receipt, nil
}

// CheckSlotOwnershipDestination rejects a stale receipt or invalid directory
// before CLI seed initialization has any target/source side effect. The atomic
// writer repeats these checks because this preflight cannot reserve the path.
func CheckSlotOwnershipDestination(path string) error {
	if _, err := ownershipDirectory(path); err != nil {
		return err
	}
	for _, suffix := range []string{"", ".applied", ".lock"} {
		if _, err := os.Lstat(path + suffix); !os.IsNotExist(err) {
			return errors.New("logical ownership destination exists or is unavailable; reconcile before seeding")
		}
	}
	return nil
}

func ownershipDirectory(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("invalid logical ownership receipt destination")
	}
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", errors.New("logical ownership requires an existing private directory")
	}
	return directory, nil
}

// WriteSlotOwnership atomically creates a mode-0600 receipt in an existing
// private directory. Exact retry is allowed; no other receipt is overwritten.
func WriteSlotOwnership(path string, receipt SlotOwnership) error {
	if !receipt.valid() {
		return errors.New("invalid logical ownership receipt destination")
	}
	receipt.ObservedAt = receipt.ObservedAt.UTC()
	directory, err := ownershipDirectory(path)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(receipt)
	f, err := os.CreateTemp(directory, ".slot-ownership-")
	if err != nil {
		return errors.New("logical ownership temporary file unavailable")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return errors.New("logical ownership receipt write failed")
	}
	if err = f.Sync(); err != nil {
		return errors.New("logical ownership receipt sync failed")
	}
	if err = f.Close(); err != nil {
		return errors.New("logical ownership receipt close failed")
	}
	if err = os.Link(f.Name(), path); err != nil {
		if !os.IsExist(err) {
			return errors.New("logical ownership receipt publish failed")
		}
		prior, e := ReadSlotOwnership(path)
		if e != nil {
			return e
		}
		old, _ := json.Marshal(prior)
		if !bytes.Equal(old, data) {
			return errors.New("logical slot ownership differs; explicit reconciliation required")
		}
	}
	dir, err := os.Open(directory)
	if err != nil {
		return errors.New("logical ownership directory unavailable")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("logical ownership directory sync failed")
	}
	return nil
}

func (c Connector) MatchSlotOwnership(receipt SlotOwnership) error {
	slot, publication, err := c.names()
	if err != nil {
		return err
	}
	contract, _ := c.Target.contract()
	if !receipt.valid() || receipt.Source != c.Target.Identity || receipt.Database != c.Source.Database || receipt.Slot != slot || receipt.Publication != publication || receipt.Contract != contract {
		return errors.New("logical ownership receipt differs from the configured generation")
	}
	return nil
}
