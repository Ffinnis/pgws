package logical

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"

	"pgws/internal/config"
	"pgws/internal/physical"
)

// AppliedReceipt is a historical lower bound for confirmed target commits.
// It survives target downtime but cannot establish current slot ownership or
// authorize deletion of source objects. Only the ingestion owner writes it.
type AppliedReceipt struct {
	Format        string `json:"format"`
	OwnershipHash string `json:"ownership_sha256"`
	AppliedLSN    string `json:"applied_lsn"`
}

func ownershipHash(owned SlotOwnership) string {
	owned.ObservedAt = owned.ObservedAt.UTC()
	b, _ := json.Marshal(owned)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

// ReadApplied reads the atomically published sibling of an ownership receipt.
// An absent receipt means no external proof of a committed seed, not LSN zero.
func ReadApplied(ownershipPath string, owned SlotOwnership) (AppliedReceipt, error) {
	var receipt AppliedReceipt
	if !owned.valid() {
		return receipt, errors.New("invalid logical progress ownership")
	}
	text, err := config.PrivateText(ownershipPath + ".applied")
	if err != nil || len(text) > 1024 || json.Unmarshal([]byte(text), &receipt) != nil {
		return AppliedReceipt{}, errors.New("private logical progress receipt unavailable")
	}
	canonical, _ := json.Marshal(receipt)
	position, e := physical.ParseLSN(receipt.AppliedLSN)
	seed, _ := physical.ParseLSN(owned.SeedLSN)
	if text != string(canonical) || receipt.Format != "pgws.logical-applied.v1" || receipt.OwnershipHash != ownershipHash(owned) || e != nil || position < seed {
		return AppliedReceipt{}, errors.New("logical progress receipt differs from confirmed ownership")
	}
	return receipt, nil
}

// PersistApplied fsyncs the receipt and containing directory before ACK. Older
// replay positions retain the existing high water. A separate nonblocking lock
// prevents two processes from overwriting newer progress with an older receipt.
func PersistApplied(ownershipPath, position string) error {
	directory, err := ownershipDirectory(ownershipPath)
	if err != nil {
		return err
	}
	lock, err := os.OpenFile(ownershipPath+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return errors.New("logical progress lock unavailable")
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("logical progress lock is unsafe or held")
	}
	owned, err := ReadSlotOwnership(ownershipPath)
	if err != nil {
		return err
	}
	lsn, err := physical.ParseLSN(position)
	seed, _ := physical.ParseLSN(owned.SeedLSN)
	if err != nil || lsn < seed {
		return errors.New("logical progress precedes its consistent seed")
	}
	path := ownershipPath + ".applied"
	if _, err = os.Lstat(path); err == nil {
		prior, e := ReadApplied(ownershipPath, owned)
		if e != nil {
			return e
		}
		old, _ := physical.ParseLSN(prior.AppliedLSN)
		if old >= lsn {
			// A previous caller may have failed after rename but before directory
			// fsync. Repeat that durability boundary even for an exact retry.
			return syncProgressDirectory(directory)
		}
	} else if !os.IsNotExist(err) {
		return errors.New("logical progress destination unavailable")
	}
	receipt := AppliedReceipt{Format: "pgws.logical-applied.v1", OwnershipHash: ownershipHash(owned), AppliedLSN: position}
	data, _ := json.Marshal(receipt)
	f, err := os.CreateTemp(directory, ".logical-applied-")
	if err != nil {
		return errors.New("logical progress temporary file unavailable")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return errors.New("logical progress write failed")
	}
	if err = f.Sync(); err != nil {
		return errors.New("logical progress sync failed")
	}
	if err = f.Close(); err != nil {
		return errors.New("logical progress close failed")
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return errors.New("logical progress publish failed")
	}
	return syncProgressDirectory(directory)
}

func syncProgressDirectory(directory string) error {
	dir, err := os.Open(directory)
	if err != nil {
		return errors.New("logical progress directory unavailable")
	}
	defer dir.Close()
	if err = dir.Sync(); err != nil {
		return errors.New("logical progress directory sync failed")
	}
	return nil
}
