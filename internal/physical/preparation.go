package physical

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ResumePreparation is only for an unpublished clone for which the host has
// not attempted OCI startup. A complete plan is immutable. Before publication
// of that plan, only known partial control files may be discarded and rebuilt.
func (t Tools) ResumePreparation(r Recovery) error {
	if err := validateRecovery(r); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(r.ControlDir, "recovery-plan.json")); err == nil {
		return ValidateRecoveryPlan(r)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(r.DataDir, "postmaster.pid")); !os.IsNotExist(err) {
		return errors.New("partial preparation may belong to a running postmaster")
	}
	entries, err := os.ReadDir(r.ControlDir)
	if err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if name != "postgresql.conf" && name != "hba.conf" && name != "ident.conf" && !strings.HasPrefix(name, ".receipt-") {
				return errors.New("unknown object in partial recovery controls")
			}
			if !entry.Type().IsRegular() {
				return errors.New("partial recovery controls contain a non-file")
			}
		}
		for _, entry := range entries {
			if err = os.Remove(filepath.Join(r.ControlDir, entry.Name())); err != nil {
				return err
			}
		}
		if err = os.Remove(r.ControlDir); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return t.PrepareDisconnected(r)
}
