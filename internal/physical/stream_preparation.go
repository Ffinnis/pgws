package physical

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type streamingPlan struct {
	Recovery       Recovery
	Source         Source
	Slot           string
	UpstreamSocket string
}

// ResumeStreamingPreparation is used only before the host durably records that
// PostgreSQL may start. A partial configuration is rebuilt; a complete one is
// bound to the exact recovery generation, approved source and owned slot.
func (t Tools) ResumeStreamingPreparation(r Recovery, s Source, slot string) error {
	if err := validateRecovery(r); err != nil {
		return err
	}
	if !slotPattern.MatchString(slot) || s.ExpectedSystemID != r.Barrier.SystemID {
		return errors.New("streaming preparation source or slot mismatch")
	}
	plan := streamingPlan{r, s, slot, t.UpstreamSocket}
	path := filepath.Join(r.ControlDir, "streaming-plan.json")
	if data, err := os.ReadFile(path); err == nil {
		var existing streamingPlan
		if json.Unmarshal(data, &existing) != nil || !reflect.DeepEqual(existing, plan) {
			return errors.New("streaming preparation differs from its immutable plan")
		}
		return ValidateRecoveryPlan(r)
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := os.Lstat(filepath.Join(r.DataDir, "postmaster.pid")); !os.IsNotExist(err) {
		return errors.New("incomplete streaming preparation may belong to a running postmaster")
	}
	if _, err := os.Lstat(filepath.Join(r.ControlDir, "recovery-plan.json")); err == nil {
		if err = ValidateRecoveryPlan(r); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(r.ControlDir)
	if err == nil {
		for _, entry := range entries {
			switch entry.Name() {
			case "postgresql.conf", "hba.conf", "ident.conf", "recovery-plan.json", "source.pgpass":
			default:
				if !strings.HasPrefix(entry.Name(), ".receipt-") {
					return errors.New("unknown object in partial streaming controls")
				}
			}
			if !entry.Type().IsRegular() {
				return errors.New("partial streaming controls contain a non-file")
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
	if err = t.PrepareStreaming(r, s, slot); err != nil {
		return err
	}
	return writeJSON(path, plan)
}
