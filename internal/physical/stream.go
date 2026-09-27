package physical

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var slotPattern = regexp.MustCompile(`^pgws_[a-f0-9]{32}_g[1-9][0-9]*$`)

// ReserveSlot refuses an unbounded source retention configuration and never
// adopts an existing slot based on its name. The host persists reservation
// intent before this call and owns subsequent cleanup/reconciliation.
func (s Source) ReserveSlot(ctx context.Context, name string, budget int64) error {
	if !slotPattern.MatchString(name) || budget < 32<<20 || s.ExpectedSystemID == "" {
		return errors.New("invalid slot reservation")
	}
	conn, err := s.ConnectAdmin(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var system string
	var recovering bool
	if err = conn.QueryRow(ctx, `SELECT (pg_control_system()).system_identifier::text,pg_is_in_recovery()`).Scan(&system, &recovering); err != nil || system != s.ExpectedSystemID || recovering {
		return errors.New("slot source identity changed")
	}
	var limit int64
	if err = conn.QueryRow(ctx, `SELECT pg_size_bytes(current_setting('max_slot_wal_keep_size'))`).Scan(&limit); err != nil {
		return safeError("slot retention admission")
	}
	if limit < 0 || limit > budget {
		return errors.New("source max_slot_wal_keep_size must be finite and within its approved retention budget")
	}
	_, err = conn.Exec(ctx, `SELECT pg_create_physical_replication_slot($1,true)`, name)
	if err != nil {
		return safeError("exclusive slot reservation")
	}
	return nil
}
func (s Source) SlotPressure(ctx context.Context, name string) (int64, bool, error) {
	if !slotPattern.MatchString(name) || s.ExpectedSystemID == "" {
		return 0, false, errors.New("invalid owned slot")
	}
	conn, err := s.ConnectAdmin(ctx)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close(context.Background())
	var system string
	if err = conn.QueryRow(ctx, `SELECT (pg_control_system()).system_identifier::text`).Scan(&system); err != nil || system != s.ExpectedSystemID {
		return 0, false, errors.New("slot source identity changed")
	}
	var retained int64
	var lost bool
	err = conn.QueryRow(ctx, `SELECT coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(),restart_lsn),0)::bigint,wal_status='lost' OR invalidation_reason IS NOT NULL FROM pg_replication_slots WHERE slot_name=$1 AND slot_type='physical'`, name).Scan(&retained, &lost)
	if err != nil {
		return 0, false, safeError("owned slot pressure")
	}
	return retained, lost, nil
}
func (s Source) DropSlot(ctx context.Context, name string) error {
	if !slotPattern.MatchString(name) {
		return errors.New("invalid owned slot")
	}
	if s.ExpectedSystemID == "" {
		return errors.New("owned slot source identity required")
	}
	conn, err := s.ConnectAdmin(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	var system string
	if err = conn.QueryRow(ctx, `SELECT (pg_control_system()).system_identifier::text`).Scan(&system); err != nil || system != s.ExpectedSystemID {
		return errors.New("owned slot source identity changed")
	}
	var active bool
	if err = conn.QueryRow(ctx, `SELECT coalesce(bool_or(active),false) FROM pg_replication_slots WHERE slot_name=$1`, name).Scan(&active); err != nil || active {
		return errors.New("owned slot is active or unavailable")
	}
	_, err = conn.Exec(ctx, `SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots WHERE slot_name=$1 AND slot_type='physical' AND NOT active`, name)
	if err != nil {
		return safeError("owned slot cleanup")
	}
	return nil
}

func (t Tools) PrepareStreaming(r Recovery, s Source, slot string) error {
	if !slotPattern.MatchString(slot) {
		return errors.New("invalid owned slot")
	}
	if err := t.PrepareDisconnected(r); err != nil {
		return err
	}
	s = t.transferSource(s)
	if _, err := s.environment(r.ControlDir); err != nil {
		return err
	}
	q := url.Values{"host": {s.Host}, "port": {strconv.Itoa(int(s.Port))}, "passfile": {filepath.Join(r.ControlDir, "source.pgpass")}, "application_name": {"pgws-baseline"}, "connect_timeout": {"5"}, "sslmode": {"verify-full"}}
	if filepath.IsAbs(s.Host) {
		q.Set("sslmode", "disable")
	} else {
		q.Set("hostaddr", s.ApprovedAddresses[0])
		q.Set("sslrootcert", "system")
	}
	if s.RootCertificate != "" {
		q.Set("sslrootcert", s.RootCertificate)
	}
	u := url.URL{Scheme: "postgresql", User: url.User(s.User), RawQuery: q.Encode()}
	escape := func(s string) string { return strings.NewReplacer(`\`, `\\`, "'", "''").Replace(s) }
	f, err := os.OpenFile(filepath.Join(r.ControlDir, "postgresql.conf"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(f, "\nprimary_conninfo = '%s'\nprimary_slot_name = '%s'\n", escape(u.String()), slot)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// WaitReplay obtains a conservative source lower bound before storage capture.
// It is used on the established baseline, never as a clone promotion gate.
func WaitReplay(ctx context.Context, baseline Source, barrier Barrier) (string, error) {
	wanted, err := ParseLSN(barrier.LSN)
	if err != nil {
		return "", err
	}
	for {
		conn, err := baseline.ConnectPrivateAdmin(ctx)
		if err == nil {
			var system string
			var recovery bool
			var timeline int64
			var replay *string
			err = conn.QueryRow(ctx, `SELECT (pg_control_system()).system_identifier::text,pg_is_in_recovery(),pg_last_wal_replay_lsn()::text,coalesce((SELECT nullif(received_tli,0) FROM pg_stat_wal_receiver),(pg_control_checkpoint()).timeline_id)`).Scan(&system, &recovery, &replay, &timeline)
			conn.Close(context.Background())
			if err == nil && (!recovery || system != barrier.SystemID || timeline != barrier.Timeline) {
				return "", errors.New("baseline source identity mismatch")
			}
			if err == nil && replay != nil {
				actual, e := ParseLSN(*replay)
				if e == nil && actual >= wanted {
					return *replay, nil
				}
			}
		}
		if err = wait(ctx, 50*time.Millisecond); err != nil {
			return "", err
		}
	}
}
