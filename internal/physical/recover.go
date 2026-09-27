package physical

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Recovery struct {
	DataDir    string            `json:"data_directory"`
	ControlDir string            `json:"control_directory"`
	SocketDir  string            `json:"socket_directory"`
	SourceUser string            `json:"source_user"`
	Barrier    Barrier           `json:"barrier"`
	Settings   map[string]string `json:"source_settings"`
}
type RecoveryEvidence struct {
	Identity
	ReplayedLSN       string    `json:"replayed_source_lsn"`
	Writable          bool      `json:"writable"`
	ObservedAt        time.Time `json:"observed_at"`
	EndpointPublished bool      `json:"endpoint_published"`
}

var safePath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)

func validateRecovery(r Recovery) error {
	paths := []string{r.DataDir, r.ControlDir, r.SocketDir}
	for i, path := range paths {
		if path == "/" || !safePath.MatchString(path) || filepath.Clean(path) != path {
			return errors.New("recovery paths must be canonical absolute paths without shell metacharacters")
		}
		for p := path; p != "/"; p = filepath.Dir(p) {
			info, err := os.Lstat(p)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("recovery path contains a non-directory or symlink")
			}
		}
		for j, other := range paths {
			if i != j && (path == other || strings.HasPrefix(path, other+"/")) {
				return errors.New("data, control and socket directories must be separate")
			}
		}
	}
	if _, err := ParseLSN(r.Barrier.LSN); err != nil {
		return err
	}
	system, err := strconv.ParseUint(r.Barrier.SystemID, 10, 64)
	if err != nil || system == 0 || r.Barrier.Timeline < 1 || r.SourceUser == "" {
		return errors.New("recovery source identity is required")
	}
	return nil
}

// ValidateRecoveryPlan binds process operations to the plan reserved before
// startup. The control directory belongs to a trusted local administrator.
func ValidateRecoveryPlan(r Recovery) error {
	if err := validateRecovery(r); err != nil {
		return err
	}
	path := filepath.Join(r.ControlDir, "recovery-plan.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 || info.Mode().Perm()&0077 != 0 {
		return errors.New("private recovery plan unavailable")
	}
	stored, err := LoadRecovery(path)
	if err != nil || !reflect.DeepEqual(stored, r) {
		return errors.New("recovery operation differs from reserved plan")
	}
	return nil
}

// PrepareDisconnected installs a closed, external configuration for a fresh
// private clone. Imported config chains and SQL authentication are not reused.
// No TCP port is opened. The caller must separately establish egress isolation.
func (t Tools) PrepareDisconnected(r Recovery) error {
	if e := validateRecovery(r); e != nil {
		return e
	}
	for _, path := range []string{r.DataDir, r.ControlDir, r.SocketDir} {
		if !safePath.MatchString(path) || filepath.Clean(path) != path {
			return errors.New("recovery paths must be absolute canonical paths without shell metacharacters")
		}
	}
	if r.ControlDir == r.DataDir || strings.HasPrefix(r.ControlDir, r.DataDir+"/") {
		return errors.New("control configuration must be outside clone data")
	}
	if _, e := ParseLSN(r.Barrier.LSN); e != nil {
		return e
	}
	for _, path := range []string{r.DataDir, filepath.Join(r.DataDir, "pg_wal"), filepath.Join(r.DataDir, "pg_tblspc")} {
		info, e := os.Lstat(path)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("clone must have ordinary internal storage directories")
		}
	}
	if entries, e := os.ReadDir(filepath.Join(r.DataDir, "pg_tblspc")); e != nil || len(entries) != 0 {
		return errors.New("external tablespaces are unsupported")
	}
	for _, name := range []string{"postmaster.pid", "recovery.signal"} {
		if _, e := os.Lstat(filepath.Join(r.DataDir, name)); !os.IsNotExist(e) {
			return errors.New("clone is not a fresh disconnected generation")
		}
	}
	version, e := os.ReadFile(filepath.Join(r.DataDir, "PG_VERSION"))
	if e != nil || strings.TrimSpace(string(version)) != "18" {
		return errors.New("clone must be PostgreSQL 18")
	}
	// Reserve controls exclusively: a second invocation cannot silently change
	// config underneath a running process. Recovery retries use the existing plan.
	if e = os.Mkdir(r.ControlDir, 0700); e != nil {
		return errors.New("recovery control directory must be new")
	}
	if e = os.MkdirAll(r.SocketDir, 0700); e != nil {
		return e
	}
	if e = os.Chmod(r.SocketDir, 0700); e != nil {
		return e
	}
	conf := fmt.Sprintf("data_directory = '%s'\nhba_file = '%s/hba.conf'\nident_file = '%s/ident.conf'\nlisten_addresses = ''\nunix_socket_directories = '%s'\nunix_socket_permissions = 0700\nport = 5432\nssl = off\nshared_buffers = '32MB'\nfsync = on\nfull_page_writes = on\nhot_standby = on\nhot_standby_feedback = off\nprimary_conninfo = ''\nprimary_slot_name = ''\nrestore_command = ''\narchive_mode = off\narchive_command = ''\narchive_library = ''\nshared_preload_libraries = ''\nsession_preload_libraries = ''\nlocal_preload_libraries = ''\n", r.DataDir, r.ControlDir, r.ControlDir, r.SocketDir)
	limits := map[string]int{"max_connections": 200, "max_prepared_transactions": 0, "max_locks_per_transaction": 1024, "max_wal_senders": 32, "max_worker_processes": 64}
	for _, name := range []string{"max_connections", "max_prepared_transactions", "max_locks_per_transaction", "max_wal_senders", "max_worker_processes"} {
		value, e := strconv.Atoi(r.Settings[name])
		if e != nil || value < 0 || value > limits[name] {
			return fmt.Errorf("recovery profile not admitted for %s", name)
		}
		conf += fmt.Sprintf("%s = %d\n", name, value)
	}
	for name, body := range map[string]string{"postgresql.conf": conf, "hba.conf": "local all all trust\nhost all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n", "ident.conf": ""} {
		if e = os.WriteFile(filepath.Join(r.ControlDir, name), []byte(body), 0600); e != nil {
			return e
		}
	}
	// auto.conf is always loaded even with an external config_file. Refuse
	// symlinks, then replace its contents before startup to remove imported hooks.
	auto := filepath.Join(r.DataDir, "postgresql.auto.conf")
	if info, e := os.Lstat(auto); e == nil && !info.Mode().IsRegular() {
		return errors.New("invalid imported auto configuration")
	}
	if e = os.WriteFile(auto, []byte("# PGWS disconnected recovery\n"), 0600); e != nil {
		return e
	}
	signal := filepath.Join(r.DataDir, "standby.signal")
	if info, e := os.Lstat(signal); e == nil && !info.Mode().IsRegular() {
		return errors.New("invalid standby signal")
	}
	if e = os.WriteFile(signal, nil, 0600); e != nil {
		return e
	}
	return writeJSON(filepath.Join(r.ControlDir, "recovery-plan.json"), r)
}
func (t Tools) StartDisconnected(ctx context.Context, r Recovery) error {
	if e := ValidateRecoveryPlan(r); e != nil {
		return e
	}
	if e := t.Require18(ctx); e != nil {
		return e
	}
	// The host may have lost the non-waiting start response. Process status
	// only suppresses a duplicate start; it is never a readiness proof.
	if t.run(ctx, "pg_ctl", nil, "-D", r.DataDir, "status") == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return t.run(ctx, "pg_ctl", nil, "-D", r.DataDir, "-l", filepath.Join(r.ControlDir, "postgres.log"), "-o", "-c config_file="+filepath.Join(r.ControlDir, "postgresql.conf"), "-W", "start")
}
func (t Tools) PromoteAndVerify(ctx context.Context, r Recovery) (RecoveryEvidence, error) {
	if e := ValidateRecoveryPlan(r); e != nil {
		return RecoveryEvidence{}, e
	}
	// pg_ctl's non-waiting start and promotion never gate on pg_isready/standby
	// SQL. Repeated promotion requests are harmless while startup reaches recovery.
	for {
		if e := t.run(ctx, "pg_ctl", nil, "-D", r.DataDir, "-t", "1", "promote"); e == nil {
			break
		}
		// An earlier promotion may have completed before its caller died.
		// SQL on a standby is optional here, never a prerequisite to promote.
		check, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		conn, err := (Source{Host: r.SocketDir, Port: 5432, User: r.SourceUser, Database: "postgres"}).ConnectPrivateAdmin(check)
		promoted := false
		if err == nil {
			var recovery bool
			if conn.QueryRow(check, "SELECT pg_is_in_recovery()").Scan(&recovery) == nil {
				promoted = !recovery
			}
			conn.Close(context.Background())
		}
		cancel()
		if promoted {
			break
		}
		if e := wait(ctx, 50*time.Millisecond); e != nil {
			return RecoveryEvidence{}, e
		}
	}
	return VerifyPromoted(ctx, r, r.SourceUser)
}

// VerifyPromoted checks a private generation after promotion or restart. A
// persisted receipt alone never substitutes for current SQL and timeline proof.
func VerifyPromoted(ctx context.Context, r Recovery, user string) (RecoveryEvidence, error) {
	if e := ValidateRecoveryPlan(r); e != nil {
		return RecoveryEvidence{}, e
	}
	source := Source{Host: r.SocketDir, Port: 5432, User: user, Database: "postgres"}
	connect, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, e := source.ConnectPrivateAdmin(connect)
	for e != nil {
		if wait(connect, 50*time.Millisecond) != nil {
			return RecoveryEvidence{}, safeError("post-promotion SQL")
		}
		conn, e = source.ConnectPrivateAdmin(connect)
	}
	defer conn.Close(context.Background())
	var recovery bool
	var writable bool
	var systemID string
	var replay *string
	if e = conn.QueryRow(ctx, `SELECT pg_is_in_recovery(),(pg_control_system()).system_identifier::text,pg_last_wal_replay_lsn()::text,current_setting('transaction_read_only')='off'`).Scan(&recovery, &systemID, &replay, &writable); e != nil {
		return RecoveryEvidence{}, safeError("recovery evidence")
	}
	if recovery || !writable || systemID != r.Barrier.SystemID {
		return RecoveryEvidence{}, errors.New("recovery identity or completion mismatch")
	}
	required, e := ParseLSN(r.Barrier.LSN)
	if e != nil {
		return RecoveryEvidence{}, e
	}
	// The source timeline is independently recorded by the capture procedure;
	// this helper also checks the immediate ancestor in the new history file.
	var timeline int64
	if e = conn.QueryRow(ctx, `SELECT (pg_control_checkpoint()).timeline_id`).Scan(&timeline); e != nil {
		return RecoveryEvidence{}, safeError("timeline verification")
	}
	// A post-promotion checkpoint ensures the control file contains the new timeline.
	if _, e = conn.Exec(ctx, "CHECKPOINT"); e != nil {
		return RecoveryEvidence{}, safeError("post-promotion checkpoint")
	}
	if e = conn.QueryRow(ctx, `SELECT (pg_control_checkpoint()).timeline_id`).Scan(&timeline); e != nil {
		return RecoveryEvidence{}, safeError("timeline verification")
	}
	history, e := os.ReadFile(filepath.Join(r.DataDir, "pg_wal", fmt.Sprintf("%08X.history", timeline)))
	if e != nil {
		return RecoveryEvidence{}, errors.New("promoted timeline history is unavailable")
	}
	lines := strings.Split(strings.TrimSpace(string(history)), "\n")
	ancestor := int64(0)
	forkLSN := ""
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && !strings.HasPrefix(fields[0], "#") {
			ancestor, _ = strconv.ParseInt(fields[0], 10, 64)
			forkLSN = fields[1]
		}
	}
	if ancestor != r.Barrier.Timeline {
		return RecoveryEvidence{}, errors.New("recovery timeline does not descend from the captured source")
	}
	// pg_last_wal_replay_lsn() is NULL after restarting the promoted primary.
	// Its verified timeline fork still proves how far source WAL was replayed.
	actual, e := ParseLSN(forkLSN)
	if e != nil || actual < required {
		return RecoveryEvidence{}, errors.New("timeline fork is before the required source barrier")
	}
	lower := forkLSN
	if replay != nil {
		seen, err := ParseLSN(*replay)
		if err != nil || seen < required || seen > actual {
			return RecoveryEvidence{}, errors.New("recovery replay does not match the timeline fork")
		}
		lower = *replay
	}
	evidence := RecoveryEvidence{Identity: r.Barrier.Identity, ReplayedLSN: lower, Writable: true, ObservedAt: time.Now().UTC()}
	path := filepath.Join(r.ControlDir, "recovery-evidence.json")
	if old, err := os.ReadFile(path); err == nil {
		var prior RecoveryEvidence
		if json.Unmarshal(old, &prior) != nil || prior.Identity != evidence.Identity || !prior.Writable || prior.EndpointPublished {
			return RecoveryEvidence{}, errors.New("prior recovery proof differs from this generation")
		}
		priorLSN, err := ParseLSN(prior.ReplayedLSN)
		if err != nil || priorLSN < required || priorLSN > actual {
			return RecoveryEvidence{}, errors.New("prior replay proof is outside the source timeline")
		}
		return evidence, nil
	} else if !os.IsNotExist(err) {
		return RecoveryEvidence{}, err
	}
	if e = writeJSON(path, evidence); e != nil {
		return RecoveryEvidence{}, e
	}
	return evidence, nil
}
func (t Tools) Stop(ctx context.Context, dataDir string) error {
	return t.run(ctx, "pg_ctl", nil, "-D", dataDir, "-m", "fast", "-w", "-t", "15", "stop")
}

func (t Tools) StopDisconnected(ctx context.Context, r Recovery) error {
	if err := ValidateRecoveryPlan(r); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(r.DataDir, "postmaster.pid")); os.IsNotExist(err) {
		return nil // A prior completed shutdown removed the PID file.
	} else if err != nil {
		return err
	}
	return t.Stop(ctx, r.DataDir)
}

func LoadRecovery(path string) (Recovery, error) {
	var r Recovery
	b, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	e = json.Unmarshal(b, &r)
	return r, e
}
