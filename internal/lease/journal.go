package lease

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"pgws/internal/atomicfile"
	"sync"
	"syscall"
)

var ErrFence = errors.New("stale or conflicting host command")

type Command struct {
	Identity
	Operation   string `json:"operation"`
	Token       int64  `json:"token"`
	Kind        string `json:"kind"`
	PayloadHash string `json:"payload_hash"`
}
type Record struct {
	Command   Command         `json:"command"`
	Completed bool            `json:"completed"`
	Evidence  json.RawMessage `json:"evidence,omitempty"`
}
type journalState struct {
	Epoch   string            `json:"epoch"`
	Records map[string]Record `json:"records"`
}

// Journal is exclusively owned by one host process. Epoch changes require an
// explicit reconciliation procedure, never automatic replacement on startup.
type Journal struct {
	mu       sync.Mutex
	folder   string
	lock     *os.File
	state    journalState
	closed   bool
	poisoned bool
}

func OpenJournal(folder, epoch string) (*Journal, error) {
	return openJournal(folder, epoch, "")
}

// OpenRecoveryJournal is for the offline operator entrypoint only. It resumes
// either side of a durable epoch transition; ordinary startup never uses it.
func OpenRecoveryJournal(folder, previous, next string) (*Journal, error) {
	if previous == "" || next == "" || previous == next {
		return nil, ErrFence
	}
	return openJournal(folder, previous, next)
}

func openJournal(folder, epoch, recoveryEpoch string) (*Journal, error) {
	if epoch == "" {
		return nil, ErrFence
	}
	if e := os.MkdirAll(folder, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(folder, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	j := &Journal{folder: folder, lock: f, state: journalState{Epoch: epoch, Records: map[string]Record{}}}
	b, e := os.ReadFile(filepath.Join(folder, "journal.json"))
	if e != nil && !os.IsNotExist(e) {
		j.Close()
		return nil, e
	}
	if e == nil {
		if json.Unmarshal(b, &j.state) != nil || (j.state.Epoch != epoch && j.state.Epoch != recoveryEpoch) || j.state.Records == nil {
			j.Close()
			return nil, ErrFence
		}
	} else if recoveryEpoch != "" {
		j.Close()
		return nil, ErrFence // Recovery must not invent a missing durable journal.
	} else if e = j.persist(j.state); e != nil {
		j.Close()
		return nil, e
	}
	return j, nil
}
func resource(c Command) string {
	b, _ := json.Marshal([]string{c.Tenant, c.Project, c.Workspace})
	return string(b)
}

func (j *Journal) Current(id Identity) (Record, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.poisoned {
		return Record{}, false
	}
	r, ok := j.state.Records[resource(Command{Identity: id})]
	r.Evidence = append(json.RawMessage(nil), r.Evidence...)
	return r, ok
}

// Accept persists intent before a caller performs a side effect. A matching
// unfinished replay must be reconciled against the actual runtime/storage.
func (j *Journal) Accept(c Command) (Record, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.poisoned || c.Epoch != j.state.Epoch || c.Token < 1 || c.Generation < 1 || c.Revision < 1 || c.Operation == "" || c.Tenant == "" || c.Project == "" || c.Workspace == "" || c.Host == "" || c.Kind == "" || len(c.PayloadHash) != 64 {
		return Record{}, false, ErrFence
	}
	key := resource(c)
	old, ok := j.state.Records[key]
	if ok {
		if old.Command == c {
			return old, true, nil
		}
		if c.Token <= old.Command.Token || c.Generation < old.Command.Generation || c.Revision < old.Command.Revision || c.Host != old.Command.Host {
			return Record{}, false, ErrFence
		}
	}
	record := Record{Command: c}
	next := j.copyState()
	next.Records[key] = record
	if e := j.persist(next); e != nil {
		j.poisoned = true
		return Record{}, false, e
	}
	j.state = next
	return record, false, nil
}
func (j *Journal) Complete(c Command) error {
	return j.CompleteWithEvidence(c, nil)
}
func (j *Journal) CompleteWithEvidence(c Command, evidence json.RawMessage) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	key := resource(c)
	old, ok := j.state.Records[key]
	if j.closed || j.poisoned || c.Epoch != j.state.Epoch || !ok || old.Command != c {
		return ErrFence
	}
	if old.Completed {
		return nil
	}
	old.Completed = true
	old.Evidence = append(json.RawMessage(nil), evidence...)
	next := j.copyState()
	next.Records[key] = old
	if e := j.persist(next); e != nil {
		j.poisoned = true
		return e
	}
	j.state = next
	return nil
}

// AdvanceEpoch retains every high-water mark and receipt, including records
// absent from a restored management backup. The host must stop old runtimes
// before calling this, and block normal startup until both journals advance.
func (j *Journal) AdvanceEpoch(previous, next string) ([]Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.poisoned || previous == "" || next == "" || previous == next || (j.state.Epoch != previous && j.state.Epoch != next) {
		return nil, ErrFence
	}
	state := j.copyState()
	state.Epoch = next
	if e := j.persist(state); e != nil {
		j.poisoned = true
		return nil, e
	}
	j.state = state
	records := make([]Record, 0, len(state.Records))
	for _, r := range state.Records {
		r.Evidence = append(json.RawMessage(nil), r.Evidence...)
		records = append(records, r)
	}
	return records, nil
}
func (j *Journal) copyState() journalState {
	next := journalState{Epoch: j.state.Epoch, Records: make(map[string]Record, len(j.state.Records))}
	for k, v := range j.state.Records {
		next.Records[k] = v
	}
	return next
}
func (j *Journal) persist(state journalState) error {
	b, e := json.Marshal(state)
	if e != nil {
		return e
	}
	return atomicfile.Replace(filepath.Join(j.folder, "journal.json"), b)
}
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	return j.lock.Close()
}
