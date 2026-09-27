package zfs

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"pgws/internal/lease"
)

// This test double checks ownership and command safety. It is never selected by
// the executable and does not qualify real OpenZFS behavior.
type fakeZFS struct {
	items                    map[string]entry
	props                    map[string]map[string]string
	holds                    map[string]string
	mutations                [][]string
	guid                     int
	failInventoryAfterEffect bool
}

func (f *fakeZFS) Run(_ context.Context, args ...string) (string, error) {
	last := args[len(args)-1]
	switch args[0] {
	case "get":
		p, ok := f.props[last]
		if !ok {
			return "", fmt.Errorf("missing %s", last)
		}
		var rows []string
		if len(args) == 7 && args[4] == "property,value" {
			for _, key := range strings.Split(args[5], ",") {
				rows = append(rows, key+"\t"+p[key])
			}
			return strings.Join(rows, "\n"), nil
		}
		for key, val := range p {
			rows = append(rows, key+"\t"+val+"\tlocal")
		}
		sort.Strings(rows)
		return strings.Join(rows, "\n"), nil
	case "list":
		if f.failInventoryAfterEffect && len(f.mutations) > 0 {
			f.failInventoryAfterEffect = false
			return "", fmt.Errorf("injected observation failure after storage effect")
		}
		var rows []string
		for _, item := range f.items {
			rows = append(rows, strings.Join([]string{item.Name, item.Kind, item.GUID, item.Origin, item.Mountpoint}, "\t"))
		}
		sort.Strings(rows)
		return strings.Join(rows, "\n"), nil
	case "holds":
		if h := f.holds[last]; h != "" {
			return last + "\t" + h + "\tdate", nil
		}
		return "", nil
	case "hold":
		f.holds[last] = args[1]
	case "release":
		if f.holds[last] != args[1] {
			return "", fmt.Errorf("foreign hold")
		}
		delete(f.holds, last)
	case "destroy":
		if len(args) != 2 {
			return "", fmt.Errorf("unsafe destroy flags")
		}
		delete(f.items, last)
		delete(f.props, last)
	case "create", "clone", "snapshot":
		if _, exists := f.items[last]; exists {
			return "", fmt.Errorf("duplicate")
		}
		props := map[string]string{}
		for i := 1; i < len(args)-1; i++ {
			if args[i] == "-o" {
				i++
				p := strings.SplitN(args[i], "=", 2)
				props[p[0]] = p[1]
			}
		}
		kind, origin := "filesystem", "-"
		if args[0] == "clone" {
			origin = args[len(args)-2]
		}
		if args[0] == "snapshot" {
			kind = "snapshot"
			props["mountpoint"] = "-"
		}
		f.guid++
		f.items[last] = entry{Ref: Ref{last, fmt.Sprint(f.guid)}, Kind: kind, Origin: origin, Mountpoint: props["mountpoint"]}
		f.props[last] = props
	default:
		return "", fmt.Errorf("unexpected command %v", args)
	}
	f.mutations = append(f.mutations, append([]string(nil), args...))
	return "", nil
}

func TestRetiredBaselineCollectionKeepsCurrentGenerationAndActualReferences(t *testing.T) {
	b, f, c := testBackend(t)
	ctx := context.Background()
	old, err := b.EnsureBaseline(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	c.Token++
	c.Operation = "capture"
	snapshotID := "10000000-0000-4000-8000-000000000004"
	snapshot, err := b.EnsureSnapshot(ctx, c, old, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	cloneCommand := c
	cloneCommand.Workspace = "10000000-0000-4000-8000-000000000005"
	cloneCommand.Token = 1
	clone, err := b.EnsureClone(ctx, cloneCommand, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	c.Generation, c.Revision = 2, 2
	c.Token++
	c.Operation = "new-baseline"
	current, err := b.EnsureBaseline(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	c.Token++
	c.Operation = "old-collection"
	count := len(f.mutations)
	if err = b.DestroyRetiredBaseline(ctx, c, 1, old); !errors.Is(err, ErrBaselineReferenced) || count != len(f.mutations) {
		t.Fatal("collected referenced baseline", err)
	}
	c.Token++
	if err = b.DestroyRetiredSnapshot(ctx, c, 1, snapshot, snapshotID); err == nil || count != len(f.mutations) {
		t.Fatal("collected snapshot with actual clone")
	}
	cloneCommand.Token++
	if err = b.DestroyClone(ctx, cloneCommand, clone); err != nil {
		t.Fatal(err)
	}
	c.Token++
	count = len(f.mutations)
	if err = b.DestroyRetiredSnapshot(ctx, c, 1, Ref{snapshot.Name, "wrong-guid"}, snapshotID); err == nil || count != len(f.mutations) {
		t.Fatal("wrong snapshot GUID mutated storage")
	}
	c.Token++
	f.props[snapshot.Name]["org.pgws:tenant"] = "foreign"
	if err = b.DestroyRetiredSnapshot(ctx, c, 1, snapshot, snapshotID); err == nil || count != len(f.mutations) {
		t.Fatal("foreign snapshot owner accepted")
	}
	f.props[snapshot.Name]["org.pgws:tenant"] = c.Tenant
	c.Token++
	if err = b.DestroyRetiredSnapshot(ctx, c, 1, snapshot, snapshotID); err != nil {
		t.Fatal(err)
	}
	c.Token++
	count = len(f.mutations)
	if err = b.DestroyRetiredBaseline(ctx, c, 2, current); err == nil || count != len(f.mutations) {
		t.Fatal("collected current baseline as retired")
	}
	if err = b.DestroyRetiredBaseline(ctx, c, 1, Ref{old.Name, "wrong-guid"}); err == nil || count != len(f.mutations) {
		t.Fatal("wrong baseline GUID mutated storage")
	}
	c.Token++
	if err = b.DestroyRetiredBaseline(ctx, c, 1, old); err != nil {
		t.Fatal(err)
	}
	count = len(f.mutations)
	if err = b.DestroyRetiredBaseline(ctx, c, 1, old); err != nil || count != len(f.mutations) {
		t.Fatal("retired cleanup replay", err)
	}
	if _, exists := f.items[old.Name]; exists {
		t.Fatal("old baseline remains")
	}
	if _, exists := f.items[current.Name]; !exists {
		t.Fatal("cleanup removed current baseline")
	}
	if err = b.VerifyGeneration(ctx, c, current, "baselines"); err != nil {
		t.Fatal(err)
	}
}
func testBackend(t *testing.T) (*Backend, *fakeZFS, lease.Command) {
	t.Helper()
	j, err := lease.OpenJournal(t.TempDir(), "epoch")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	b, err := New("/usr/sbin/zfs", "pool/pgws", "/var/lib/pgws", j)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeZFS{items: map[string]entry{"pool/pgws": {Ref: Ref{"pool/pgws", "1"}, Kind: "filesystem", Origin: "-", Mountpoint: "/var/lib/pgws"}}, props: map[string]map[string]string{"pool/pgws": {"org.pgws:managed": "on"}}, holds: map[string]string{}, guid: 1}
	b.run = f
	c := lease.Command{Identity: lease.Identity{Epoch: "epoch", Tenant: "10000000-0000-4000-8000-000000000001", Project: "10000000-0000-4000-8000-000000000002", Workspace: "10000000-0000-4000-8000-000000000003", Host: "host", Generation: 1, Revision: 1}, Operation: "baseline", Token: 1}
	return b, f, c
}
func TestStorageIdentityAndReplay(t *testing.T) {
	b, f, c := testBackend(t)
	ctx := context.Background()
	baseline, err := b.EnsureBaseline(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	count := len(f.mutations)
	if got, err := b.EnsureBaseline(ctx, c); err != nil || got != baseline || count != len(f.mutations) {
		t.Fatalf("baseline replay %v %v", got, err)
	}
	c.Token = 2
	c.Operation = "snapshot"
	snapshotID := "10000000-0000-4000-8000-000000000004"
	snap, err := b.EnsureSnapshot(ctx, c, baseline, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	count = len(f.mutations)
	if got, err := b.EnsureSnapshot(ctx, c, baseline, snapshotID); err != nil || got != snap || count != len(f.mutations) {
		t.Fatalf("snapshot replay %v %v", got, err)
	}
	if f.holds[snap.Name] != "pgws:"+snapshotID {
		t.Fatal("missing snapshot hold")
	}
	c.Workspace = "10000000-0000-4000-8000-000000000005"
	c.Token = 1
	c.Operation = "clone"
	clone, err := b.EnsureClone(ctx, c, snap)
	if err != nil {
		t.Fatal(err)
	}
	oldCommand := c
	count = len(f.mutations)
	c.Token = 2
	c.Operation = "destroy-wrong"
	if err = b.DestroyClone(ctx, c, Ref{clone.Name, "999"}); err == nil || count != len(f.mutations) {
		t.Fatal("wrong GUID mutated storage")
	}
	c.Token = 3
	c.Operation = "destroy"
	if err = b.DestroyClone(ctx, c, clone); err != nil {
		t.Fatal(err)
	}
	count = len(f.mutations)
	if err = b.DestroyClone(ctx, c, clone); err != nil || count != len(f.mutations) {
		t.Fatal("delete replay mutated storage", err)
	}
	if _, err = b.EnsureClone(ctx, oldCommand, snap); err == nil {
		t.Fatal("old clone resurrected after delete")
	}
}
func TestRemovedCompletedResourceIsNotRecreated(t *testing.T) {
	b, f, c := testBackend(t)
	ref, err := b.EnsureBaseline(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	delete(f.items, ref.Name)
	count := len(f.mutations)
	if _, err = b.EnsureBaseline(context.Background(), c); err == nil || count != len(f.mutations) {
		t.Fatal("completed receipt recreated deleted resource")
	}
}
func TestForeignOwnerIsRejected(t *testing.T) {
	b, f, c := testBackend(t)
	ref, err := b.EnsureBaseline(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	f.props[ref.Name]["org.pgws:tenant"] = "foreign"
	c.Token = 2
	c.Operation = "snapshot"
	count := len(f.mutations)
	if _, err = b.EnsureSnapshot(context.Background(), c, ref, "10000000-0000-4000-8000-000000000004"); err == nil || count != len(f.mutations) {
		t.Fatal("foreign owner accepted")
	}
}

func TestLostObservationReconcilesExistingObject(t *testing.T) {
	b, f, c := testBackend(t)
	f.failInventoryAfterEffect = true
	if _, err := b.EnsureBaseline(context.Background(), c); err == nil {
		t.Fatal("injected observation failure ignored")
	}
	count := len(f.mutations)
	if count != 1 {
		t.Fatal("expected one real effect", count)
	}
	if ref, err := b.EnsureBaseline(context.Background(), c); err != nil || ref.GUID == "" || count != len(f.mutations) {
		t.Fatal("replay failed to reconcile existing object", ref, err)
	}
}
