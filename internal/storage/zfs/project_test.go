package zfs

import (
	"context"
	"testing"
)

func TestProjectAllocationIdentity(t *testing.T) {
	b, f, c := testBackend(t)
	ctx := context.Background()
	ref, err := b.EnsureProject(ctx, c, 1<<30, Ref{})
	if err != nil {
		t.Fatal(err)
	}
	count := len(f.mutations)
	if again, err := b.EnsureProject(ctx, c, 1<<30, ref); err != nil || again != ref || len(f.mutations) != count {
		t.Fatal("project replay changed allocation", err)
	}
	if _, err = b.EnsureProject(ctx, c, 2<<30, ref); err == nil || len(f.mutations) != count {
		t.Fatal("workspace admission changed an existing project limit")
	}
	if _, err = b.EnsureProject(ctx, c, 1<<30, Ref{Name: ref.Name, GUID: "999999"}); err == nil || len(f.mutations) != count {
		t.Fatal("replacement project GUID was adopted")
	}
	for key, value := range map[string]string{"used": "12345", "available": "1000000000", "referenced": "1024", "usedbydataset": "1024", "usedbychildren": "10321", "usedbysnapshots": "1000", "usedbyrefreservation": "0"} {
		f.props[ref.Name][key] = value
	}
	a, err := b.ProjectAllocation(ctx, c, ref)
	if err != nil || a.Used != 12345 || a.Quota != 1<<30 || a.ByChildren != 10321 {
		t.Fatal("incorrect ancestor allocation counters", a, err)
	}
	c.Project = "20000000-0000-4000-8000-000000000002"
	if _, err = b.ProjectAllocation(ctx, c, ref); err == nil {
		t.Fatal("cross-project accounting read accepted")
	}
	c.Project = "10000000-0000-4000-8000-000000000002"
	delete(f.items, ref.Name)
	if _, err = b.EnsureProject(ctx, c, 1<<30, ref); err == nil || len(f.mutations) != count {
		t.Fatal("deleted project allocation was recreated")
	}
}

func TestProjectRefusesUnlabelledAncestor(t *testing.T) {
	b, f, c := testBackend(t)
	name, _ := b.scope(c)
	f.items[name] = entry{Ref: Ref{Name: name, GUID: "2"}, Kind: "filesystem", Origin: "-", Mountpoint: "none"}
	f.props[name] = map[string]string{"mountpoint": "none", "canmount": "off", "quota": "1073741824"}
	if _, err := b.EnsureProject(context.Background(), c, 1<<30, Ref{}); err == nil || len(f.mutations) != 0 {
		t.Fatal("unowned ancestor was silently relabelled")
	}
}
