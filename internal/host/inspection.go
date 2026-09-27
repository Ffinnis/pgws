package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"pgws/internal/control"
	"pgws/internal/lease"
	"pgws/internal/storage/zfs"
)

type ProjectCapacity struct {
	Tenant         string `json:"tenant"`
	Project        string `json:"project"`
	ReservedMemory int64  `json:"reserved_memory_bytes"`
	zfs.Allocation
}

type CapacityReport struct {
	Host           string            `json:"host"`
	ObservedAt     time.Time         `json:"observed_at"`
	RootAvailable  int64             `json:"root_available_bytes"`
	ReservedMemory int64             `json:"reserved_memory_bytes"`
	Projects       []ProjectCapacity `json:"projects"`
}

// InspectCapacity is read-only and can run while the host owns its journal
// locks. It reports observed allocation, not synthetic sums of clone references
// and not billable usage intervals. Every project is checked against its GUID.
func InspectCapacity(ctx context.Context, c Config) (CapacityReport, error) {
	var report CapacityReport
	if !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) != c.Root || !control.ValidID(c.Epoch) || c.ID == "" {
		return report, errors.New("invalid capacity inspection scope")
	}
	available, err := zfs.RootAvailable(ctx, "/usr/sbin/zfs", c.Dataset)
	if err != nil {
		return report, err
	}
	paths, err := filepath.Glob(filepath.Join(c.Root, "project-limits", "*", "*.json"))
	if err != nil || len(paths) > 10000 {
		return report, errors.New("project allocation inventory exceeds its bound")
	}
	report = CapacityReport{Host: c.ID, ObservedAt: time.Now().UTC(), RootAvailable: available, Projects: []ProjectCapacity{}}
	projects := make(map[string]int)
	for _, path := range paths {
		var record projectAllocation
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &record) != nil || !control.ValidID(record.Tenant) || !control.ValidID(record.Project) || filepath.Base(filepath.Dir(path)) != record.Tenant || filepath.Base(path) != record.Project+".json" {
			return CapacityReport{}, errors.New("project allocation ownership record differs")
		}
		command := lease.Command{Identity: lease.Identity{Epoch: c.Epoch, Host: c.ID, Tenant: record.Tenant, Project: record.Project, Workspace: record.Project, Generation: 1}}
		allocation, err := zfs.ReadProjectAllocation(ctx, "/usr/sbin/zfs", c.Dataset, command, record.Ref)
		if err != nil {
			return CapacityReport{}, err
		}
		if allocation.Quota != record.Quota {
			return CapacityReport{}, errors.New("observed quota differs from its durable allocation policy")
		}
		projects[record.Tenant+"/"+record.Project] = len(report.Projects)
		report.Projects = append(report.Projects, ProjectCapacity{Tenant: record.Tenant, Project: record.Project, Allocation: allocation})
	}
	states, err := filepath.Glob(filepath.Join(c.Root, "objects", "*", "*", "state.json"))
	if err != nil || len(states) > 10000 {
		return CapacityReport{}, errors.New("capacity generation inventory exceeds its bound")
	}
	for _, path := range states {
		var s state
		data, err := os.ReadFile(path)
		if err != nil || json.Unmarshal(data, &s) != nil {
			return CapacityReport{}, errors.New("unreadable generation allocation")
		}
		if s.Phase == "deleted" {
			continue
		}
		id := s.Task.Command.Identity
		if id.Host != c.ID || (id.Epoch != c.Epoch && s.Phase != "quarantined") || filepath.Join((&Host{Config: c}).folder(s.Task), "state.json") != path {
			return CapacityReport{}, errors.New("capacity generation scope differs")
		}
		i, ok := projects[id.Tenant+"/"+id.Project]
		if !ok {
			return CapacityReport{}, errors.New("active generation has no durable project allocation policy")
		}
		memory, err := chargedMemory(filepath.Dir(path), s)
		if err != nil {
			return CapacityReport{}, err
		}
		report.ReservedMemory += memory
		report.Projects[i].ReservedMemory += memory
	}
	return report, nil
}
