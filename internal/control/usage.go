package control

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// CapacityBatch records the acquisition interval of observed gauges. These are
// neither byte-seconds nor a claim that allocation stayed constant between polls.
type CapacityBatch struct {
	ID        string           `json:"id"`
	Epoch     string           `json:"authority_epoch"`
	Host      string           `json:"host_id"`
	Start     time.Time        `json:"interval_start"`
	End       time.Time        `json:"interval_end"`
	Boot      string           `json:"boot_id"`
	ElapsedNS int64            `json:"elapsed_ns"`
	Projects  []CapacitySample `json:"projects"`
}
type CapacitySample struct {
	Tenant         string `json:"tenant_id"`
	Project        string `json:"project_id"`
	DatasetGUID    string `json:"dataset_guid"`
	Used           int64  `json:"used_bytes"`
	Referenced     int64  `json:"referenced_bytes"`
	ByChildren     int64  `json:"used_by_children_bytes"`
	BySnapshots    int64  `json:"used_by_snapshots_bytes"`
	ByDataset      int64  `json:"used_by_dataset_bytes"`
	ByReservation  int64  `json:"used_by_refreservation_bytes"`
	ReservedMemory int64  `json:"reserved_memory_bytes"`
}

func (s CapacitySample) gauges() map[string]int64 {
	return map[string]int64{"project_allocated_bytes": s.Used, "ancestor_referenced_bytes": s.Referenced, "allocation_children_bytes": s.ByChildren, "allocation_snapshots_bytes": s.BySnapshots, "allocation_dataset_bytes": s.ByDataset, "allocation_reservation_bytes": s.ByReservation, "reserved_runtime_memory_bytes": s.ReservedMemory}
}
func (b CapacityBatch) Validate() error {
	if !ValidID(b.ID) || !ValidID(b.Epoch) || !ValidID(b.Boot) || b.Host == "" || len(b.Host) > 200 || b.Start.IsZero() || !b.End.After(b.Start) || b.End.Sub(b.Start) > time.Minute || b.ElapsedNS <= 0 || b.ElapsedNS > int64(time.Minute) || len(b.Projects) > 256 {
		return errors.New("invalid capacity observation interval")
	}
	seen := map[string]bool{}
	for _, p := range b.Projects {
		scope := p.Tenant + "/" + p.Project
		if !ValidID(p.Tenant) || !ValidID(p.Project) || p.DatasetGUID == "" || len(p.DatasetGUID) > 32 || seen[scope] {
			return errors.New("invalid capacity observation scope")
		}
		for _, c := range p.DatasetGUID {
			if c < '0' || c > '9' {
				return errors.New("invalid capacity dataset GUID")
			}
		}
		for _, amount := range p.gauges() {
			if amount < 0 || amount > 1<<60 {
				return errors.New("capacity gauge exceeds its bound")
			}
		}
		seen[scope] = true
	}
	return nil
}

type UsageBackend interface {
	CollectUsage(context.Context, Task) (CapacityBatch, error)
	AcknowledgeUsage(context.Context, Task) error
}

// CollectUsage performs all host I/O outside the management transaction. A
// missing commit/ack response leaves the same durable batch available to retry.
func (w *Worker) CollectUsage(ctx context.Context) error {
	backend, ok := w.Backend.(UsageBackend)
	if !ok {
		return nil
	}
	t := Task{Kind: "collect_usage"}
	t.Command.Epoch = w.Epoch
	t.Command.Host = w.HostID
	batch, err := backend.CollectUsage(ctx, t)
	if err != nil {
		return err
	}
	if batch.Epoch != w.Epoch || batch.Host != w.HostID {
		return errors.New("host usage authority differs")
	}
	if err = w.recordUsage(ctx, batch); err != nil {
		return err
	}
	t.Kind = "acknowledge_usage"
	t.Document, _ = json.Marshal(Object{"batch_id": batch.ID})
	return backend.AcknowledgeUsage(ctx, t)
}
func (w *Worker) recordUsage(ctx context.Context, b CapacityBatch) error {
	if err := b.Validate(); err != nil {
		return err
	}
	if b.Epoch != w.Epoch || b.Host != w.HostID {
		return errors.New("capacity authority differs")
	}
	tx, err := w.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var active bool
	if err = tx.QueryRow(ctx, "SELECT pgws_control.lock_authority($1::uuid)", w.Epoch).Scan(&active); err != nil {
		return err
	}
	if !active {
		return errors.New("usage authority is not active")
	}
	payload, _ := json.Marshal(b)
	hash := fmt.Sprintf("%x", sha256.Sum256(payload))
	if _, err = tx.Exec(ctx, `INSERT INTO pgws_control.usage_batches(id,host_id,authority_epoch,payload_hash) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, b.ID, b.Host, b.Epoch, hash); err != nil {
		return errors.New("usage batch persistence failed")
	}
	var identical bool
	if err = tx.QueryRow(ctx, `SELECT host_id=$2 AND authority_epoch=$3 AND payload_hash=$4 FROM pgws_control.usage_batches WHERE id=$1`, b.ID, b.Host, b.Epoch, hash).Scan(&identical); err != nil || !identical {
		return errors.New("usage batch retry differs")
	}
	for _, p := range b.Projects {
		dimensions, _ := json.Marshal(Object{"kind": "observed_gauge", "host_id": b.Host, "authority_epoch": b.Epoch, "dataset_guid": p.DatasetGUID, "boot_id": b.Boot, "elapsed_ns": b.ElapsedNS, "batch_id": b.ID})
		resource := "zfs-project:" + p.DatasetGUID
		gauges := p.gauges()
		metrics := make([]string, 0, len(gauges))
		for name := range gauges {
			metrics = append(metrics, name)
		}
		slices.Sort(metrics)
		for _, metric := range metrics {
			amount := gauges[metric]
			key := fmt.Sprintf("%s/%s/%s/%s", b.Epoch, b.Host, b.ID, metric)
			_, err = tx.Exec(ctx, `INSERT INTO pgws_control.usage_events(tenant_id,project_id,id,resource_reference,metric,amount,unit,interval_start,interval_end,source_event_key,dimensions) VALUES($1,$2,$3,$4,$5,$6,'bytes',$7,$8,$9,$10) ON CONFLICT(tenant_id,project_id,source_event_key) DO NOTHING`, p.Tenant, p.Project, ID(), resource, metric, amount, b.Start, b.End, key, dimensions)
			if err != nil {
				return errors.New("capacity measurement persistence failed")
			}
			var same bool
			err = tx.QueryRow(ctx, `SELECT resource_reference=$4 AND metric=$5 AND amount=$6 AND unit='bytes' AND interval_start=$7 AND interval_end=$8 AND dimensions=$9::jsonb FROM pgws_control.usage_events WHERE tenant_id=$1 AND project_id=$2 AND source_event_key=$3`, p.Tenant, p.Project, key, resource, metric, amount, b.Start, b.End, dimensions).Scan(&same)
			if err != nil || !same {
				return errors.New("usage event retry differs from original measurement")
			}
		}
	}
	return tx.Commit(ctx)
}
