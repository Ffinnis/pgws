package control

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"
)

type sourceJob struct {
	SourceID    string `json:"source_id"`
	BaselineID  string `json:"baseline_id,omitempty"`
	SourceEpoch int64  `json:"source_epoch,omitempty"`
}

func (s *Server) getSource(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, _ []byte) (int, any, error) {
	if !p.Admin {
		return 0, nil, fail(403, "FORBIDDEN", "Source administration requires a project administrator")
	}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT jsonb_strip_nulls(jsonb_build_object('id',id,'connector',connector,'source_epoch',source_epoch,'generation',baseline_generation,'status',status,'observed_at',observed_at)) FROM sources WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, p.Tenant, p.Project, r.PathValue("source_id")).Scan(&raw)
	return 200, json.RawMessage(raw), err
}

func (s *Server) sourceAction(ctx context.Context, tx pgx.Tx, p Principal, r *http.Request, body []byte) (int, any, error) {
	if !p.Admin {
		return 0, nil, fail(403, "FORBIDDEN", "Source reseeding requires a project administrator")
	}
	var in struct {
		Action string `json:"action"`
		Epoch  int64  `json:"expected_source_epoch"`
	}
	if err := decode(body, &in, "action", "expected_source_epoch"); err != nil {
		return 0, nil, err
	}
	if in.Action != "reseed" || in.Epoch < 1 || in.Epoch >= 1e9 {
		return 0, nil, fail(400, "INVALID_REQUEST", "Expected a reseed action and a valid source epoch")
	}
	if !s.Physical {
		return 0, nil, fail(503, "CONNECTOR_UNAVAILABLE", "Reseeding requires the physical connector")
	}
	id := r.PathValue("source_id")
	var epoch, generation int64
	var status string
	var approved bool
	err := tx.QueryRow(ctx, `SELECT source_epoch,baseline_generation,status,EXISTS(SELECT FROM approved_source_references a WHERE (a.tenant_id,a.project_id,a.endpoint_reference,a.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference)) FROM sources s WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND connector='physical' FOR UPDATE`, p.Tenant, p.Project, id).Scan(&epoch, &generation, &status, &approved)
	if err != nil {
		return 0, nil, err
	}
	if !approved {
		return 0, nil, fail(403, "SOURCE_NOT_APPROVED", "Source reference pair is not approved")
	}
	if epoch != in.Epoch {
		return 0, nil, fail(409, "SOURCE_EPOCH_CONFLICT", "Source epoch changed")
	}
	if status != "streaming" && status != "blocked" && status != "unreachable" {
		return 0, nil, fail(409, "SOURCE_NOT_READY", "Wait for the current source operation")
	}
	var busy bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM operations WHERE tenant_id=$1 AND project_id=$2 AND workspace_id IS NULL AND request_document->>'source_id'=$3 AND status IN ('queued','running'))`, p.Tenant, p.Project, id).Scan(&busy); err != nil {
		return 0, nil, err
	}
	if busy {
		return 0, nil, fail(409, "OPERATION_IN_PROGRESS", "Wait for the current source operation")
	}
	baseline := ID()
	if _, err = tx.Exec(ctx, `UPDATE sources SET source_epoch=source_epoch+1,baseline_generation=baseline_generation+1,status='seeding' WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, p.Tenant, p.Project, id); err != nil {
		return 0, nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE baselines SET state='retired' WHERE tenant_id=$1 AND project_id=$2 AND source_id=$3 AND state<>'retired'`, p.Tenant, p.Project, id); err != nil {
		return 0, nil, err
	}
	doc, _ := json.Marshal(sourceJob{SourceID: id, BaselineID: baseline, SourceEpoch: epoch + 1})
	op, err := s.enqueue(ctx, tx, p, r, "", "reseed_source", generation+1, generation+1, doc)
	return 202, Object{"source_id": id, "source_epoch": epoch + 1, "baseline_id": baseline, "generation": generation + 1, "operation": op}, err
}
