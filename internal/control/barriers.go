package control

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"pgws/internal/freshness"
	"time"
)

type BarrierResponse struct {
	Source      string    `json:"source_id"`
	SourceEpoch int64     `json:"source_epoch"`
	Token       string    `json:"barrier_token"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (w *Worker) completeBarrier(ctx context.Context, tx pgx.Tx, j *Job, t Task, out Outcome) error {
	c := out.Barrier
	if c == nil || out.Phase != "barrier" || c.SystemID != t.SourceContract.SystemID || c.Timeline != t.SourceContract.Timeline || c.SourceEpoch != t.SourceContract.SourceEpoch {
		return errors.New("source barrier lineage differs")
	}
	c.ID = j.ID
	c.Authority = w.Epoch
	c.Tenant = j.Tenant
	c.Project = j.Project
	c.Source = t.SourceID
	c.IssuedAt = time.Now().UTC()
	c.ExpiresAt = c.IssuedAt.Add(time.Hour)
	token, err := freshness.Sign(w.SigningKey, *c)
	if err != nil {
		return err
	}
	var current bool
	err = tx.QueryRow(ctx, `SELECT status='streaming' AND source_epoch=$4 AND timeline=$5 AND system_identifier=$6 AND host_fencing_token=$7 FROM pgws_control.sources WHERE tenant_id=$1 AND project_id=$2 AND id=$3 FOR SHARE`, j.Tenant, j.Project, t.SourceID, c.SourceEpoch, c.Timeline, c.SystemID, j.Fence).Scan(&current)
	if err != nil {
		return err
	}
	if !current {
		return errors.New("source barrier authority changed")
	}
	raw, _ := json.Marshal(BarrierResponse{c.Source, c.SourceEpoch, token, c.IssuedAt, c.ExpiresAt})
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operations SET status='succeeded',current_step='barrier_captured',safe_result=$4,lease_until=NULL,completed_at=now(),updated_at=now() WHERE tenant_id=$1 AND project_id=$2 AND id=$3`, j.Tenant, j.Project, j.ID, raw)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE pgws_control.operation_steps SET state='completed',finished_at=now() WHERE tenant_id=$1 AND project_id=$2 AND operation_id=$3 AND fencing_token=$4`, j.Tenant, j.Project, j.ID, j.Fence)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Server) barrierResult(ctx context.Context, tx pgx.Tx, tenant, project string, raw []byte) (int, any, error) {
	var response BarrierResponse
	if json.Unmarshal(raw, &response) != nil {
		return 0, nil, errors.New("invalid source barrier receipt")
	}
	c, err := freshness.Verify(s.AuthorityKey, response.Token, time.Now())
	if err != nil || c.Tenant != tenant || c.Project != project || c.Authority != s.Epoch {
		if s.Log != nil {
			s.Log.Warn("source barrier verification rejected", "reason", err, "scope_matches", c.Tenant == tenant && c.Project == project && c.Authority == s.Epoch)
		}
		return 0, nil, fail(409, "BARRIER_EXPIRED", "Source barrier is expired or no longer authorized")
	}
	var current bool
	err = tx.QueryRow(ctx, `SELECT status='streaming' AND source_epoch=$4 AND system_identifier=$5 AND timeline=$6 FROM sources s WHERE tenant_id=$1 AND project_id=$2 AND id=$3 AND EXISTS(SELECT FROM approved_source_references a WHERE (a.tenant_id,a.project_id,a.endpoint_reference,a.secret_reference)=(s.tenant_id,s.project_id,s.endpoint_reference,s.secret_reference))`, tenant, project, c.Source, c.SourceEpoch, c.SystemID, c.Timeline).Scan(&current)
	if err != nil {
		return 0, nil, err
	}
	if !current {
		return 0, nil, fail(409, "SOURCE_LINEAGE_CHANGED", "Source barrier lineage is no longer current")
	}
	return 200, response, nil
}
