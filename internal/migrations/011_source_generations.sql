ALTER TABLE pgws_control.sources ADD COLUMN baseline_generation bigint NOT NULL DEFAULT 1 CHECK (baseline_generation > 0);
-- Admission may reserve a generation and retire old baselines within its RLS
-- scope. It still cannot change source references, manifests or ready evidence.
GRANT UPDATE (source_epoch,baseline_generation,status) ON pgws_control.sources TO pgws_runtime;
GRANT UPDATE (state) ON pgws_control.baselines TO pgws_runtime;

CREATE OR REPLACE FUNCTION pgws_control.lock_execution_grant(tid uuid,pid uuid,oid uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pgws_control AS $$
DECLARE matched text;
BEGIN
 SELECT t.token_hash INTO matched FROM pgws_control.api_tokens t JOIN pgws_control.operations o
 ON (t.tenant_id,t.project_id,t.principal_id)=(o.tenant_id,o.project_id,o.actor_reference)
 WHERE o.tenant_id=tid AND o.project_id=pid AND o.id=oid
 AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()
 AND (o.workspace_id IS NULL AND (o.kind IN ('register_source','reseed_source') AND t.is_admin OR o.kind='issue_barrier' AND t.allow_raw)
 OR o.workspace_id IS NOT NULL AND t.allow_raw)
 LIMIT 1 FOR SHARE OF t;
 RETURN matched IS NOT NULL;
END $$;
