SET search_path=pgws_control,pg_catalog;
CREATE TABLE usage_batches (
 id uuid PRIMARY KEY,
 host_id text NOT NULL,
 authority_epoch uuid NOT NULL,
 payload_hash text NOT NULL CHECK(payload_hash ~ '^[0-9a-f]{64}$'),
 received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE usage_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_batches FORCE ROW LEVEL SECURITY;
CREATE POLICY worker_scope ON usage_batches TO pgws_worker USING(true) WITH CHECK(true);
GRANT SELECT,INSERT ON usage_batches TO pgws_worker;
ALTER TABLE usage_events ADD COLUMN dimensions jsonb NOT NULL DEFAULT '{}';
REVOKE UPDATE, DELETE ON usage_events FROM pgws_worker;
CREATE FUNCTION immutable_usage_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'usage measurements are immutable';
END
$$;
CREATE TRIGGER immutable_usage_event BEFORE UPDATE OR DELETE ON usage_events
FOR EACH ROW EXECUTE FUNCTION immutable_usage_event();
CREATE TRIGGER immutable_usage_batch BEFORE UPDATE OR DELETE ON usage_batches
FOR EACH ROW EXECUTE FUNCTION immutable_usage_event();
CREATE INDEX usage_events_project_history ON usage_events(tenant_id,project_id,interval_end DESC,id DESC);
