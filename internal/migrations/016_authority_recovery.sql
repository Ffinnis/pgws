SET LOCAL search_path=pg_catalog,pgws_control;
ALTER TABLE pgws_control.authority ADD COLUMN signing_public_key bytea
 CHECK(signing_public_key IS NULL OR octet_length(signing_public_key)=32);
CREATE TABLE pgws_control.authority_recoveries (
 epoch uuid PRIMARY KEY,
 previous_epoch uuid NOT NULL CHECK(previous_epoch<>epoch),
 plan_hash text NOT NULL CHECK(plan_hash ~ '^[0-9a-f]{64}$'),
 plan jsonb NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz
);
CREATE TABLE pgws_control.authority_recovery_hosts (
 epoch uuid NOT NULL REFERENCES pgws_control.authority_recoveries(epoch),
 host_id text NOT NULL,
 report jsonb NOT NULL,
 acknowledged_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(epoch,host_id)
);
-- Only the operator login can inspect or change recovery records. Runtime and
-- worker roles have no grants. Cold recovery never reopens retained resources.
CREATE FUNCTION pgws_control.preserve_recovery_quarantine() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pgws_control AS $$
BEGIN
 IF TG_TABLE_NAME='workspaces' AND OLD.phase='recovery_blocked' AND
    ROW(NEW.phase,NEW.desired_state) IS DISTINCT FROM ROW(OLD.phase,OLD.desired_state) THEN
  RAISE EXCEPTION 'recovered workspace remains quarantined' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER recovery_quarantine BEFORE UPDATE ON pgws_control.workspaces
 FOR EACH ROW EXECUTE FUNCTION pgws_control.preserve_recovery_quarantine();
