SET LOCAL search_path=pgws_control,pg_catalog;
CREATE FUNCTION preserve_snapshot_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path=pgws_control,pg_catalog,pg_temp AS $$
BEGIN
 IF OLD.state IN ('ready','deleting','deleted') AND
 ROW(NEW.storage_name,NEW.storage_guid,NEW.captured_source_lower_bound,
     NEW.requested_source_lsn,NEW.capture_operation_id,NEW.captured_at)
 IS DISTINCT FROM
 ROW(OLD.storage_name,OLD.storage_guid,OLD.captured_source_lower_bound,
     OLD.requested_source_lsn,OLD.capture_operation_id,OLD.captured_at) THEN
  RAISE EXCEPTION 'published snapshot evidence is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER snapshot_evidence_immutable BEFORE UPDATE ON snapshots
 FOR EACH ROW EXECUTE FUNCTION preserve_snapshot_evidence();
CREATE FUNCTION preserve_generation_evidence() RETURNS trigger
LANGUAGE plpgsql SET search_path=pgws_control,pg_catalog,pg_temp AS $$
BEGIN
 IF ROW(NEW.tenant_id,NEW.project_id,NEW.workspace_id,NEW.generation,NEW.snapshot_id)
 IS DISTINCT FROM ROW(OLD.tenant_id,OLD.project_id,OLD.workspace_id,OLD.generation,OLD.snapshot_id) THEN
  RAISE EXCEPTION 'workspace generation identity is immutable' USING ERRCODE='23514';
 END IF;
 IF OLD.ready_at IS NOT NULL AND
 ROW(NEW.volume_name,NEW.volume_guid,NEW.runtime_reference,NEW.runtime_digest,
     NEW.endpoint_metadata,NEW.readiness_evidence,NEW.ready_at)
 IS DISTINCT FROM
 ROW(OLD.volume_name,OLD.volume_guid,OLD.runtime_reference,OLD.runtime_digest,
     OLD.endpoint_metadata,OLD.readiness_evidence,OLD.ready_at) THEN
  RAISE EXCEPTION 'published generation evidence is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER generation_evidence_immutable BEFORE UPDATE ON workspace_generations
 FOR EACH ROW EXECUTE FUNCTION preserve_generation_evidence();
