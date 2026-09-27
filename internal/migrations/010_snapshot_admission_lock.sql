CREATE FUNCTION pgws_control.lock_ready_snapshot(tid uuid,pid uuid,sid uuid,bid uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pgws_control,pg_catalog,pg_temp AS $$
DECLARE ready boolean;
BEGIN
 IF tid IS DISTINCT FROM nullif(current_setting('pgws.tenant_id',true),'')::uuid
 OR pid IS DISTINCT FROM nullif(current_setting('pgws.project_id',true),'')::uuid THEN
  RETURN false;
 END IF;
 SELECT state='ready' INTO ready FROM snapshots
 WHERE tenant_id=tid AND project_id=pid AND id=sid AND baseline_id=bid FOR SHARE;
 RETURN ready;
END $$;
REVOKE ALL ON FUNCTION pgws_control.lock_ready_snapshot(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pgws_control.lock_ready_snapshot(uuid,uuid,uuid,uuid) TO pgws_runtime;
