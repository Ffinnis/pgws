SET LOCAL search_path=pgws_control,pg_catalog;
-- SELECT FOR SHARE requires UPDATE privileges. Narrow definer functions grant
-- the worker a lock, without granting it permission to modify authority/grants.
CREATE FUNCTION lock_authority(expected uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pgws_control,pg_catalog AS $$
DECLARE active boolean;
BEGIN
 SELECT reconciled AND epoch=expected INTO active FROM authority WHERE singleton FOR SHARE;
 RETURN coalesce(active,false);
END $$;
CREATE FUNCTION lock_execution_grant(tid uuid,pid uuid,oid uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pgws_control,pg_catalog AS $$
DECLARE matched text;
BEGIN
 SELECT t.token_hash INTO matched FROM api_tokens t JOIN operations o
 ON (t.tenant_id,t.project_id,t.principal_id)=(o.tenant_id,o.project_id,o.actor_reference)
 WHERE o.tenant_id=tid AND o.project_id=pid AND o.id=oid
 AND t.revoked_at IS NULL AND t.expires_at>clock_timestamp()
 AND (o.workspace_id IS NULL AND (o.kind='register_source' AND t.is_admin OR o.kind='issue_barrier' AND t.allow_raw)
 OR o.workspace_id IS NOT NULL AND t.allow_raw)
 LIMIT 1 FOR SHARE OF t;
 RETURN matched IS NOT NULL;
END $$;
CREATE FUNCTION lock_source_reference(tid uuid,pid uuid,endpoint text,secret text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pgws_control,pg_catalog AS $$
DECLARE matched text;
BEGIN
 SELECT endpoint_reference INTO matched FROM approved_source_references
 WHERE tenant_id=tid AND project_id=pid AND endpoint_reference=endpoint AND secret_reference=secret FOR SHARE;
 RETURN matched IS NOT NULL;
END $$;
REVOKE ALL ON FUNCTION lock_authority(uuid),lock_execution_grant(uuid,uuid,uuid),lock_source_reference(uuid,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lock_authority(uuid),lock_execution_grant(uuid,uuid,uuid),lock_source_reference(uuid,uuid,text,text) TO pgws_worker;
