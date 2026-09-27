SET LOCAL search_path=pg_catalog,pgws_control;

CREATE TABLE pgws_control.privacy_policy_bindings (
 tenant_id uuid NOT NULL,
 project_id uuid NOT NULL,
 policy_id uuid NOT NULL,
 source_id uuid NOT NULL,
 source_epoch bigint NOT NULL CHECK(source_epoch>0),
 system_identifier text NOT NULL CHECK(system_identifier ~ '^[0-9]+$'),
 timeline bigint NOT NULL CHECK(timeline>0),
 schema_hash text NOT NULL CHECK(schema_hash ~ '^[0-9a-f]{64}$'),
 key_fingerprint text NOT NULL CHECK(key_fingerprint ~ '^[0-9a-f]{64}$'),
 compiler_version text NOT NULL CHECK(compiler_version='pgws-transform-v1'),
 approval_epoch uuid,
 approved_by text,
 PRIMARY KEY(tenant_id,project_id,policy_id),
 FOREIGN KEY(tenant_id,project_id,policy_id) REFERENCES pgws_control.privacy_policies(tenant_id,project_id,id),
 FOREIGN KEY(tenant_id,project_id,source_id) REFERENCES pgws_control.sources(tenant_id,project_id,id),
 CHECK((approval_epoch IS NULL)=(approved_by IS NULL))
);
ALTER TABLE pgws_control.privacy_policy_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE pgws_control.privacy_policy_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY project_scope ON pgws_control.privacy_policy_bindings TO pgws_runtime
 USING(tenant_id=nullif(current_setting('pgws.tenant_id',true),'')::uuid
 AND project_id=nullif(current_setting('pgws.project_id',true),'')::uuid);
CREATE POLICY worker_scope ON pgws_control.privacy_policy_bindings TO pgws_worker USING(true);
GRANT SELECT ON pgws_control.privacy_policy_bindings TO pgws_runtime,pgws_worker;
ALTER TABLE pgws_control.privacy_policies ADD COLUMN revoked_at timestamptz;

CREATE FUNCTION pgws_control.preserve_policy_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pgws_control AS $$
BEGIN
 IF ROW(NEW.tenant_id,NEW.project_id,NEW.policy_id,NEW.source_id,NEW.source_epoch,
 NEW.system_identifier,NEW.timeline,NEW.schema_hash,NEW.key_fingerprint,NEW.compiler_version)
 IS DISTINCT FROM ROW(OLD.tenant_id,OLD.project_id,OLD.policy_id,OLD.source_id,OLD.source_epoch,
 OLD.system_identifier,OLD.timeline,OLD.schema_hash,OLD.key_fingerprint,OLD.compiler_version) THEN
  RAISE EXCEPTION 'policy binding is immutable; create a new policy' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER policy_binding_immutable BEFORE UPDATE ON pgws_control.privacy_policy_bindings
 FOR EACH ROW EXECUTE FUNCTION pgws_control.preserve_policy_binding();

CREATE FUNCTION pgws_control.validate_policy_approval() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pgws_control AS $$
BEGIN
 IF TG_OP='UPDATE' AND OLD.state='revoked' AND
 ROW(NEW.state,NEW.revoked_at,NEW.approved_at) IS DISTINCT FROM ROW(OLD.state,OLD.revoked_at,OLD.approved_at) THEN
  RAISE EXCEPTION 'revoked policy cannot be revived or rewritten' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND OLD.state='approved' AND NEW.state='draft' THEN
  RAISE EXCEPTION 'approved policy cannot return to draft' USING ERRCODE='23514';
 END IF;
 IF NEW.state='approved' AND (NEW.approved_at IS NULL OR NOT EXISTS(
 SELECT FROM pgws_control.privacy_policy_bindings b JOIN pgws_control.authority a ON a.singleton
 WHERE (b.tenant_id,b.project_id,b.policy_id)=(NEW.tenant_id,NEW.project_id,NEW.id)
 AND b.approval_epoch=a.epoch AND a.reconciled AND b.approved_by IS NOT NULL)) THEN
  RAISE EXCEPTION 'policy lacks a current operator approval' USING ERRCODE='23514';
 END IF;
 IF (NEW.state='revoked') IS DISTINCT FROM (NEW.revoked_at IS NOT NULL) THEN
  RAISE EXCEPTION 'policy revocation timestamp differs' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER policy_approval_guard BEFORE INSERT OR UPDATE ON pgws_control.privacy_policies
 FOR EACH ROW EXECUTE FUNCTION pgws_control.validate_policy_approval();
