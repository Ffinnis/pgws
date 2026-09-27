SET LOCAL search_path = pgws_control, pg_catalog;

CREATE TABLE authority (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  epoch uuid NOT NULL,
  reconciled boolean NOT NULL DEFAULT false
);
CREATE TABLE api_tokens (
  token_hash text PRIMARY KEY CHECK (length(token_hash) = 64),
  principal_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  is_admin boolean NOT NULL DEFAULT false,
  allow_raw boolean NOT NULL DEFAULT false,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)
);
CREATE TABLE approved_source_references (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_reference text NOT NULL,
  secret_reference text NOT NULL,
  PRIMARY KEY (tenant_id, project_id, endpoint_reference, secret_reference),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)
);
ALTER TABLE operations ADD COLUMN request_document jsonb NOT NULL DEFAULT '{}';
ALTER TABLE operations ADD COLUMN actor_reference uuid;
ALTER TABLE operations ADD COLUMN authority_epoch uuid;
ALTER TABLE workspaces ADD COLUMN requested_baseline_id uuid;
ALTER TABLE workspaces ADD COLUMN requested_freshness jsonb NOT NULL DEFAULT '{}';
ALTER TABLE workspaces ADD CONSTRAINT requested_baseline_fk
  FOREIGN KEY (tenant_id, project_id, requested_baseline_id)
  REFERENCES baselines(tenant_id, project_id, id);
CREATE TABLE api_replays (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  scope text NOT NULL,
  key text NOT NULL CHECK (length(key) BETWEEN 1 AND 200),
  request_hash text NOT NULL,
  status integer NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, project_id, principal_id, scope, key),
  FOREIGN KEY (tenant_id, project_id) REFERENCES projects(tenant_id, id)
);

-- Migrations run under a database owner; the API uses this non-owner role.
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pgws_runtime') THEN
    CREATE ROLE pgws_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
  ELSIF EXISTS (SELECT FROM pg_roles WHERE rolname='pgws_runtime'
               AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
    RAISE EXCEPTION 'existing pgws_runtime role has unsafe attributes';
  END IF;
END $$;
GRANT USAGE ON SCHEMA pgws_control TO pgws_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA pgws_control TO pgws_runtime;
GRANT INSERT ON sources, workspaces, operations, api_replays, audit_events TO pgws_runtime;
GRANT UPDATE ON workspaces TO pgws_runtime;

-- Both tenant and project must be set transaction-locally by authenticated code.
DO $$ DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['projects','sources','privacy_policies','baselines',
    'snapshots','workspaces','workspace_generations','operations','operation_steps',
    'snapshot_refs','credentials','audit_events','usage_events',
    'approved_source_references','api_replays'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY project_scope ON %I TO pgws_runtime USING
      (tenant_id = nullif(current_setting(''pgws.tenant_id'', true), '''')::uuid AND
       %I = nullif(current_setting(''pgws.project_id'', true), '''')::uuid)
      WITH CHECK
      (tenant_id = nullif(current_setting(''pgws.tenant_id'', true), '''')::uuid AND
       %I = nullif(current_setting(''pgws.project_id'', true), '''')::uuid)',
      t, CASE WHEN t = 'projects' THEN 'id' ELSE 'project_id' END,
      CASE WHEN t = 'projects' THEN 'id' ELSE 'project_id' END);
  END LOOP;
END $$;
REVOKE ALL ON tenants, credentials FROM pgws_runtime;
