SET LOCAL search_path=pgws_control,pg_catalog;
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='pgws_worker') THEN
  CREATE ROLE pgws_worker NOLOGIN NOSUPERUSER NOBYPASSRLS;
 ELSIF EXISTS(SELECT FROM pg_roles WHERE rolname='pgws_worker' AND (rolsuper OR rolbypassrls OR rolcanlogin)) THEN
  RAISE EXCEPTION 'existing pgws_worker role has unsafe attributes';
 END IF;
END $$;
GRANT USAGE ON SCHEMA pgws_control TO pgws_worker;
GRANT SELECT ON ALL TABLES IN SCHEMA pgws_control TO pgws_worker;
GRANT INSERT,UPDATE ON sources,baselines,snapshots,workspaces,workspace_generations,
 operations,operation_steps,snapshot_refs,credentials,audit_events,usage_events TO pgws_worker;
-- This is the trusted management worker for the dedicated deployment. It may
-- process each configured project, but cannot mutate authority or API grants.
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['projects','sources','privacy_policies','baselines',
  'snapshots','workspaces','workspace_generations','operations','operation_steps',
  'snapshot_refs','credentials','audit_events','usage_events',
  'approved_source_references','api_replays'] LOOP
  EXECUTE format('CREATE POLICY worker_scope ON %I TO pgws_worker USING(true) WITH CHECK(true)',t);
 END LOOP;
END $$;
