-- Executed only in the temporary database created by test_control_plane.py.
SET search_path = pgws_control, pg_catalog;
CREATE TEMP TABLE results (label text PRIMARY KEY);
CREATE FUNCTION pg_temp.must_reject(label text, command text, expected_state text)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE actual_state text;
BEGIN
  BEGIN
    EXECUTE command;
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS actual_state = RETURNED_SQLSTATE;
  END;
  IF actual_state IS DISTINCT FROM expected_state THEN
    RAISE EXCEPTION '%: expected %, received %', label, expected_state, actual_state;
  END IF;
  INSERT INTO results VALUES (label);
END;
$$;
INSERT INTO tenants(id,name) VALUES ('00000000-0000-0000-0000-000000000001','test');
INSERT INTO projects(tenant_id,id,name) VALUES
 ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','one'),
 ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000003','two');
INSERT INTO sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status)
 VALUES ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',
 '00000000-0000-0000-0000-000000000004','physical','test','test','registered');
INSERT INTO sources SELECT tenant_id,project_id,'00000000-0000-0000-0000-000000000008',
 'logical',source_epoch,system_identifier,timeline,endpoint_reference,secret_reference,
 status,discovery_manifest,observed_at,created_at FROM sources;
INSERT INTO privacy_policies(tenant_id,project_id,id,version,policy_hash,policy_document,state)
 VALUES ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',
 '00000000-0000-0000-0000-000000000005',1,repeat('a',64),'{}','approved');
INSERT INTO baselines(tenant_id,project_id,id,source_id,generation,source_epoch,source_timeline,
 kind,runtime_digest,compatibility_manifest,state) VALUES
 ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',
 '00000000-0000-0000-0000-000000000006','00000000-0000-0000-0000-000000000004',1,1,1,
 'physical_standby','test','{}','ready');
INSERT INTO baselines SELECT tenant_id, project_id,
 '00000000-0000-0000-0000-000000000007', '00000000-0000-0000-0000-000000000008', 2, source_epoch, source_timeline,
 'logical_writer', '00000000-0000-0000-0000-000000000005', repeat('a',64),
 runtime_digest,compatibility_manifest,state,observed_applied_source_lsn,observed_at,created_at
 FROM baselines WHERE generation=1;
INSERT INTO snapshots(tenant_id,project_id,id,baseline_id,source_epoch,source_timeline,policy_hash,state)
 SELECT tenant_id,project_id,id,id,source_epoch,source_timeline,privacy_policy_hash,'pending' FROM baselines;
INSERT INTO results VALUES ('valid raw and sanitized snapshots accepted');
DO $$
DECLARE base_command text;
BEGIN
  base_command := 'INSERT INTO baselines SELECT tenant_id,project_id,gen_random_uuid(),source_id,99,source_epoch,source_timeline,%L,%s,%s,runtime_digest,compatibility_manifest,state,observed_applied_source_lsn,observed_at,created_at FROM baselines WHERE generation=1';
  PERFORM pg_temp.must_reject('logical baseline without policy',
    format(base_command,'logical_writer','NULL','NULL'),'23514');
  PERFORM pg_temp.must_reject('physical baseline with policy',
    format(base_command,'physical_standby',quote_literal('00000000-0000-0000-0000-000000000005')||'::uuid',quote_literal(repeat('a',64))),'23514');
  PERFORM pg_temp.must_reject('snapshot wrong epoch',
    'INSERT INTO snapshots SELECT tenant_id,project_id,gen_random_uuid(),baseline_id,2,source_timeline,requested_source_lsn,captured_source_lower_bound,policy_hash,storage_name,storage_guid,capture_operation_id,state,captured_at,created_at FROM snapshots LIMIT 1','23514');
  PERFORM pg_temp.must_reject('snapshot wrong timeline',
    'INSERT INTO snapshots SELECT tenant_id,project_id,gen_random_uuid(),baseline_id,source_epoch,2,requested_source_lsn,captured_source_lower_bound,policy_hash,storage_name,storage_guid,capture_operation_id,state,captured_at,created_at FROM snapshots LIMIT 1','23514');
  PERFORM pg_temp.must_reject('raw snapshot incorrectly labeled sanitized',
    'INSERT INTO snapshots SELECT tenant_id,project_id,gen_random_uuid(),baseline_id,source_epoch,source_timeline,requested_source_lsn,captured_source_lower_bound,repeat(''a'',64),storage_name,storage_guid,capture_operation_id,state,captured_at,created_at FROM snapshots WHERE policy_hash IS NULL','23514');
  PERFORM pg_temp.must_reject('sanitized snapshot missing policy',
    'INSERT INTO snapshots SELECT tenant_id,project_id,gen_random_uuid(),baseline_id,source_epoch,source_timeline,requested_source_lsn,captured_source_lower_bound,NULL,storage_name,storage_guid,capture_operation_id,state,captured_at,created_at FROM snapshots WHERE policy_hash IS NOT NULL','23514');
  PERFORM pg_temp.must_reject('snapshot wrong policy hash',
    'INSERT INTO snapshots SELECT tenant_id,project_id,gen_random_uuid(),baseline_id,source_epoch,source_timeline,requested_source_lsn,captured_source_lower_bound,repeat(''b'',64),storage_name,storage_guid,capture_operation_id,state,captured_at,created_at FROM snapshots WHERE policy_hash IS NOT NULL','23514');
  PERFORM pg_temp.must_reject('cross-project snapshot reference',
    'INSERT INTO snapshots SELECT tenant_id,''00000000-0000-0000-0000-000000000003'',gen_random_uuid(),baseline_id,source_epoch,source_timeline,requested_source_lsn,captured_source_lower_bound,policy_hash,storage_name,storage_guid,capture_operation_id,state,captured_at,created_at FROM snapshots LIMIT 1','23503');
  PERFORM pg_temp.must_reject('baseline identity mutation',
    'UPDATE baselines SET source_epoch=2','23514');
  PERFORM pg_temp.must_reject('baseline runtime mutation',
    'UPDATE baselines SET runtime_digest=''other''','23514');
  PERFORM pg_temp.must_reject('snapshot identity mutation',
    'UPDATE snapshots SET source_epoch=2','23514');
  PERFORM pg_temp.must_reject('policy document mutation',
    'UPDATE privacy_policies SET policy_document='' {"changed":true} ''::jsonb','23514');
END;
$$;
UPDATE privacy_policies SET state='revoked';
UPDATE baselines SET state='blocked', observed_at=now();
UPDATE snapshots SET state='held';
INSERT INTO results VALUES ('policy revocation and operational-state updates remain allowed');
SELECT json_build_object('status','database_contract_checks_passed',
 'postgresql_version',version(),'check_count',(SELECT count(*) FROM results),
 'checks',(SELECT json_agg(label ORDER BY label) FROM results),
 'not_validated',json_build_array('PostgreSQL/ZFS recovery and service behavior',
 'Concurrent publication/revocation and runtime grants/RLS',
 'T-23 through T-29 end-to-end acceptance; this suite covers only selected T-29 constraints'));
