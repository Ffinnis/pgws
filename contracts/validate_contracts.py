#!/usr/bin/env python3
"""Static contract checks; does not run PostgreSQL or a full OpenAPI conformance suite.
Install contracts/requirements.txt. Run from any directory with Python 3.
"""
from __future__ import annotations
import json
import re
from pathlib import Path
import yaml
from jsonschema import Draft202012Validator, FormatChecker

if 'date-time' not in FormatChecker.checkers:
    raise SystemExit('Missing date-time format validator; install contracts/requirements.txt')

ROOT = Path(__file__).resolve().parent
spec = yaml.safe_load((ROOT / 'openapi.yaml').read_text())
assert spec['openapi'] == '3.1.0'
checks: list[str] = []

def resolve(ref: str):
    assert ref.startswith('#/'), f'Only local references are expected: {ref}'
    value = spec
    for part in ref[2:].split('/'):
        value = value[part.replace('~1','/').replace('~0','~')]
    return value

def walk(value):
    if isinstance(value, dict):
        if '$ref' in value:
            resolve(value['$ref'])
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

walk(spec)
checks.append('All local OpenAPI references resolve.')
ids = set()
for path, methods in spec['paths'].items():
    required = set(re.findall(r'\{([^}]+)\}', path))
    for method, operation in methods.items():
        operation_id = operation['operationId']
        assert operation_id not in ids
        ids.add(operation_id)
        parameters = [resolve(p['$ref']) if '$ref' in p else p
                      for p in operation.get('parameters', [])]
        actual = {p['name'] for p in parameters if p['in'] == 'path' and p['required']}
        assert actual == required, (path, actual, required)
        if method in ('post', 'put', 'patch', 'delete'):
            assert any(p['name'] == 'Idempotency-Key' and p['required'] for p in parameters)
        assert any(str(code).startswith('2') for code in operation['responses'])
checks.append(f'{len(ids)} operations have unique IDs, matching path parameters, success responses, and write idempotency headers.')

for name, schema in spec['components']['schemas'].items():
    Draft202012Validator.check_schema(schema)
checks.append(f"{len(spec['components']['schemas'])} component schemas pass JSON Schema 2020-12 syntax checks.")

# The OpenAPI components object is retained as a reference-resolution container.
def valid(name, instance):
    root = {'$ref': f'#/components/schemas/{name}', 'components': spec['components']}
    return not list(Draft202012Validator(root, format_checker=FormatChecker()).iter_errors(instance))

uid = '22222222-2222-4222-8222-222222222222'
base = {'baseline_id':uid,'task_id':'checkout-test','freshness':{'mode':'latest'},
        'resource_profile':'small','ttl_seconds':28800}
extension = {'action':'extend_ttl', 'expected_generation':1,
             'expected_expires_at':'2026-09-19T12:00:00Z',
             'expires_at':'2026-09-19T16:00:00Z'}
cases = [
 ('SourceAction', {'action':'reseed','expected_source_epoch':1}, True),
 ('SourceAction', {'action':'reseed','expected_source_epoch':0}, False),
 ('SourceAction', {'action':'reseed','expected_source_epoch':1,'source_dsn':'arbitrary'}, False),
 ('SourceAction', {'action':'reseed'}, False),
 ('CreateWorkspace', base, True),
 ('CreateWorkspace', {**base, 'anonymize':False}, False),
 ('CreateWorkspace', {**base, 'source_dsn':'postgresql://source'}, False),
 ('CreateWorkspace', {**base, 'ttl_seconds':0}, False),
 ('CreateWorkspace', {**base, 'baseline_id':'not-a-uuid'}, False),
 ('Freshness', {'mode':'latest'}, True),
 ('Freshness', {'mode':'at_least','barrier_token':'opaque'}, True),
 ('Freshness', {'mode':'at_least'}, False),
 ('Freshness', {'mode':'snapshot','snapshot_id':uid}, True),
 ('Freshness', {'mode':'snapshot','barrier_token':'wrong'}, False),
 ('Freshness', {'mode':'latest','barrier_token':'unexpected'}, False),
 ('BarrierRequest', {'after_commit_asserted':True}, True),
 ('BarrierRequest', {'after_commit_asserted':False}, False),
 ('Action', extension, True),
 ('Action', {k:v for k,v in extension.items() if k != 'expected_expires_at'}, False),
 ('Action', {**extension, 'expected_generation':0}, False),
 ('Action', {**extension, 'expires_at':'tomorrow'}, False),
 ('Action', {**extension, 'additional_seconds':3600}, False),
 ('Action', {'action':'pause','expected_generation':1}, True),
 ('Action', {'action':'resume','expected_generation':1}, True),
 ('Action', {'action':'reset','expected_generation':1,'discard_local_changes':True,
             'baseline_id':uid,'freshness':{'mode':'latest'}}, True),
 ('Action', {'action':'reset','expected_generation':1,'discard_local_changes':False,
             'baseline_id':uid,'freshness':{'mode':'latest'}}, False),
]
for schema, instance, expected in cases:
    assert valid(schema, instance) == expected, (schema, instance, expected)
checks.append(f'{len(cases)} positive/negative request examples produce the expected validation result.')

sql = (ROOT / 'control-plane.sql').read_text()
assert 'BEGIN;' in sql and sql.rstrip().endswith('COMMIT;')
assert 'DEFERRABLE INITIALLY DEFERRED' in sql
assert 'FOREIGN KEY (tenant_id, project_id' in sql
checks.append('SQL file presence and selected design markers checked only; SQL was NOT parsed or executed on PostgreSQL.')
report = {
 'status':'static_checks_passed', 'checks':checks,
 'not_validated':[
  'Full OpenAPI conformance using a dedicated OpenAPI validator',
  'PostgreSQL SQL syntax, migrations, constraints, concurrency, and application behavior',
  'Live source replication, filesystem recovery, security, and workload performance',
  'Expiry ordering, seven-day cap, authorization, host acknowledgement, and expiry races require service tests'
 ]
}
print(json.dumps(report, indent=2))
