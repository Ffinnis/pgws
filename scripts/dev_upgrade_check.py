#!/usr/bin/env python3
"""Upgrade the owned development service and verify a newly created SQL workspace."""
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'sdk/python'))
from pgws import Client


def main():
    psql = shutil.which('psql')
    if not psql:
        raise RuntimeError('psql is required')
    config = json.loads((ROOT/'.local/dev-client.json').read_text())
    client = Client(config['url'], config['project_id'], config['token'])
    status = json.loads(subprocess.check_output([sys.executable, ROOT/'scripts/dev.py', 'status']))
    marker = str(uuid.uuid4())
    created = client.create(status['baseline_id'], 'upgrade-check-'+marker, key=marker, ttl=1800)
    workspace_id = created['workspace']['id']
    passed = False
    try:
        client.wait(created['operation']['id'])
        before = client.get(workspace_id)
        credential = client.credentials(workspace_id, before['generation'], key='credential-'+marker, ttl=900)
        endpoint = credential['endpoint']
        env = dict(os.environ, PGHOST=endpoint['hostname'], PGPORT=str(endpoint['port']),
                   PGDATABASE=endpoint['database'], PGUSER=credential['username'], PGPASSWORD=credential['password'],
                   PGSSLMODE='verify-full', PGSSLROOTCERT=str(ROOT/'.local/dev-ca.crt'), PGCONNECT_TIMEOUT='5')

        def query(sql):
            result = subprocess.run([psql, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'],
                                    input=sql.encode(), env=env, capture_output=True, timeout=15)
            if result.returncode:
                raise RuntimeError('workspace SQL verification failed; credentials withheld')
            return result.stdout.decode().strip()

        query("CREATE TABLE upgrade_check(value text PRIMARY KEY); INSERT INTO upgrade_check VALUES ('"+marker+"');")
        subprocess.run([sys.executable, ROOT/'scripts/dev.py', 'upgrade'], check=True)
        after = client.get(workspace_id)
        if before['generation'] != after['generation'] or after['phase'] != 'ready':
            raise RuntimeError('upgrade changed workspace generation or readiness')
        if query('SELECT value FROM upgrade_check') != marker:
            raise RuntimeError('upgrade lost workspace data')
        # The old credential still works. Also prove the new worker can issue a
        # new one and execute lifecycle operations against the preserved host.
        fresh = client.credentials(workspace_id, after['generation'], key='new-credential-'+marker, ttl=300)
        env.update(PGUSER=fresh['username'], PGPASSWORD=fresh['password'])
        query("UPDATE upgrade_check SET value='after-upgrade';")
        if query('SELECT value FROM upgrade_check') != 'after-upgrade':
            raise RuntimeError('upgraded workspace is not writable')
        if not client.usage(limit=1)['items']:
            raise RuntimeError('capacity delivery is missing')
        passed = True
    finally:
        current = client.get(workspace_id)
        if current['phase'] != 'deleted':
            client.wait(client.delete(workspace_id, current['generation'], key='delete-'+marker)['id'])
        if client.get(workspace_id)['phase'] != 'deleted':
            raise RuntimeError('verification workspace cleanup failed')
    if passed:
        evidence = {'recorded_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'scope': 'persistent development service upgrade with a newly created verification workspace',
                    'checks': ['pre-upgrade SQL write', 'management dump and migrations',
                               'preserved generation and credential', 'post-upgrade SQL read/write',
                               'new credentials', 'capacity API', 'verification workspace deletion'],
                    'status': 'passed'}
        (ROOT/'evidence/dev-upgrade.json').write_text(json.dumps(evidence, indent=2)+'\n')
        print('Development upgrade passed: SQL data, credentials, usage and deletion.')


if __name__ == '__main__':
    main()
