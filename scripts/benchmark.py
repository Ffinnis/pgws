#!/usr/bin/env python3
"""Measure the real API/SQL path using fresh workspaces and an approved baseline."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import json
import math
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import threading
import time
import uuid
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'sdk/python'))
from pgws import Client


def distribution(values):
    ordered = sorted(values)
    return {'count': len(ordered), 'min_seconds': min(ordered), 'max_seconds': max(ordered),
            'p50_seconds': ordered[math.ceil(len(ordered)*0.50)-1],
            'p95_seconds': ordered[math.ceil(len(ordered)*0.95)-1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', type=Path, default=ROOT/'.local/dev-client.json')
    parser.add_argument('--certificate', type=Path, default=ROOT/'.local/dev-ca.crt')
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--workspaces', type=int, default=2)
    parser.add_argument('--rounds', type=int, default=1)
    parser.add_argument('--output', type=Path, default=ROOT/'evidence/workspace-benchmark.json')
    args = parser.parse_args()
    if not 1 <= args.workspaces <= 14 or not 1 <= args.rounds <= 20:
        parser.error('workspaces must be 1..14 and rounds must be 1..20')
    if not args.certificate.is_file() or not shutil.which('psql'):
        parser.error('psql and an existing SQL trust certificate are required')
    cfg = json.loads(args.client.read_text())
    run_id = str(uuid.uuid4())
    admitted = []
    unconfirmed_admissions = set()
    lock = threading.Lock()
    results, cleanup_errors = [], []
    failed = None

    def client():
        return Client(cfg['url'], cfg['project_id'], cfg['token'])

    def query(credential, sql):
        endpoint = credential['endpoint']
        env = dict(os.environ, PGHOST=endpoint['hostname'], PGPORT=str(endpoint['port']),
                   PGDATABASE=endpoint['database'], PGUSER=credential['username'], PGPASSWORD=credential['password'],
                   PGSSLMODE='verify-full', PGSSLROOTCERT=str(args.certificate.resolve()), PGCONNECT_TIMEOUT='5')
        result = subprocess.run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'], input=sql.encode(),
                                env=env, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError('SQL verification failed; connection details withheld')
        return result.stdout.decode().strip()

    def create(round_number, ordinal):
        c = client()
        key = f'benchmark-{run_id}-{round_number}-{ordinal}'
        started = time.monotonic()
        # Repeat the exact admission key after a lost response. If all replies
        # are lost, retain the key in evidence instead of claiming full cleanup.
        with lock:
            unconfirmed_admissions.add(key)
        for attempt in range(3):
            try:
                created = c.create(args.baseline, key, key=key, ttl=1800)
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError):
                if attempt == 2:
                    raise
                time.sleep(0.2 * (attempt+1))
        workspace = created['workspace']['id']
        with lock:
            admitted.append((workspace, key))
            unconfirmed_admissions.remove(key)
        c.wait(created['operation']['id'], timeout=600)
        ready = time.monotonic()
        state = c.get(workspace)
        if state['phase'] != 'ready':
            raise RuntimeError('operation succeeded without workspace readiness')
        credential = c.credentials(workspace, state['generation'], key=key+'-credential', ttl=900)
        credential_time = time.monotonic()
        measured = query(credential, "SELECT pg_database_size(current_database()), current_setting('server_version_num'), pg_is_in_recovery();")
        size, version, recovery = measured.split('|')
        if recovery != 'f':
            raise RuntimeError('workspace is still a replica')
        sql_time = time.monotonic()
        table = 'pgws_benchmark_'+run_id.replace('-', '')
        if query(credential, "SELECT to_regclass('public."+table+"') IS NULL;") != 't':
            raise RuntimeError('a newly created clone observed a sibling write')
        query(credential, f'CREATE TABLE public.{table}(value integer PRIMARY KEY); INSERT INTO public.{table} VALUES ({ordinal});')
        print(f'Round {round_number}, workspace {ordinal}: ready in {ready-started:.3f}s; SQL verified.', flush=True)
        return ({'round': round_number, 'ordinal': ordinal, 'workspace': workspace,
                 'generation': state['generation'], 'create_seconds': ready-started,
                 'credential_seconds': credential_time-ready, 'first_sql_seconds': sql_time-credential_time,
                 'database_bytes': int(size), 'server_version_num': int(version)}, credential, table)

    def cleanup():
        pending = list(admitted)
        for workspace, key in pending:
            try:
                c = client()
                state = c.get(workspace)
                if state['phase'] != 'deleted':
                    c.wait(c.delete(workspace, state['generation'], key=key+'-delete')['id'], timeout=120)
                if c.get(workspace)['phase'] != 'deleted':
                    raise RuntimeError('deletion is not confirmed')
                admitted.remove((workspace, key))
            except Exception:
                cleanup_errors.append(workspace)

    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        for round_number in range(1, args.rounds+1):
            with ThreadPoolExecutor(max_workers=args.workspaces) as pool:
                futures = [pool.submit(create, round_number, n) for n in range(1, args.workspaces+1)]
                round_results = []
                errors = []
                for future in as_completed(futures):
                    try:
                        round_results.append(future.result())
                    except Exception as error:
                        errors.append(type(error).__name__)
                # Join every admission before cleanup; no background create can
                # otherwise add a workspace after the cleanup inventory is read.
                if errors:
                    raise RuntimeError('workspace round failed: '+', '.join(errors))
            for result, credential, table in round_results:
                if query(credential, f'SELECT value FROM public.{table};') != str(result['ordinal']):
                    raise RuntimeError('independent workspace writes differ')
                results.append(result)
            cleanup()
            if cleanup_errors:
                raise RuntimeError('workspace cleanup needs inspection')
    except Exception as error:
        failed = str(error)
    finally:
        cleanup()
        report = {'status': 'passed' if failed is None and not cleanup_errors else 'failed',
                  'run_id': run_id, 'started_at': started_at,
                  'finished_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'driver_platform': platform.platform(), 'baseline_id': args.baseline,
                  'concurrent_workspaces': args.workspaces, 'rounds': args.rounds,
                  'percentile_method': 'nearest rank; small samples are not performance qualification',
                  'results': sorted(results, key=lambda r: (r['round'], r['ordinal'])),
                  'cleanup_unconfirmed': sorted(workspace for workspace, _ in admitted),
                  'admission_unconfirmed_keys': sorted(unconfirmed_admissions), 'error': failed,
                  'full_rfc_benchmark_qualified': False,
                  'not_measured': ['source load', 'cell resident memory', 'recovery under power loss',
                                   '1 TB / fourteen-workspace qualification']}
        if results:
            report['create_latency'] = distribution([r['create_seconds'] for r in results])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2)+'\n')
    if report['status'] != 'passed':
        raise SystemExit('Benchmark failed; inspect '+str(args.output)+' and any cleanup_unconfirmed workspace IDs.')
    print(json.dumps(report['create_latency']))
    print('Evidence: '+str(args.output))


if __name__ == '__main__':
    main()
