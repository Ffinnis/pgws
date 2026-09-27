#!/usr/bin/env python3
"""Run lineage-constraint tests in an isolated, temporary local PostgreSQL cluster.

Requires initdb, pg_ctl and psql on PATH. Never connects to an existing server.
The output records the actual PostgreSQL version; PostgreSQL 18 remains the target.
"""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
for binary in ('initdb', 'pg_ctl', 'psql'):
    if not shutil.which(binary):
        raise SystemExit(f'Missing {binary}; put one matching PostgreSQL installation on PATH')

def run(*args):
    return subprocess.run(args, text=True, check=True, capture_output=True).stdout

with tempfile.TemporaryDirectory(prefix='pgws-contract-') as temporary:
    directory = Path(temporary)
    data, socket = directory / 'data', directory / 'socket'
    socket.mkdir(mode=0o700)
    run('initdb', '-D', str(data), '--auth-local=trust', '--auth-host=reject',
        '--no-locale', '-E', 'UTF8')
    started = False
    try:
        run('pg_ctl', '-D', str(data), '-l', str(directory / 'server.log'),
            '-o', f"-c listen_addresses='' -c unix_socket_directories='{socket}' -p 55438",
            '-w', 'start')
        started = True
        connection = ['psql', '-X', '-h', str(socket), '-p', '55438',
                      '-d', 'postgres', '-v', 'ON_ERROR_STOP=1', '-qAt']
        run(*connection, '-f', str(ROOT / 'control-plane.sql'))
        report = run(*connection, '-f', str(ROOT / 'control-plane-tests.sql'))
        print(json.dumps(json.loads(report), indent=2))
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.stderr or error.stdout) from error
    finally:
        if started:
            run('pg_ctl', '-D', str(data), '-m', 'fast', '-w', 'stop')
