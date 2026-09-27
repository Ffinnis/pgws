#!/usr/bin/env python3
"""Build and operate the persistent service in the dedicated pgws-lab VM."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
local = root/'.local'
go = ['rtk', 'go'] if shutil.which('rtk') else ['go']
vm = ['limactl', 'shell', 'pgws-lab', 'sudo']
action = sys.argv[1] if len(sys.argv)>1 else 'status'

def private(name, content):
    local.mkdir(mode=0o700, exist_ok=True)
    local.chmod(0o700)
    path = local/name
    with os.fdopen(os.open(path, os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW, 0o600), 'wb') as file:
        file.write(content)
    path.chmod(0o600)

if action=='cli':
    client = json.loads((local/'dev-client.json').read_text())
    env = dict(os.environ, PGWS_URL=client['url'], PGWS_PROJECT_ID=client['project_id'], PGWS_TOKEN=client['token'])
    raise SystemExit(subprocess.run([root/'bin/pgws']+sys.argv[2:], env=env).returncode)
if action not in ('up', 'upgrade', 'workspace', 'down', 'status'):
    raise SystemExit('usage: python3 scripts/dev.py up|upgrade|workspace|down|status|cli [CLI arguments]')
if action in ('up', 'upgrade'):
    env = dict(os.environ, GOOS='linux', GOARCH='arm64', CGO_ENABLED='0')
    for name in ('pgws', 'pgwsd', 'pgws-host', 'pgws-guard', 'pgws-watchdog'):
        subprocess.run(go+['build', '-o', str(root/'bin'/(name+'-linux')), './cmd/'+name], cwd=root, env=env, check=True)
    subprocess.run(go+['build', '-o', str(root/'bin/pgws'), './cmd/pgws'], cwd=root, check=True)
subprocess.run(vm+['python3', str(root/'lab/dev.py'), action, str(root)], check=True)
if action in ('up', 'upgrade'):
    private('dev-client.json', subprocess.check_output(vm+['cat', '/var/lib/pgws-dev/client.json']))
    private('dev-ca.crt', subprocess.check_output(vm+['cat', '/var/lib/pgws-dev/tls.crt']))
    print('Client configuration: '+str(local/'dev-client.json'))
    print('SQL certificate: '+str(local/'dev-ca.crt'))
    print('Try: python3 scripts/dev.py cli baselines')
elif action=='down':
    for name in ('dev-client.json','dev-ca.crt'):
        (local/name).unlink(missing_ok=True)
