#!/usr/bin/env python3
"""Persistent, disposable development service inside the dedicated Linux VM."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = Path('/var/lib/pgws-dev')
IMAGE = 'postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae'
URL = 'http://127.0.0.1:18870'
os.umask(0o077)


def run(args, data=None, env=None, check=True):
    result = subprocess.run([str(a) for a in args], input=data, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and result.returncode:
        # Passwords and bootstrap responses never appear in diagnostics.
        raise RuntimeError(f'{args[0]} {args[1] if len(args)>1 else ""} failed ({result.returncode})')
    return result.stdout


def write(path, value, mode=0o600, uid=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    path.chmod(mode)
    if uid is not None:
        os.chown(path, uid, pwd.getpwuid(uid).pw_gid if uid != 999 else 999)
    return str(path)


def save(state):
    atomic_write(ROOT/'state.json', (json.dumps(state, indent=2)+'\n').encode())


def atomic_write(path, data, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
            os.fchmod(file.fileno(), mode)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def sql(container, query):
    return run(['docker', 'exec', '-i', '--user', '999', container, 'psql',
                '-h', str(ROOT/'management'/'socket') if container.endswith('-mgmt') else str(ROOT/'source'/'socket'),
                '-U', 'postgres', '-d', 'postgres', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'], query.encode())


def primary(name, root, run_id):
    for part in ('data', 'control', 'socket'):
        path = root/part
        path.mkdir(parents=True)
        path.chmod(0o700)
        os.chown(path, 999, 999)
    args = ['docker', 'run', '-d', '--name', name, '--label', 'org.pgws.dev='+run_id,
            '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt',
            'no-new-privileges', '--user', '999:999', '--memory', '512m', '--memory-swap',
            '512m', '--pids-limit', '128', '--cpus', '1', '--init', '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m',
            '--tmpfs', '/var/lib/postgresql:rw,noexec,nosuid,size=1m', '--entrypoint', '/bin/sleep']
    for part in ('data', 'control', 'socket'):
        args += ['--mount', f'type=bind,src={root/part},dst={root/part}']
    run(args+[IMAGE, 'infinity'])
    run(['docker', 'exec', name, 'initdb', '-D', root/'data', '-U', 'postgres',
         '--auth-local=trust', '--auth-host=reject', '--encoding=UTF8', '--no-locale'])
    conf = f"data_directory='{root/'data'}'\nlisten_addresses=''\nunix_socket_directories='{root/'socket'}'\nshared_buffers='32MB'\nmax_connections=30\nmax_wal_senders=10\nmax_worker_processes=8\nmax_slot_wal_keep_size='128MB'\n"
    write(root/'control'/'postgresql.conf', conf, 0o644)
    run(['docker', 'exec', name, 'pg_ctl', '-D', root/'data', '-l', root/'control'/'postgres.log',
         '-o', '-c config_file='+str(root/'control'/'postgresql.conf'), '-w', 'start'])


def api(path):
    with urllib.request.urlopen(URL+path, timeout=3) as response:
        return json.load(response)


def up(project):
    if ROOT.exists():
        if (ROOT/'state.json').exists():
            status()
            return
        raise RuntimeError('development directory already exists without its ownership record')
    ROOT.mkdir(mode=0o711)
    ROOT.chmod(0o711)
    run_id = secrets.token_hex(8)
    pool = 'pgws_dev_'+run_id
    state = {'run_id': run_id, 'pool': pool, 'units': [], 'fixtures': [], 'stage': 'preparing'}
    save(state)
    for name in ('pgwsdev_api', 'pgwsdev_worker'):
        try:
            pwd.getpwnam(name)
        except KeyError:
            run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', name])
    for name in ('pgwsd', 'pgws', 'pgws-host', 'pgws-guard', 'pgws-watchdog'):
        write(ROOT/'bin'/name, (project/'bin'/(name+'-linux')).read_bytes(), 0o755)
    (ROOT/'bin').chmod(0o755)
    with (ROOT/'vdev').open('wb') as file:
        file.truncate(8 << 30)
    run(['zpool', 'create', '-m', 'none', '-o', 'cachefile=none', '-O', 'canmount=off',
         '-O', 'compression=lz4', '-O', 'atime=off', pool, ROOT/'vdev'])
    state['pool_guid'] = run(['zpool', 'get', '-H', '-o', 'value', 'guid', pool]).decode().strip()
    save(state)
    run(['zfs', 'create', '-o', 'mountpoint=none', '-o', 'canmount=off', '-o', 'org.pgws:managed=on', pool+'/pgws'])
    for part, suffix in (('source', 'source'), ('management', 'mgmt')):
        name = 'pgws-dev-'+run_id+'-'+suffix
        state['fixtures'].append(name)
        save(state)
        primary(name, ROOT/part, run_id)
    source, management = state['fixtures']
    sql(source, "CREATE TABLE notes(id integer PRIMARY KEY, body text NOT NULL); INSERT INTO notes VALUES(1,'source row'),(2,'workspace changes stay in the clone');")
    base_env = dict(os.environ, PGWS_DATABASE_URL=f'host={ROOT}/management/socket user=postgres dbname=postgres sslmode=disable')
    run([ROOT/'bin/pgwsd', 'migrate'], env=base_env)
    boot = json.loads(run([ROOT/'bin/pgwsd', 'bootstrap'], env=base_env))
    state.update(epoch=boot['authority_epoch'], project=boot['project_id'], tenant=boot['tenant_id'])
    save(state)
    write(ROOT/'bootstrap.json', json.dumps(boot))
    sql(management, f"INSERT INTO pgws_control.approved_source_references VALUES('{boot['tenant_id']}','{boot['project_id']}','dev-source','dev-secret');")
    run(['openssl', 'genpkey', '-algorithm', 'ED25519', '-out', ROOT/'signing.pem'])
    private = run(['openssl', 'pkey', '-in', ROOT/'signing.pem', '-outform', 'DER'])
    public = run(['openssl', 'pkey', '-in', ROOT/'signing.pem', '-pubout', '-outform', 'DER'])
    if len(private)!=48 or private[:16].hex()!='302e020100300506032b657004220420' or len(public)!=44 or public[:12].hex()!='302a300506032b6570032100':
        raise RuntimeError('unexpected Ed25519 key format')
    signing = base64.b64encode(private[16:]+public[12:]).decode()
    authority = base64.b64encode(public[12:]).decode()
    encryption = base64.b64encode(secrets.token_bytes(32)).decode()
    rpc = secrets.token_hex(32)
    run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '7',
         '-subj', '/CN=PGWS local development', '-addext', 'subjectAltName=IP:127.0.0.1,DNS:127.0.0.1,DNS:localhost',
         '-keyout', ROOT/'tls.key', '-out', ROOT/'tls.crt'])
    worker_user = pwd.getpwnam('pgwsdev_worker')
    cfg = {'id': 'dev-host', 'epoch': boot['authority_epoch'], 'root': str(ROOT/'host'),
           'sockets': str(ROOT/'s'), 'dataset': pool+'/pgws', 'mount_root': str(ROOT/'mounts'),
           'guard_binary': str(ROOT/'bin/pgws-guard'), 'certificate': str(ROOT/'tls.crt'),
           'certificate_key': str(ROOT/'tls.key'), 'authority_key': authority, 'secret_key': encryption,
           'rpc_socket': str(ROOT/'rpc/host.sock'), 'rpc_group': worker_user.pw_gid,
           'sources': [{'tenant': boot['tenant_id'], 'project': boot['project_id'],
                        'endpoint_reference': 'dev-source', 'secret_reference': 'dev-secret',
                        'source': {'host': str(ROOT/'source/socket'), 'port': 5432, 'user': 'postgres',
                                   'database': 'postgres', 'approved_databases': ['postgres']}}]}
    write(ROOT/'host.json', json.dumps(cfg))
    write(ROOT/'rpc.token', rpc)
    env_paths = {}
    for name, group in (('api', 'pgws_runtime'), ('worker', 'pgws_worker')):
        account = pwd.getpwnam('pgwsdev_'+name)
        password = secrets.token_hex(32)
        sql(management, f"CREATE ROLE pgwsdev_{name} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '{password}'; GRANT {group} TO pgwsdev_{name};")
        folder = ROOT/name
        folder.mkdir(mode=0o700)
        os.chown(folder, account.pw_uid, account.pw_gid)
        env = {'PGWS_DATABASE_URL': f'host={ROOT}/management/socket user=pgwsdev_{name} password={password} dbname=postgres sslmode=disable',
               'PGWS_AUTHORITY_EPOCH': boot['authority_epoch']}
        if name=='api':
            env.update(PGWS_PHYSICAL_ENABLED='true', PGWS_LISTEN='127.0.0.1:18870',
                       PGWS_SECRET_KEY_FILE=write(folder/'secret.key', encryption, uid=account.pw_uid),
                       PGWS_AUTHORITY_KEY_FILE=write(folder/'authority.key', authority, uid=account.pw_uid))
        else:
            env.update(PGWS_HOST_SOCKET=cfg['rpc_socket'], PGWS_HOST_ID=cfg['id'],
                       PGWS_SIGNING_KEY_FILE=write(folder/'signing.key', signing, uid=account.pw_uid),
                       PGWS_HOST_TOKEN_FILE=write(folder/'rpc.token', rpc, uid=account.pw_uid))
        env_paths[name] = write(ROOT/(name+'.env'), '\n'.join(k+'="'+v+'"' for k,v in env.items())+'\n')
    (ROOT/'management').chmod(0o711)
    (ROOT/'management/socket').chmod(0o755)
    write(ROOT/'management/data/pg_hba.conf', 'local all postgres peer\nlocal all all scram-sha-256\n', uid=999)
    sql(management, 'SELECT pg_reload_conf()')
    for name, command in [('host', [ROOT/'bin/pgws-host', ROOT/'host.json', ROOT/'rpc.token']),
                          ('watchdog', [ROOT/'bin/pgws-watchdog', ROOT/'host.json']),
                          ('worker', [ROOT/'bin/pgwsd', 'worker']), ('api', [ROOT/'bin/pgwsd', 'serve'])]:
        unit = 'pgws-dev-'+name
        state['units'].append(unit)
        save(state)
        args = ['systemd-run', '--collect', '--unit='+unit, '--property=Restart=on-failure', '--property=RestartSec=2s',
                '--property=Description=PGWS disposable development '+run_id]
        if name in env_paths:
            args += ['--property=User=pgwsdev_'+name, '--property=EnvironmentFile='+env_paths[name],
                     '--property=NoNewPrivileges=yes']
        if name=='host':
            args += ['--property=KillMode=process']
        run(args+command)
    for _ in range(100):
        try:
            api('/readyz')
            break
        except (OSError, ValueError):
            time.sleep(0.1)
    else:
        raise RuntimeError('API did not start; inspect journalctl -u pgws-dev-api')
    client = {'url': URL, 'project_id': boot['project_id'], 'token': boot['token']}
    write(ROOT/'client.json', json.dumps(client))
    sys.path.insert(0, str(project/'sdk/python'))
    from pgws import Client
    c = Client(URL, boot['project_id'], boot['token'])
    registered = c.register_source('dev-source', 'dev-secret', key='dev-source')
    c.wait(registered['operation']['id'])
    state['source_id'] = registered['source_id']
    created = c.create(registered['source_id'], 'getting-started', key='getting-started', ttl=3600)
    c.wait(created['operation']['id'])
    state['workspace_id'] = created['workspace']['id']
    state['stage'] = 'ready'
    save(state)
    status()


def upgrade_storage_plan(state):
    """Recognize only this launcher's original, single-project ZFS layout."""
    cfg = json.loads((ROOT/'host.json').read_text())
    if (cfg['epoch'], cfg['id'], cfg['dataset']) != (state['epoch'], 'dev-host', state['pool']+'/pgws'):
        raise RuntimeError('host configuration differs from installation')
    project = cfg['dataset']+'/t_'+state['tenant']+'/p_'+state['project']
    policy = ROOT/'host/project-limits'/state['tenant']/(state['project']+'.json')
    quota = cfg.get('project_quota_bytes', 0) or 2 << 30
    legacy = not policy.exists()
    for path in (ROOT/'host/objects').glob('*/*/state.json'):
        item = json.loads(path.read_text())
        if item['phase'] == 'deleted':
            continue
        identity = item['task']['command']
        if any(identity[key] != value for key, value in
               [('epoch', state['epoch']), ('tenant', state['tenant']), ('project', state['project']), ('host', 'dev-host')]):
            raise RuntimeError('generation scope differs from development installation')
        guard = item.get('guard_directory')
        if guard:
            config = json.loads((Path(guard)/'config.json').read_text())
            if config.get('runtime_stop_file') != str(path.parent/'safety-stop.json'):
                raise RuntimeError('legacy workspace guard is incompatible; retain/export its data and retire it before upgrade')
            if item['phase'] in ('ready', 'resuming'):
                receipt = json.loads((Path(guard)/'receipt.json').read_text())
                if not receipt.get('runtime'):
                    raise RuntimeError('workspace has no durable runtime lease; refusing upgrade')
        if legacy:
            # No live workspace can race the adoption of the old uncharged
            # ancestor. Only the launcher's already recorded baseline is allowed.
            if identity['workspace'] != state['source_id'] or item['phase'] != 'streaming':
                raise RuntimeError('legacy quota migration requires only the recorded streaming baseline')
            volume = item['volume']
            if volume['name'] != project+'/baselines/'+state['source_id']+'/g'+str(identity['generation']):
                raise RuntimeError('legacy baseline dataset path differs')
            props = dict(line.split('\t', 1) for line in run(['zfs', 'get', '-H', '-p', '-o', 'property,value',
                         'guid,org.pgws:tenant,org.pgws:project,org.pgws:resource,org.pgws:generation', volume['name']]).decode().splitlines())
            if any(props[key] != value for key, value in [('guid', volume['guid']), ('org.pgws:tenant', state['tenant']),
                   ('org.pgws:project', state['project']), ('org.pgws:resource', state['source_id']),
                   ('org.pgws:generation', str(identity['generation']))]):
                raise RuntimeError('legacy baseline GUID or ownership differs')
    props = dict(line.split('\t', 1) for line in run(['zfs', 'get', '-H', '-p', '-o', 'property,value',
                 'guid,used,quota,org.pgws:managed,org.pgws:tenant,org.pgws:project,mountpoint,canmount', project]).decode().splitlines())
    if legacy:
        if props['quota'] not in ('0', str(quota)) or props['org.pgws:managed'] not in ('on', 'project'):
            raise RuntimeError('legacy project quota or ownership differs')
        if props['org.pgws:tenant'] not in ('-', state['tenant']) or props['org.pgws:project'] not in ('-', state['project']):
            raise RuntimeError('legacy project belongs to a different scope')
        if props['mountpoint'] != 'none' or props['canmount'] not in ('on', 'off') or int(props['used']) > quota-(32 << 20):
            raise RuntimeError('legacy project cannot fit the configured allocation policy')
    else:
        old = json.loads(policy.read_text())
        if (old['dataset'], old['quota_bytes'], old['tenant'], old['project']) != (
                {'name': project, 'guid': props['guid']}, quota, state['tenant'], state['project']):
            raise RuntimeError('durable allocation policy differs')
    return {'path': str(policy), 'legacy': legacy, 'record': {'tenant': state['tenant'], 'project': state['project'],
            'quota_bytes': quota, 'dataset': {'name': project, 'guid': props['guid']}}}


def upgrade(project):
    state = json.loads((ROOT/'state.json').read_text())
    if state['stage'] not in ('ready', 'upgrading', 'upgrade_failed'):
        raise RuntimeError('installation is incomplete; refusing upgrade')
    expected_units = ['pgws-dev-'+name for name in ('host', 'watchdog', 'worker', 'api')]
    if state['units'] != expected_units:
        raise RuntimeError('unexpected service ownership record')
    actual = run(['zpool', 'get', '-H', '-o', 'value', 'guid', state['pool']]).decode().strip()
    if actual != state['pool_guid']:
        raise RuntimeError('pool identity changed; refusing upgrade')
    expected_fixtures = ['pgws-dev-'+state['run_id']+'-'+suffix for suffix in ('source', 'mgmt')]
    if state['fixtures'] != expected_fixtures:
        raise RuntimeError('unexpected database ownership record')
    for container in expected_fixtures:
        info = json.loads(run(['docker', 'inspect', container]))[0]
        if info['Config']['Labels'].get('org.pgws.dev') != state['run_id'] or not info['State']['Running']:
            raise RuntimeError('database identity or running state changed')
    for unit in expected_units:
        description = run(['systemctl', 'show', '--value', '--property=Description', unit]).decode().strip()
        if description != 'PGWS disposable development '+state['run_id']:
            raise RuntimeError('systemd unit ownership changed; refusing upgrade')
    storage = upgrade_storage_plan(state)
    names = ('pgws', 'pgwsd', 'pgws-host', 'pgws-guard', 'pgws-watchdog')
    # Read all inputs before touching the running installation. ELF identifies
    # Linux ARM64 and rejects an accidentally supplied native macOS executable.
    binaries = {name: (project/'bin'/(name+'-linux')).read_bytes() for name in names}
    for data in binaries.values():
        if len(data) < 64 or data[:6] != b'\x7fELF\x02\x01' or data[18:20] != b'\xb7\x00':
            raise RuntimeError('upgrade requires Linux ARM64 executables')
    backup = ROOT/'upgrades'/(time.strftime('%Y%m%dT%H%M%S')+'-'+secrets.token_hex(4))
    backup.mkdir(parents=True, mode=0o700)
    (backup.parent).chmod(0o700)
    (backup/'bin').mkdir(mode=0o700)
    for name in names:
        atomic_write(backup/'bin'/name, (ROOT/'bin'/name).read_bytes(), 0o700)
    for path in ROOT.iterdir():
        if path.is_file() and path.name != 'vdev':
            atomic_write(backup/path.name, path.read_bytes())
    for name in ('api', 'worker'):
        shutil.copytree(ROOT/name, backup/name)
    management = expected_fixtures[1]
    # The peer-authenticated owner runs inside the database container. No owner
    # password is introduced and neither daemon gets migration privileges.
    dump = run(['docker', 'exec', '--user', '999', management, 'pg_dump', '-Fc',
                '-h', ROOT/'management/socket', '-U', 'postgres', '-d', 'postgres'])
    run(['docker', 'exec', '-i', '--user', '999', management, 'pg_restore', '--list'], dump)
    atomic_write(backup/'management.dump', dump)
    manifest = {'run_id': state['run_id'], 'pool_guid': state['pool_guid'], 'epoch': state['epoch'],
                'dump_sha256': hashlib.sha256(dump).hexdigest(),
                'binaries': {name: hashlib.sha256(data).hexdigest() for name, data in binaries.items()},
                'storage': storage, 'status': 'prepared'}
    atomic_write(backup/'upgrade.json', (json.dumps(manifest, indent=2)+'\n').encode())
    state.update(stage='upgrading', upgrade_backup=str(backup))
    save(state)
    migration_binary = ROOT/'management/control'/('pgwsd-upgrade-'+secrets.token_hex(8))
    try:
        atomic_write(migration_binary, binaries['pgwsd'], 0o555)
        run(['docker', 'exec', '--user', '999', '--env',
             f'PGWS_DATABASE_URL=host={ROOT}/management/socket user=postgres dbname=postgres sslmode=disable',
             management, migration_binary, 'migrate'])
        if storage['legacy']:
            record = storage['record']
            # All GUID checks precede the explicit one-time local migration.
            run(['zfs', 'set', 'quota='+str(record['quota_bytes']), 'mountpoint=none', 'canmount=off', 'org.pgws:managed=project',
                 'org.pgws:tenant='+record['tenant'], 'org.pgws:project='+record['project'], record['dataset']['name']])
            path = Path(storage['path'])
            path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            atomic_write(path, (json.dumps(record, indent=2)+'\n').encode())
        for name, data in binaries.items():
            atomic_write(ROOT/'bin'/name, data, 0o755)
        # Restart keeps transient units registered. Stop/start with --collect
        # would discard their environment and privilege configuration.
        for unit in expected_units:
            run(['systemctl', 'restart', unit])
        for _ in range(100):
            try:
                ready = bool(api('/readyz'))
                active = all(run(['systemctl', 'is-active', unit], check=False).strip() == b'active'
                             for unit in expected_units)
                if ready and active:
                    break
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        else:
            raise RuntimeError('upgraded services failed readiness; inspect service journals')
        run([ROOT/'bin/pgws-host', 'capacity', ROOT/'host.json'])
        manifest['status'] = 'complete'
        atomic_write(backup/'upgrade.json', (json.dumps(manifest, indent=2)+'\n').encode())
        state.update(stage='ready', build_sha256=manifest['binaries'])
        save(state)
    except Exception:
        state['stage'] = 'upgrade_failed'
        save(state)
        # Never restore the pre-upgrade database automatically: doing so can
        # revive revoked authorization and discard operations admitted meanwhile.
        raise RuntimeError('upgrade failed; retained backup at '+str(backup)+'; inspect service journals and retry upgrade') from None
    finally:
        migration_binary.unlink(missing_ok=True)
    status()


def status():
    state = json.loads((ROOT/'state.json').read_text())
    healthy = False
    try:
        healthy = bool(api('/readyz'))
    except (OSError, ValueError):
        pass
    print(json.dumps({'stage': state['stage'], 'api_healthy': healthy, 'url': URL,
                      'project_id': state.get('project'), 'baseline_id': state.get('source_id'),
                      'workspace_id': state.get('workspace_id'), 'client_file': str(ROOT/'client.json'),
                      'certificate': str(ROOT/'tls.crt'), 'upgrade_backup': state.get('upgrade_backup'),
                      'build_sha256': state.get('build_sha256')}))


def workspace(project):
    state = json.loads((ROOT/'state.json').read_text())
    if state['stage'] != 'ready':
        raise RuntimeError('development installation must be ready')
    sys.path.insert(0, str(project/'sdk/python'))
    from pgws import Client
    config = json.loads((ROOT/'client.json').read_text())
    client = Client(config['url'], config['project_id'], config['token'])
    if state.get('workspace_id'):
        current = client.get(state['workspace_id'])
        if current['phase'] not in ('deleted', 'failed'):
            # Preserve an existing workspace, including an intentional pause.
            status()
            return
    if 'workspace_request' not in state:
        state['workspace_request'] = 'getting-started-'+secrets.token_hex(16)
        save(state)
    key = state['workspace_request']
    created = client.create(state['source_id'], key, key=key, ttl=3600)
    # Persist the exact key before admission so a lost response cannot create
    # another example on retry. A failed operation is retained for inspection.
    client.wait(created['operation']['id'])
    state['workspace_id'] = created['workspace']['id']
    del state['workspace_request']
    save(state)
    status()


def down():
    if not ROOT.exists():
        print('Development service is already absent.')
        return
    state = json.loads((ROOT/'state.json').read_text())
    for unit in reversed(state['units']):
        run(['systemctl', 'stop', unit], check=False)
    # Stop only guards whose private control paths were recorded by this host.
    import socket
    for path in (ROOT/'host/objects').glob('*/*/ingress/guard.sock'):
        try:
            with socket.socket(socket.AF_UNIX) as conn:
                conn.settimeout(2)
                conn.connect(str(path))
                conn.sendall(b'POST /shutdown HTTP/1.1\r\nHost: guard\r\nContent-Length: 0\r\n\r\n')
                conn.recv(4096)
        except OSError:
            pass
    containers = set(run(['docker', 'ps', '-aq', '--filter', 'label=org.pgws.dev='+state['run_id']]).decode().split())
    if 'epoch' in state:
        containers.update(run(['docker', 'ps', '-aq', '--filter', 'label=org.pgws:epoch='+state['epoch'],
                               '--filter', 'label=org.pgws:host=dev-host']).decode().split())
    for container in containers:
        run(['docker', 'rm', '-f', container])
    if 'pool_guid' in state:
        actual = run(['zpool', 'get', '-H', '-o', 'value', 'guid', state['pool']]).decode().strip()
        if actual!=state['pool_guid']:
            raise RuntimeError('pool identity changed; refusing cleanup')
        run(['zpool', 'destroy', state['pool']])
    shutil.rmtree(ROOT)
    print('Removed the development service, its containers and its file-backed ZFS pool.')


if __name__=='__main__':
    if os.geteuid()!=0 or not sys.platform.startswith('linux'):
        raise SystemExit('Use scripts/dev.py in the project to operate the dedicated Linux VM.')
    try:
        # One installation mutation at a time, including down versus upgrade.
        # The lock is outside ROOT so cleanup cannot unlink a held lock.
        if sys.argv[1] != 'status':
            lock = os.open(str(ROOT)+'.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if sys.argv[1]=='up':
            up(Path(sys.argv[2]))
        elif sys.argv[1]=='upgrade':
            upgrade(Path(sys.argv[2]))
        elif sys.argv[1]=='workspace':
            workspace(Path(sys.argv[2]))
        elif sys.argv[1]=='status':
            status()
        elif sys.argv[1]=='down':
            down()
        else:
            raise RuntimeError('expected up, upgrade, workspace, status or down')
    except Exception as error:
        raise SystemExit(str(error))
