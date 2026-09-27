#!/usr/bin/env python3
"""Run integration tests against a disposable, socket-only PostgreSQL cluster."""
import json
import base64
import hashlib
import uuid
import os
import re
import signal
import socket as sockets
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import urllib.request


def smoke(base, socket, env, bins):
    """Exercise the built daemon/CLI against a second empty private database."""
    def run(args, *, ok=True, local_env=env):
        result = subprocess.run(args, cwd=root, env=local_env, capture_output=True, text=True)
        if ok and result.returncode:
            if args[1].startswith("policy-"):
                raise RuntimeError(f"Policy smoke failed: {result.stderr[:1000]}")
            raise RuntimeError(f"Smoke command failed: {Path(args[0]).name} {args[1]}")
        return result

    daemon, cli = str(base / "pgwsd"), str(base / "pgws")
    go = ["rtk", "go"] if shutil.which("rtk") else [bins["go"]]
    run(go + ["build", "-o", daemon, "./cmd/pgwsd"])
    run(go + ["build", "-o", cli, "./cmd/pgws"])
    discovery = str(base / "pgws-discover")
    run(go + ["build", "-o", discovery, "./cmd/pgws-discover"])
    psql = [bins["psql"], "-h", str(socket), "-U", "pgws_test", "-d", "postgres", "-v", "ON_ERROR_STOP=1"]
    run(psql + ["-c", "CREATE DATABASE pgws_smoke"])
    env = dict(env, PGWS_DATABASE_URL=f"host={socket} user=pgws_test dbname=pgws_smoke sslmode=disable")
    run([daemon, "migrate"], local_env=env)
    bootstrap = json.loads(run([daemon, "bootstrap"], local_env=env).stdout)
    if run([daemon, "bootstrap"], ok=False, local_env=env).returncode == 0:
        raise RuntimeError("Bootstrap overwrote an existing authority")
    with sockets.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    env.update(PGWS_AUTHORITY_EPOCH=bootstrap["authority_epoch"], PGWS_PROJECT_ID=bootstrap["project_id"],
               PGWS_TOKEN=bootstrap["token"], PGWS_LISTEN=f"127.0.0.1:{port}", PGWS_URL=f"http://127.0.0.1:{port}")
    run([bins["psql"], "-h", str(socket), "-U", "pgws_test", "-d", "pgws_smoke", "-v", "ON_ERROR_STOP=1", "-c",
         "CREATE ROLE smoke_discovery LOGIN; CREATE TABLE public.discovery_sample(id bigint PRIMARY KEY,email varchar(64)); "
         "INSERT INTO public.discovery_sample SELECT n,'fixture@example.org' FROM generate_series(1,64)n; ANALYZE public.discovery_sample; "
         "GRANT USAGE ON SCHEMA public TO smoke_discovery; GRANT SELECT ON public.discovery_sample TO smoke_discovery"])
    discovery_config = base / "discovery.json"
    discovery_config.write_text(json.dumps({"source_dsn": f"host={socket} user=smoke_discovery dbname=pgws_smoke sslmode=disable",
        "relation": {"source_id": "12345678-1234-1234-1234-123456789abc", "source_epoch": 1, "schema": "public", "table": "discovery_sample"}}))
    discovery_config.chmod(0o600)
    discovery_result = run([discovery, str(discovery_config)], local_env=env).stdout
    profiled = json.loads(discovery_result)
    assert "fixture@example.org" not in discovery_result and profiled["sampled_rows"] == 64 and profiled["review_required"]
    processes = []
    try:
        with (base / "smoke.log").open("w") as log:
            processes.append(subprocess.Popen([daemon, "serve"], env=env, stdout=log, stderr=log))
            deadline = time.monotonic() + 10
            while True:
                try:
                    with urllib.request.urlopen(env["PGWS_URL"] + "/readyz", timeout=1) as response:
                        ready = json.load(response)
                        assert ready["workspace_backend"] == "unavailable"
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Daemon did not become ready")
                    time.sleep(0.1)
            assert json.loads(run([cli, "baselines"], local_env=env).stdout) == {"items": []}
            assert json.loads(run([cli, "usage", "--limit", "2"], local_env=env).stdout) == {"items": [], "measurement_kind": "observed_gauge"}
            scope = ["--tenant", bootstrap["tenant_id"], "--project", bootstrap["project_id"]]
            minted = json.loads(run([daemon, "token-create", *scope, "--raw", "--ttl", "1h"], local_env=env).stdout)
            token_env = dict(env, PGWS_TOKEN=minted["token"])
            assert json.loads(run([cli, "baselines"], local_env=token_env).stdout) == {"items": []}
            listing = run([daemon, "token-list", *scope], local_env=env).stdout
            assert minted["token"] not in listing and "token_hash" not in listing
            assert minted["grant"]["id"] in {item["id"] for item in json.loads(listing)["items"]}
            rotated = json.loads(run([daemon, "token-rotate", *scope, "--id", minted["grant"]["id"], "--ttl", "1h"], local_env=env).stdout)
            assert rotated["grant"]["principal_id"] == minted["grant"]["principal_id"]
            assert run([cli, "baselines"], ok=False, local_env=token_env).returncode != 0
            token_env["PGWS_TOKEN"] = rotated["token"]
            assert json.loads(run([cli, "baselines"], local_env=token_env).stdout) == {"items": []}
            assert json.loads(run([daemon, "token-revoke", *scope, "--id", rotated["grant"]["id"]], local_env=env).stdout)["revoked_tokens"] == 1
            assert json.loads(run([daemon, "token-revoke", *scope, "--id", rotated["grant"]["id"]], local_env=env).stdout)["revoked_tokens"] == 0
            assert run([cli, "baselines"], ok=False, local_env=token_env).returncode != 0
            replacement = json.loads(run([daemon, "token-create", *scope, "--principal", minted["grant"]["principal_id"], "--raw"], local_env=env).stdout)
            assert json.loads(run([daemon, "principal-revoke", *scope, "--principal", replacement["grant"]["principal_id"]], local_env=env).stdout)["revoked_tokens"] == 1
            sql = ("INSERT INTO pgws_control.approved_source_references VALUES "
                   f"('{bootstrap['tenant_id']}','{bootstrap['project_id']}','smoke-endpoint','smoke-secret-reference')")
            run([bins["psql"], "-h", str(socket), "-U", "pgws_test", "-d", "pgws_smoke", "-v", "ON_ERROR_STOP=1", "-c", sql])
            source_file = base / "source.json"
            source_file.write_text(json.dumps({"connector": "physical", "approved_endpoint_reference": "smoke-endpoint", "secret_reference": "smoke-secret-reference"}))
            args = [cli, "source", "--file", str(source_file), "--key", "smoke-source"]
            accepted = json.loads(run(args, local_env=env).stdout)
            assert json.loads(run(args, local_env=env).stdout) == accepted
            processes.append(subprocess.Popen([daemon, "worker"], env=env, stdout=log, stderr=log))
            waited = run([cli, "wait", "--id", accepted["operation"]["id"], "--timeout", "10s"], ok=False, local_env=env)
            assert waited.returncode != 0
            assert json.loads(waited.stdout)["error"]["code"] == "BACKEND_UNAVAILABLE"
            # Operator policy commands exercise metadata authority only. This
            # fixture never publishes or attaches a logical workspace runtime.
            admin = [bins["psql"], "-h", str(socket), "-U", "pgws_test", "-d", "pgws_smoke", "-v", "ON_ERROR_STOP=1"]
            identity = json.loads(run(admin + ["-Atc", "SELECT json_build_object('system_id',(pg_control_system()).system_identifier::text,'timeline',(pg_control_checkpoint()).timeline_id,'relation','public.discovery_sample'::regclass::oid::bigint)"], local_env=env).stdout)
            policy_source, policy_id = str(uuid.uuid4()), str(uuid.uuid4())
            run(admin + ["-c", "INSERT INTO pgws_control.sources(tenant_id,project_id,id,connector,endpoint_reference,secret_reference,status,system_identifier,timeline) VALUES "
                f"('{bootstrap['tenant_id']}','{bootstrap['project_id']}','{policy_source}','physical','smoke-endpoint','smoke-secret-reference','streaming','{identity['system_id']}',{identity['timeline']})"], local_env=env)
            schema = {"tables": [{"id": identity["relation"], "schema": "public", "name": "discovery_sample", "columns": [
                {"id": 1, "name": "id", "type": "int8", "nullable": False},
                {"id": 2, "name": "email", "type": "varchar", "nullable": True, "max_chars": 64}], "primary_key": [1]}]}
            schema_hash = hashlib.sha256(json.dumps(schema, separators=(",", ":")).encode()).hexdigest()
            transform_key = base / "policy-transform.key"
            transform_key.write_text(base64.b64encode(os.urandom(32)).decode())
            transform_key.chmod(0o600)
            review = base / "policy-review.json"
            review.write_text(json.dumps({"transform_key_file": str(transform_key), "draft": {
                "tenant_id": bootstrap["tenant_id"], "project_id": bootstrap["project_id"], "policy_id": policy_id, "revision": 1,
                "source_id": policy_source, "source_epoch": 1, "system_id": identity["system_id"], "timeline": identity["timeline"], "schema": schema,
                "policy": {"version": 1, "schema_hash": schema_hash, "key_id": "smoke-transform", "rules": [
                    {"table": identity["relation"], "column": 1, "action": "copy_original"},
                    {"table": identity["relation"], "column": 2, "action": "null"}]}}}))
            review.chmod(0o600)
            policy = json.loads(run([daemon, "policy-create", str(review)], local_env=env).stdout)
            assert policy["state"] == "draft" and policy["schema_hash"] == schema_hash
            assert json.loads(run([daemon, "policy-create", str(review)], local_env=env).stdout) == policy
            policy_scope = [*scope, "--id", policy_id]
            approved = json.loads(run([daemon, "policy-approve", *policy_scope, "--hash", policy["plan_hash"], "--schema-hash", schema_hash], local_env=env).stdout)
            assert approved["state"] == "approved" and approved["approval_epoch"] == bootstrap["authority_epoch"]
            # RFC 8032 test key, used only in this disposable fixture.
            signing_key = base / "policy-signing.key"
            signing_key.write_text(base64.b64encode(bytes.fromhex(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")).decode())
            signing_key.chmod(0o600)
            sign_env = dict(env, PGWS_SIGNING_KEY_FILE=str(signing_key))
            signed = json.loads(run([daemon, "policy-sign", *policy_scope, "--hash", policy["plan_hash"]], local_env=sign_env).stdout)
            assert signed["approval"]["plan_hash"] == policy["plan_hash"] and signed["approval"]["source_id"] == policy_source
            assert signed["approval"]["schema_hash"] == schema_hash and len(signed["approval_token"].split(".")) == 2
            revoked = json.loads(run([daemon, "policy-revoke", *policy_scope, "--hash", policy["plan_hash"]], local_env=env).stdout)
            assert revoked["state"] == "revoked"
            assert run([daemon, "policy-sign", *policy_scope, "--hash", policy["plan_hash"]], ok=False, local_env=sign_env).returncode != 0
            assert json.loads(run([daemon, "policy-show", *policy_scope], local_env=env).stdout) == revoked
            assert run([daemon, "policy-approve", *policy_scope, "--hash", policy["plan_hash"], "--schema-hash", schema_hash], ok=False, local_env=env).returncode != 0
            authority_key = base / "old-authority.key"
            authority_key.write_text(base64.b64encode(bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")).decode())
            authority_key.chmod(0o600)
            recovery_env = dict(env, PGWS_AUTHORITY_KEY_FILE=str(authority_key), PGWS_DATABASE_URL="deliberately-not-a-database")
            recovery_dir = base / "external-recovery"
            recovery = json.loads(run([daemon, "recovery-init", "--directory", str(recovery_dir), "--hosts", "smoke-host", "--operator", "smoke-operator"], local_env=recovery_env).stdout)
            assert recovery["authority_epoch"] != bootstrap["authority_epoch"]
            for name in ("plan.json", "signing.key", "authority.key"):
                assert (recovery_dir / name).stat().st_mode & 0o777 == 0o600
            assert run([daemon, "recovery-init", "--directory", str(recovery_dir), "--hosts", "smoke-host", "--operator", "smoke-operator"], ok=False, local_env=recovery_env).returncode != 0
            sealed = json.loads(run([daemon, "recovery-begin", recovery["plan_file"]], local_env=env).stdout)
            assert sealed["reconciled"] is False
            assert json.loads(run([daemon, "recovery-begin", recovery["plan_file"]], local_env=env).stdout) == sealed
            recovery_env = dict(env, PGWS_AUTHORITY_EPOCH=recovery["authority_epoch"])
            assert run([daemon, "token-create", *scope], ok=False, local_env=recovery_env).returncode != 0
            channels = base / "missing-recovery-hosts.json"
            channels.write_text("[]")
            channels.chmod(0o600)
            assert run([daemon, "recovery-finish", recovery["plan_file"], str(channels)], ok=False, local_env=env).returncode != 0
    finally:
        for process in processes:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
        for process in processes:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    print("CLI/daemon smoke passed: migrate, bootstrap, API token administration, serve, replay, worker, bounded discovery, operator policy CLI and external recovery seal")

root = Path(__file__).resolve().parents[1]
bins = {name: shutil.which(name) for name in ("initdb", "pg_ctl", "postgres", "psql", "go")}
if not all(bins.values()):
    raise SystemExit("initdb, pg_ctl, postgres, psql and go must be available on PATH")
versions = [subprocess.check_output([bins[name], "--version"], text=True).strip()
            for name in ("initdb", "pg_ctl", "postgres")]
if len({re.search(r"PostgreSQL\) (\d+(?:\.\d+)*)", v).group(1) for v in versions}) != 1:
    raise SystemExit("PostgreSQL binaries must belong to the same installation")

with tempfile.TemporaryDirectory(prefix="pgws-test-") as folder:
    base = Path(folder)
    data, socket = base / "data", base / "socket"
    socket.mkdir(mode=0o700)
    subprocess.run([bins["initdb"], "-D", str(data), "-U", "pgws_test",
                    "--auth-local=trust", "--auth-host=reject", "--encoding=UTF8",
                    "--no-locale"], check=True, capture_output=True)
    with (data / "postgresql.conf").open("a") as f:
        f.write(f"\nlisten_addresses = ''\nunix_socket_directories = '{socket}'\n")
    started = False
    try:
        subprocess.run([bins["pg_ctl"], "-D", str(data), "-l", str(base / "server.log"),
                        "-w", "start"], check=True, capture_output=True)
        started = True
        env = dict(os.environ)
        env["PGWS_TEST_DATABASE_URL"] = f"host={socket} user=pgws_test dbname=postgres sslmode=disable"
        command = ["rtk", "go", "test", "-race", "-count=1", "./..."] if shutil.which("rtk") else [bins["go"], "test", "-race", "-count=1", "./..."]
        result = subprocess.run(command, cwd=root, env=env)
        print(json.dumps({"postgresql": versions[-1], "tests_exit_code": result.returncode,
                          "scope": "real management DB and HTTP integration; no ZFS workspace runtime"}))
        if result.returncode:
            raise SystemExit(result.returncode)
        smoke(base, socket, env, bins)
    finally:
        if started:
            subprocess.run([bins["pg_ctl"], "-D", str(data), "-m", "immediate", "-w", "stop"], check=True, capture_output=True)
