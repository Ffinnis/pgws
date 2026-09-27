#!/usr/bin/env python3
"""Compile and exercise physical PostgreSQL code in an isolated Linux container."""
import json
from datetime import datetime, timezone
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import uuid

root = Path(__file__).resolve().parents[1]
image = "postgres@sha256:86c951e05bf56c93d95d397747fb8820ac76cc3bedb78f43abd83eedbe3666ae"
arch = "arm64" if platform.machine() in ("arm64", "aarch64") else "amd64"
go = ["rtk", "go"] if shutil.which("rtk") else ["go"]
docker = ["rtk", "docker"] if shutil.which("rtk") else ["docker"]
with tempfile.TemporaryDirectory(prefix="pgws-physical-build-") as folder:
    binary = Path(folder) / "physical.test"
    env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0")
    subprocess.run(go + ["test", "-c", "-o", str(binary), "./internal/physical"], cwd=root, env=env, check=True)
    subprocess.run(go + ["test", "-c", "-o", str(Path(folder) / "control.test"), "./internal/control"], cwd=root, env=env, check=True)
    subprocess.run(go + ["test", "-c", "-o", str(Path(folder) / "logical.test"), "./internal/logical"], cwd=root, env=env, check=True)
    subprocess.run(go + ["test", "-c", "-o", str(Path(folder) / "logical-cli.test"), "./cmd/pgws-logical"], cwd=root, env=env, check=True)
    subprocess.run(go + ["test", "-c", "-o", str(Path(folder) / "discover.test"), "./internal/privacy/discover"], cwd=root, env=env, check=True)
    subprocess.run(go + ["test", "-c", "-o", str(Path(folder) / "policyapproval.test"), "./internal/policyapproval"], cwd=root, env=env, check=True)
    shutil.copy(root / "lab" / "management.sh", Path(folder) / "management.sh")
    # The container runs as postgres; native Linux Docker enforces host ownership on bind mounts.
    os.chmod(folder, 0o755)
    for artifact in Path(folder).iterdir():
        os.chmod(artifact, 0o755)
    name = "pgws-physical-lab-" + uuid.uuid4().hex[:12]
    management_name = name + "-management"
    try:
        subprocess.run(docker + ["run", "--rm", "--name", management_name, "--network", "none",
            "--read-only", "--user", "postgres", "--memory", "512m", "--cpus", "2",
            "--tmpfs", "/tmp:rw,size=256m,mode=1777", "--mount", f"type=bind,src={folder},dst=/tests,readonly",
            "--entrypoint", "/bin/sh", image, "/tests/management.sh"], cwd=root, check=True)
        result = subprocess.run(docker + ["run", "--rm", "--name", name, "--network", "none",
            "--read-only", "--user", "postgres", "--memory", "1g", "--cpus", "2",
            "--tmpfs", "/tmp:rw,size=768m,mode=1777", "--mount", f"type=bind,src={folder},dst=/tests,readonly",
            "-e", "PGWS_PHYSICAL_LAB=1", "-e", "PGWS_PG_BIN=/usr/lib/postgresql/18/bin",
            "--entrypoint", "/tests/physical.test", image, "-test.v", "-test.timeout=4m"], cwd=root)
        if result.returncode:
            raise SystemExit(result.returncode)
        report = {"status": "passed", "observed_at": datetime.now(timezone.utc).isoformat(), "image": image, "architecture": arch,
                  "network": "none", "runtime_uid": "postgres", "management_integration": "passed",
                  "scope": "PostgreSQL 18: management transactions, source discovery, verified seed, disconnected promotion, independent writes, promotion with 70 open subtransactions, missing WAL rejection, changed plan rejection, unlogged and event-trigger source rejection, pre-hardening catalog drift rejection in postgres/template1, private preload/login-trigger suppression, hardening replay after SQL commit, promoted-primary restart proof; ordinary-file storage",
                  "policy_approval": "Linux boot-clock receipt durability, replay and renewal ordering; management signing/revocation and source binding",
                  "capacity_measurements": "immutable batches, lost-ACK replay, concurrent deduplication, scoped HTTP history and exact decimal amounts",
                  "bounded_discovery": "restricted reader, aggregate-only output, oversized/opaque exclusions, empty samples, schema fingerprint and deadline connection cleanup",
                  "logical_ingestion": {"status": "passed", "source": "PostgreSQL 18 pgoutput v1", "cases": ["policy-bound atomic target apply", "parallel immutable baseline generations at one source epoch, different transforms and sibling-safe slot retirement", "exported snapshot with concurrent source writes", "continuous INSERT/UPDATE/DELETE", "unchanged TOAST", "socket failure after target commit before ACK and exact replay", "uniqueness failure without ACK", "idle schema drift stop", "unsupported source catalog rejection", "private administrator discover/seed/run CLI", "positive identity/serial sequence high-water atomicity, seed/CDC, deletion, drift, exhaustion and branch insertion", "clone primary and unique key validation", "committed idle-source marker barriers, stopped consumer, replay, atomicity, bounded writer role, receipt quota/expiry and private CLI", "durable ownership before seed rows; real SIGKILL after creation and after committed apply before ACK; progress persistence failure and replay; independent source-only status with real retained WAL pressure and slot/publication replacement"], "public_sanitized_service_qualified": False},
                  "not_qualified": ["ZFS snapshots in this fixture", "workspace endpoint isolation", "sanitized baseline publication", "complete logical crash and source WAL watchdog campaign", "full T-23 on ZFS capture"]}
        report['logical_ingestion']['cases'].append('real SIGKILL before ownership receipt: inspection, reseed and stream refuse the unrecorded generation; source slot position/publication OID unchanged and target empty')
        (root / "evidence" / "physical-lab.json").write_text(json.dumps(report, indent=2) + "\n")
    finally:
        # Only the random container created by this invocation is eligible.
        subprocess.run(docker + ["rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(docker + ["rm", "-f", management_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
