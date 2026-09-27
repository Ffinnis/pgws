#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--test-pattern", default="TestLive")
parser.add_argument("--one-gib", action="store_true", help="Isolated 1 GiB source, clone benchmark and daemon fault tests")
args = parser.parse_args()
if args.one_gib:
    args.test_pattern = '^TestLiveDaemonsOneGiB$'
go = ["rtk", "go"] if shutil.which("rtk") else ["go"]
env = dict(os.environ, GOOS="linux", GOARCH="arm64", CGO_ENABLED="0")
(root / "bin").mkdir(exist_ok=True)
build = tempfile.TemporaryDirectory(prefix=".host-lab-", dir=root / "bin")
build_root = Path(build.name)
build_root.chmod(0o755)  # The fixture runs API/worker as separate unprivileged users.
binary = build_root / "host-linux.test"
guard = build_root / "pgws-guard-linux"
for name in ("pgws", "pgwsd", "pgws-host", "pgws-guard", "pgws-watchdog", "pgws-logical", "pgws-logical-watchdog"):
    subprocess.run(go + ["build", "-o", str(build_root / (name + "-linux")), "./cmd/" + name], cwd=root, env=env, check=True)
subprocess.run(go + ["test", "-c", "-o", str(binary), "./internal/host"], cwd=root, env=env, check=True)
result = subprocess.Popen(["limactl", "shell", "pgws-lab", "sudo", "env", "PGWS_ONE_GIB_LAB="+str(int(args.one_gib)), "PGWS_ZFS_TEST_PATTERN="+args.test_pattern, "PGWS_GUARD_BINARY="+str(guard), "PGWS_LAB_BIN="+str(build_root), "PGWS_LAB_ROOT="+str(root), "sh", str(root/"lab/zfs.sh"), str(binary)], cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
lines = []
for line in result.stdout:
    print(line, end="", flush=True)
    lines.append(line)
exit_code = result.wait()
output = "".join(lines)
if exit_code or "=== RUN   " not in output:
    (root/"evidence/host-lab-failure.json").write_text(json.dumps({"status":"failed","observed_at":datetime.now(timezone.utc).isoformat(),"test_pattern":args.test_pattern,"exit_code":exit_code,"output":output}, indent=2)+"\n")
    raise SystemExit(exit_code or 1)
report = "host-lab.json" if args.test_pattern == "TestLive" else "host-lab-selection-" + hashlib.sha256(args.test_pattern.encode()).hexdigest()[:12] + ".json"
if args.one_gib:
    report = 'one-gib-lab.json'
evidence = {"status":"passed","observed_at":datetime.now(timezone.utc).isoformat(),"test_pattern":args.test_pattern,"output":output}
if args.one_gib:
    for line in lines:
        if 'ONE_GIB benchmark=' in line:
            evidence['benchmark'] = json.loads(line.split('ONE_GIB benchmark=', 1)[1])
        if 'ONE_GIB initial_seed_seconds=' in line:
            evidence['initial_seed_seconds'] = float(line.split('ONE_GIB initial_seed_seconds=', 1)[1])
    if 'benchmark' not in evidence:
        raise SystemExit('1 GiB test returned without measured benchmark evidence')
(root/"evidence"/report).write_text(json.dumps(evidence, indent=2)+"\n")
