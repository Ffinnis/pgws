#!/usr/bin/env python3
"""Measure native Linux extraction/scoring on one pinned CPU in a fresh process."""
from datetime import datetime, timezone
import json
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
with tempfile.TemporaryDirectory(prefix="pgws-classifier-resources-") as folder:
    binary = Path(folder) / "classifier.test"
    subprocess.run(go + ["test", "-c", "-o", str(binary), "./internal/privacy/classify"],
                   cwd=root, env=dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0"), check=True)
    name = "pgws-classifier-resources-" + uuid.uuid4().hex[:12]
    try:
        # Original stdout is a machine-readable evidence stream. RTK's Docker
        # presentation is useful for ordinary calls but must not rewrite it.
        raw_docker = ["rtk", "proxy", "docker"] if shutil.which("rtk") else ["docker"]
        result = subprocess.run(raw_docker + ["run", "--rm", "--name", name, "--network", "none",
            "--read-only", "--user", "postgres", "--memory", "128m", "--cpuset-cpus", "0",
            "--tmpfs", "/tmp:rw,size=16m,mode=1777", "--mount", f"type=bind,src={folder},dst=/tests,readonly",
            "-e", "PGWS_CLASSIFIER_RESOURCE_LAB=1", "--entrypoint", "/tests/classifier.test", image,
            "-test.run=^TestClassifierResources$", "-test.v", "-test.timeout=2m"],
            cwd=root, capture_output=True, text=True, timeout=150)
        print(result.stdout)
        print(result.stderr)
        reports = [json.loads(line.split("=", 1)[1]) for line in result.stdout.splitlines()
                   if line.startswith("CLASSIFIER_RESOURCES=")]
        if len(reports) != 1:
            raise RuntimeError("isolated resource report missing")
        report = reports[0]
        if report["architecture"] != arch or report["cpus_allowed"] != "0":
            raise RuntimeError("native architecture or CPU affinity differs")
        report.update(observed_at=datetime.now(timezone.utc).isoformat(), image=image,
                      fixture="isolated Linux OCI process; no source I/O or trained quality evaluation")
        (root / "evidence" / f"classifier-resources-{arch}.json").write_text(json.dumps(report, indent=2) + "\n")
        if result.returncode or report["status"] != "passed":
            raise RuntimeError("classifier resource budget failed; see recorded evidence")
    finally:
        subprocess.run(docker + ["rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
