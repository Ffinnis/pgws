#!/usr/bin/env python3
"""Run the ZFS adapter against a disposable file pool in the pgws-lab Lima VM."""
import json
import os
from pathlib import Path
import shutil
import subprocess
from datetime import datetime, timezone

root = Path(__file__).resolve().parents[1]
binary = root / "bin" / "zfs-linux.test"
binary.parent.mkdir(exist_ok=True)
go = ["rtk", "go"] if shutil.which("rtk") else ["go"]
subprocess.run(go + ["test", "-c", "-o", str(binary), "./internal/storage/zfs"], cwd=root,
               env=dict(os.environ, GOOS="linux", GOARCH="arm64", CGO_ENABLED="0"), check=True)
result = subprocess.run(["limactl", "shell", "pgws-lab", "sudo", "sh", str(root / "lab/zfs.sh"), str(binary)],
                        cwd=root, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
print(result.stdout, end="")
if result.returncode:
    raise SystemExit(result.returncode)
report = {"status": "passed", "observed_at": datetime.now(timezone.utc).isoformat(),
          "storage": "real OpenZFS file-backed disposable pool", "output": result.stdout,
          "not_qualified": ["power-loss durability", "physical disk performance", "1 TB workload"]}
(root / "evidence/zfs-lab.json").write_text(json.dumps(report, indent=2) + "\n")
