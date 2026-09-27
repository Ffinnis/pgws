#!/usr/bin/env python3
"""Exercise training/export plumbing on authored fixtures, not model quality."""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import numpy as np
import train


def main():
    go = ["rtk", "go"] if shutil.which("rtk") else ["go"]
    with tempfile.TemporaryDirectory(prefix="pgws-classifier-smoke-") as folder:
        root = Path(folder)
        bins = {}
        for command in ("pgws-features", "pgws-classify", "pgws-model-pack"):
            bins[command] = root / command
            subprocess.run(go + ["build", "-o", str(bins[command]), "./cmd/" + command], cwd=train.ROOT, check=True)
        example = json.loads((train.ROOT / "contracts/classifier/training-record.example.json").read_text())
        records = []
        for family in range(20):
            for number, label in enumerate(train.LABELS):
                record = deepcopy(example)
                record["record_id"] = f"fixture-{family}-{number}"
                record["application_family_id"] = f"authored-fixture-{family}"
                record["profile"]["column_name"] = label
                record["profile"]["neighbor_columns"] = ["id", "created_at"]
                record["label"] = label
                records.append(record)
        dataset = root / "fixtures.ndjson"
        dataset.write_bytes(b"".join(train.encode(r) for r in records))
        split = train.family_split(records, smoke=True)
        assert split == train.family_split(list(reversed(records)), smoke=True)
        assert sum(map(len, split.values())) == len(set(sum(split.values(), []))) == 20
        for variant in ("duplicate", "private", "unknown_field"):
            bad = deepcopy(records[:2])
            if variant == "duplicate":
                bad[1]["record_id"] = bad[0]["record_id"]
            elif variant == "private":
                bad[0]["provenance"]["redistribution_approved"] = False
            else:
                bad[0]["profile"]["raw_values"] = ["private-canary"]
            path = root / (variant + ".ndjson")
            path.write_bytes(b"".join(train.encode(r) for r in bad))
            try:
                train.read_records(path)
            except ValueError as error:
                assert "private-canary" not in str(error)
            else:
                raise AssertionError("unsafe training input accepted")
        output = root / "candidate"
        subprocess.run([sys.executable, str(Path(train.__file__)), str(dataset), str(output),
                        "--features", str(bins["pgws-features"]), "--synthetic-smoke"], check=True)
        # The ephemeral key exists only inside this fixture. No release key or
        # trained model is installed, retained, or shipped by this smoke run.
        keygen = root / "keygen.go"
        keygen.write_text('''package main
import("crypto/ed25519";"crypto/rand";"encoding/base64";"os";"path/filepath")
func main(){pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{panic(err)};for name,value:=range map[string][]byte{"private.key":key,"release.pub":pub}{if err=os.WriteFile(filepath.Join(os.Args[1],name),[]byte(base64.StdEncoding.EncodeToString(value)),0600);err!=nil{panic(err)}}}
''')
        subprocess.run(go + ["run", str(keygen), str(root)], cwd=train.ROOT, check=True)
        artifact = root / "fixture.model"
        pack = [str(bins["pgws-model-pack"]), str(output / "manifest.json"), str(output / "weights.f32"),
                str(output / "bias.f32"), str(root / "private.key"), str(artifact)]
        subprocess.run(pack, check=True)
        before = artifact.read_bytes()
        assert subprocess.run(pack, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0
        assert artifact.read_bytes() == before
        with (output / "parity-profiles.ndjson").open("rb") as profiles:
            result = subprocess.run([str(bins["pgws-classify"]), str(artifact), str(root / "release.pub")],
                                    stdin=profiles, capture_output=True, check=True)
        proposals = [json.loads(line) for line in result.stdout.splitlines()]
        actual = np.array([proposal["scores"] for proposal in proposals])
        expected = np.array(json.loads((output / "parity-scores.json").read_text()))
        assert actual.shape == expected.shape
        error = float(np.max(np.abs(actual - expected)))
        assert error <= 1e-5, f"Python/Go exported score mismatch: {error}"
        assert all(p["review_required"] and "unqualified_model" in p["review_flags"] for p in proposals)
        card = json.loads((output / "model-card.json").read_text())
        assert card["status"] == "synthetic_smoke_only" and not card["automatic_acceptance_enabled"]
        report = {"status": "passed", "observed_at": datetime.now(timezone.utc).isoformat(),
            "scope": "authored synthetic fixtures only; training/export/signature/native-score plumbing",
            "records": len(records), "declared_synthetic_families": 20, "classes": 24,
            "parity_profiles": len(proposals), "max_absolute_python_go_score_error": error,
            "versions": card["versions"], "trained_release_qualified": False,
            "real_corpus_accuracy_qualified": False, "automatic_acceptance_enabled": False,
            "artifacts_retained": False}
        (train.ROOT / "evidence/classifier-lab.json").write_bytes(train.encode(report))
        print(json.dumps(report))


if __name__ == "__main__":
    main()
