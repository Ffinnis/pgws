#!/usr/bin/env python3
"""Offline, from-scratch review-only candidate training. Never loads pickle."""
import argparse
from array import array
import hashlib
import json
import math
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import warnings

import jsonschema
import numpy as np
import scipy
from scipy.optimize import minimize_scalar
from scipy.sparse import csr_matrix
from scipy.special import logsumexp
import sklearn
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, log_loss
from threadpoolctl import threadpool_limits

ROOT = Path(__file__).resolve().parents[2]
SPEC = json.loads((ROOT / "contracts/classifier/spec.json").read_text())
LABELS = SPEC["labels"]
SCHEMA = json.loads((ROOT / "contracts/classifier/training-record.schema.json").read_text())
PARTITIONS = ("train", "development", "temperature", "threshold", "test")


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_records(path, private=False, smoke=False):
    if path.stat().st_size > 512 << 20:
        raise ValueError("dataset exceeds byte budget")
    validator = jsonschema.Draft202012Validator(SCHEMA)
    records, ids = [], set()
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for number, line in enumerate(source, 1):
            if number > 30000 or len(line) > 128 << 10:
                raise ValueError("dataset exceeds record budget")
            digest.update(line)
            try:
                record = json.loads(line, object_pairs_hook=strict_object,
                                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
                validator.validate(record)
            except (ValueError, jsonschema.ValidationError):
                raise ValueError(f"invalid training record at line {number}") from None
            if record["record_id"] in ids:
                raise ValueError("duplicate training record identity")
            ids.add(record["record_id"])
            rights = record["provenance"]
            if not private and (not rights["redistribution_approved"] or rights["origin"] == "consented_private_profile"):
                raise ValueError("private corpus requires explicit --private")
            if smoke and rights["origin"] != "project_authored_synthetic":
                raise ValueError("synthetic smoke mode cannot consume real schema records")
            records.append(record)
    if not records:
        raise ValueError("empty training corpus")
    return records, digest.hexdigest()


def family_split(records, smoke=False):
    families = sorted({r["application_family_id"] for r in records},
                      key=lambda f: sha(("pgws-family-split-v1:" + f).encode()))
    if len(families) < (20 if smoke else 100):
        raise ValueError("insufficient independent families for this review-only run")
    count = len(families)
    boundaries = [int(count * x) for x in (0, .65, .75, .80, .85)] + [count]
    split = {name: families[boundaries[i]:boundaries[i + 1]] for i, name in enumerate(PARTITIONS)}
    if any(not values for values in split.values()):
        raise ValueError("empty family partition")
    return split


def export_features(records, binary):
    # Private temporary files avoid holding a second complete JSON/vector copy
    # in memory. Only schema metadata/aggregate profiles are written here.
    values, indices, pointers = array("f"), array("i"), array("i", [0])
    feature_digest = None
    with tempfile.TemporaryFile() as source, tempfile.TemporaryFile() as destination:
        for record in records:
            source.write(encode(record["profile"]))
        source.seek(0)
        result = subprocess.run([str(binary)], stdin=source, stdout=destination,
                                stderr=subprocess.DEVNULL, timeout=120)
        if result.returncode:
            raise ValueError("shared Go feature export rejected the corpus")
        destination.seek(0)
        for count, line in enumerate(destination, 1):
            vector = json.loads(line)
            current = vector["feature_contract_digest"]
            if feature_digest is not None and current != feature_digest:
                raise ValueError("feature contract changed during export")
            feature_digest = current
            for item in vector["entries"]:
                indices.append(item["index"])
                values.append(item["value"])
            if len(values) > 16_000_000:
                raise ValueError("offline feature matrix exceeds sparse budget")
            pointers.append(len(values))
        if len(pointers) != len(records) + 1:
            raise ValueError("feature exporter omitted or added records")
    matrix = csr_matrix((np.frombuffer(values, dtype=np.float32),
                         np.frombuffer(indices, dtype=np.int32),
                         np.frombuffer(pointers, dtype=np.int32)),
                        shape=(len(records), 16416))
    return matrix, feature_digest


def probabilities(logits, temperature):
    scaled = logits / temperature
    return np.exp(scaled - logsumexp(scaled, axis=1, keepdims=True))


def evaluate(labels, probabilities, records):
    predicted = probabilities.argmax(axis=1)
    confidence = probabilities.max(axis=1)
    ece = 0.0
    bins = np.minimum((confidence * 10).astype(int), 9)
    for bucket in range(10):
        selected = bins == bucket
        if selected.any():
            ece += float(selected.mean()) * abs(float((predicted[selected] == labels[selected]).mean()) - float(confidence[selected].mean()))
    return {"classification": classification_report(labels, predicted, labels=np.arange(24),
                target_names=LABELS, output_dict=True, zero_division=0),
            "confusion_matrix": confusion_matrix(labels, predicted, labels=np.arange(24)).tolist(),
            "negative_log_likelihood": float(log_loss(labels, probabilities, labels=np.arange(24))),
            "expected_calibration_error_10_bins": ece,
            "families_per_class": {name: len({r["application_family_id"] for r in records if r["label"] == name}) for name in LABELS},
            "automatic_acceptance_enabled": False, "qualified_precision_claim": False}


def train(args):
    if args.output.exists():
        raise ValueError("candidate output already exists")
    records, dataset_digest = read_records(args.dataset, args.private, args.synthetic_smoke)
    split = family_split(records, args.synthetic_smoke)
    sets = {name: set(families) for name, families in split.items()}
    rows = {name: np.array([i for i, r in enumerate(records) if r["application_family_id"] in families]) for name, families in sets.items()}
    labels = np.array([LABELS.index(r["label"]) for r in records])
    if set(labels[rows["train"]]) != set(range(24)):
        raise ValueError("training partition must contain all 24 classes")
    matrix, feature_digest = export_features(records, args.features.resolve())
    train_rows, dev_rows = rows["train"], rows["development"]
    frequencies = np.bincount(labels[train_rows], minlength=24)
    capped = {i: min(5.0, len(train_rows) / (24 * int(n))) for i, n in enumerate(frequencies)}
    candidates, best = [], None
    with threadpool_limits(limits=1):
        for c in (.1, 1.0, 10.0):
            for weighting, weights in (("none", None), ("capped_training_only", capped)):
                candidate = LogisticRegression(solver="saga", C=c, l1_ratio=0.0,
                            class_weight=weights, random_state=713, max_iter=2000, tol=1e-4)
                try:
                    with warnings.catch_warnings():
                        warnings.simplefilter("error", ConvergenceWarning)
                        candidate.fit(matrix[train_rows], labels[train_rows])
                except ConvergenceWarning:
                    candidates.append({"C": c, "weighting": weighting, "converged": False})
                    continue
                loss = float(log_loss(labels[dev_rows], candidate.predict_proba(matrix[dev_rows]), labels=np.arange(24)))
                item = {"C": c, "weighting": weighting, "converged": True, "development_loss": loss}
                candidates.append(item)
                if best is None or loss < best[0]:
                    best = loss, candidate, item
        if best is None:
            raise ValueError("no training candidate converged")
        model = best[1]
        if not np.array_equal(model.classes_, np.arange(24)):
            raise ValueError("class export order differs")
        weights, bias = np.asarray(model.coef_, dtype="<f4"), np.asarray(model.intercept_, dtype="<f4")
        if weights.shape != (24, 16416) or bias.shape != (24,) or not np.isfinite(weights).all() or not np.isfinite(bias).all():
            raise ValueError("non-finite or incorrectly shaped model candidate")
        # Fit/check calibration on the exact exported FP32 representation.
        logits = matrix.astype(np.float64) @ weights.astype(np.float64).T + bias.astype(np.float64)
        calibration = rows["temperature"]
        temperature_fit = minimize_scalar(lambda log_t: float(log_loss(labels[calibration],
            probabilities(logits[calibration], math.exp(log_t)), labels=np.arange(24))),
            bounds=(-5, 5), method="bounded", options={"xatol": 1e-7})
        if not temperature_fit.success:
            raise ValueError("temperature calibration did not converge")
        temperature = math.exp(float(temperature_fit.x))
        # Test is inspected only after C/weighting and temperature are fixed.
        reports = {name: evaluate(labels[rows[name]], probabilities(logits[rows[name]], temperature),
                    [records[i] for i in rows[name]]) for name in ("threshold", "test")}
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    split_data = encode({"format": "pgws-family-split-v1", "families": split})
    (args.output / "split.json").write_bytes(split_data)
    weight_data, bias_data = weights.tobytes(order="C"), bias.tobytes(order="C")
    (args.output / "weights.f32").write_bytes(weight_data)
    (args.output / "bias.f32").write_bytes(bias_data)
    report = {"status": "synthetic_smoke_only" if args.synthetic_smoke else "unqualified_review_candidate",
        "dataset_sha256": dataset_digest, "records": len(records), "families": len({r["application_family_id"] for r in records}),
        "redistribution_approved": not args.private and all(r["provenance"]["redistribution_approved"] for r in records),
        "feature_contract_digest": feature_digest, "candidates": candidates, "selected": best[2],
        "temperature": temperature, "evaluation": reports, "automatic_acceptance_enabled": False,
        "limitations": ["Declared application families require independent provenance review", "No family-cluster confidence qualification", "No automatic acceptance thresholds enabled",
                        "Source sampling and feature-plus-score resources require separate qualification"],
        "versions": {"python": platform.python_version(), "numpy": np.__version__, "scipy": scipy.__version__, "scikit_learn": sklearn.__version__}}
    card = encode(report)
    (args.output / "model-card.json").write_bytes(card)
    manifest = {"format": "pgws.column-model.v1", "runtime": "pgws-go-classifier-v1", "feature_contract_digest": feature_digest,
        "labels": LABELS, "dataset_digest": dataset_digest, "split_digest": sha(split_data),
        "trainer_revision": sha(Path(__file__).read_bytes() + Path(__file__).with_name("requirements.txt").read_bytes()),
        "model_card_digest": sha(card), "weights_sha256": sha(weight_data), "bias_sha256": sha(bias_data),
        "temperature": temperature, "auto_accept": False}
    (args.output / "manifest.json").write_bytes(encode(manifest))
    # A small reference set is for release export parity, not another model fit.
    reference_rows = rows["test"][:128]
    with (args.output / "parity-profiles.ndjson").open("wb") as output:
        for i in reference_rows:
            output.write(encode(records[i]["profile"]))
    (args.output / "parity-scores.json").write_bytes(encode(probabilities(logits[reference_rows], temperature).tolist()))
    return {"status": report["status"], "records": len(records), "families": report["families"], "automatic_acceptance_enabled": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--features", type=Path, default=ROOT / "bin/pgws-features")
    parser.add_argument("--private", action="store_true")
    parser.add_argument("--synthetic-smoke", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(train(args)))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Source/library errors can embed data. Emit only the exception class.
        print("classifier training failed: " + type(error).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
