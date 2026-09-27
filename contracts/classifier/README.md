# Tiny column-classifier contracts — RFC revision 0.3

This directory specifies a model to train. It contains **no trained weights**, production feature extractor, training pipeline or deployed classifier.

`spec.json` pins the architecture, ordered labels, feature dimensions, privacy boundaries and unmeasured release targets. `column-profile.schema.json` and `training-record.schema.json` constrain proposed internal data. The example is project-authored synthetic metadata with no sampled rows; its label illustrates serialization, not model accuracy.

Run `python3 validate.py` with jsonschema installed. Checks cover dimensions, labels, memory arithmetic, safety defaults and positive/negative schema examples. They do not test classifier quality, runtime parity, database sampling, lineage, source safety, signatures or anonymization.

The 32 numeric feature definitions and hash arithmetic are explicit. Parser versions, acronym-boundary edge cases, protected identifier handling and full golden fixtures must be implemented and pinned before training. The Go extractor is the single shared training/runtime implementation; do not substitute a different library's hashing function.

Revision 0.3 updates the lifecycle API and management SQL separately. Discovery persistence needs the additive migration described in RFC 10.15/12.1. Training and discovery administration are not agent permissions.

The 100-family minimum is a review-only pilot. Automatic acceptance requires the per-class acquisition plan in `spec.json`, at least 30 held-out families per enabled class, enough accepted cases, and separate calibration groups. The nominal 200-family lower bound is necessary at a 15% test split but is not sufficient by itself.
