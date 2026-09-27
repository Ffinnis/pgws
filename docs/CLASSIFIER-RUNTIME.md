# Local feature extraction and model scoring

The shared Go encoder and native scoring runtime are implemented. No trained
model or licensed training corpus is included. Every proposal requires review.
The loader rejects a manifest that enables automatic acceptance. These tools
cannot authorize raw copying or publish a sanitized baseline.

`pgws-features` reads one ColumnProfile JSON object per line and emits a sparse
vector per line. Its input uses the unchanged RFC profile schema. The numeric
inputs are already aggregated profiles; this command does not query PostgreSQL,
parse sampled values or collect training data.

```sh
make build
./bin/pgws-features < profiles.ndjson > vectors.ndjson
./bin/pgws-classify approved.model release-key.pub < profiles.ndjson > proposals.ndjson
```

The release key is an operator-pinned base64 Ed25519 public key in a private file.
It is never read from the model itself. A missing/invalid model returns an error;
there is no remote model call or fallback classifier. Already approved row
transformation plans do not depend on these commands.

## Encoder contract

The encoder emits 16,384 signed FNV-1a metadata buckets followed by the 32 RFC
numeric features. It aggregates repeated feature occurrences before L2
normalization. Tokens are namespaced by column, table, neighbor, type, key role
and table/column interaction. Character n-grams have lengths two through five
and never cross token boundaries. Acronym/camel boundaries and numeric feature
order have fixed golden checks.

The implementation descriptor is `internal/privacy/features/contract.json`.
The feature digest hashes that file, the encoder source, numeric order source
and encoder golden test source, then the profiler source and profiler golden
test source, separated by NUL bytes in that order. Changing any of
them makes older model bundles incompatible. All builds use the same byte
contract, including training's Go exporter and the local scoring process.

Each input document is limited to 64 KiB, 32 neighbors and the schema's metadata
length limits. Unknown fields, duplicate JSON keys, null numeric entries,
non-finite/out-of-range numbers and contradictory missing-sample evidence fail.
Errors do not echo the supplied metadata. Non-ASCII identifiers, unsupported
types, JSON containers, incomplete samples and feature overflow require review.
At most 2,048 distinct metadata features are retained. Raw row values, comments
and defaults are not accepted fields or token sources.

`ProfileSamples` now computes the numeric block from at most 64 already returned
UTF-8 values of at most 256 bytes each. NULL, empty and truncated values have
separate denominators. It calculates nearest-rank p95, complete-value distinct
fraction, pinned format recognizers and explicit secret/entropy heuristics.
Truncated values contribute only returned lengths, and force incomplete-sample
review. No raw values appear in its result or errors.

The separate [PostgreSQL reader](BOUNDED-DISCOVERY.md) now supplies bounded
values from eligible built-in types through a private read-only connection.
Unbounded text/JSON remains metadata-only. Complete protected-identifier and
mixed-content detection, source load and representativeness need qualification. Format hits and entropy are
features, not guarantees about sensitive content.

## Signed data-only bundle

The v1 file contains these exact bytes, with no archives or executable objects:

1. Eight ASCII bytes `PGWSCLF1`.
2. Four-byte little-endian manifest length, at most 64 KiB.
3. UTF-8 JSON manifest.
4. 1,575,936 bytes of row-major little-endian FP32 weights, shape `[24,16416]`.
5. 96 bytes of little-endian FP32 biases.
6. A 64-byte Ed25519 signature over all preceding bytes.

The full input is capped at 4 MiB. The manifest format is
`pgws.column-model.v1`, with runtime `pgws-go-classifier-v1`. It binds the exact
feature digest and ordered RFC labels, SHA-256 dataset/split/trainer/model-card
references, weight/bias checksums and a finite positive temperature.
`auto_accept` must be explicitly false. Unknown, duplicate, missing or null
manifest fields fail validation. Trailing bytes, wrong signatures, reordered
labels and non-finite parameters fail before activation.

The loader copies parameters into an immutable model. Scoring uses ordinary Go
sparse dot products and stable temperature-scaled softmax. Eight inferences may
run concurrently across model versions. Outputs contain all class scores, the
top score/margin, model and feature digests, and `review_required=true`.

Tests check signed loading, corruption rejection, an independently calculated
arithmetic score, concurrent determinism, malformed sparse inputs and the CLI.
A five-second encoder fuzz run also passed. The offline training pipeline now
runs end to end on authored synthetic fixtures: 480 records, 24 classes and 72
held-out Python/Go parity profiles. It deletes all fixture weights and keys.
See [training workflow](../ml/column-classifier/README.md) and
`evidence/classifier-lab.json` for measured parity and pinned versions.

This validates training/export plumbing. Real licensed data, family-independent
accuracy/calibration qualification, resource measurements and persisted
approved discovery findings remain unfinished. Every proposal still requires
review; no trained release is included.

## Resource measurements

`make classifier-resources` builds a native Linux test binary and runs it in a
fresh container pinned to one CPU with GOMAXPROCS=1. A child process loads a
full-size arithmetic fixture after recording baseline RSS, measures extraction
plus scoring on three bounded profiles, and exercises eight concurrent workers.
The kernel's process high-water RSS includes loading and inference allocations.
On the recorded ARM64 VM, p95 was at most 2.179 ms and peak resident increase was
10,506,240 bytes. See `evidence/classifier-resources-arm64.json` for individual
fixtures and environment. This is a fixture measurement on one VM, not an
x86-64 result, trained-corpus benchmark or complete T-21 qualification.
