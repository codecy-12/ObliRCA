# ObliRCA (OBLIGERCA)

Security-obligation-driven post-deployment source-level root-cause analysis.

This repository is a reference implementation of the paper's architecture: an
offline data flywheel, an online Localization / SOI / Rank pipeline, a ten-entry
obligation library, tool adapters, prompts, tests, and a 102-scenario benchmark
scaffold. It is not a byte-for-byte copy of the authors' full prototype.

## 0. Repository contents

1. **ObliRCA prototype and tool adapters.** The Python package is under
   `src/obli_rca/`; sysdig, Joern, and angr adapters are in
   `src/obli_rca/tools/adapters.py` (backed by `log_query.py`, `joern.py`, and
   `angr_check.py`).
2. **Frozen obligation library.** `obligations/frozen/` contains the frozen
   10-entry, 78-graph snapshot, `manifest.json` with SHA-256 hashes, and
   `library.json` with the full serialized library.
3. **102 evaluation scenarios.** `benchmark/scenarios/` contains one directory
   per scenario with deployment configuration, `scenario.json`, `symptom.json`,
   `annotation.json`, and `audit/manifest.json`. Captured logs are external and
   marked `not_captured` rather than fabricated.
4. **Six role prompts and baseline adapters.** `prompts/` contains the
   Extraction, Assessment, Consolidation, Localization, SOI, and Rank prompts
   (Rank has separate verification and explanation templates). Baseline
   adaptations are in `src/obli_rca/evaluation/baselines.py`.

## 1. Layout

```
config/                 runtime configuration
obligations/            ten obligation entries (YAML)
obligations/frozen/     frozen snapshot, hashes, serialized library
prompts/                six role prompts and output constraints
benchmark/
  manifest.json         102 scenario metadata
  scenarios/            one Docker scaffold per scenario
  annotations/          annotation schema
src/obli_rca/
  models/               obligation, log, code, evidence, hypothesis, scenario
  llm/                  OpenAI-compatible client, JSON repair, mock mode
  storage/              SQLite default; MySQL DDL
  tools/                syscall-CFG, cross-application search, Joern, angr, DWARF, taint
  offline/              extraction, assessment, consolidation, flywheel
  online/               localization, SOI, rank, scheduler, report
  evaluation/           metrics, ablations, cost, statistics
scripts/                init, validation, offline, online, evaluation
tests/                  unit and integration tests
```

## 2. Obligation library

The library contains ten entries. Each entry's graph count matches the paper's
category table; the total is 78 graphs.

| # | Category | Graphs |
| ---: | --- | ---: |
| 1 | Path Constraints | 7 |
| 2 | Authorization Checks | 4 |
| 3 | Resource Bounds | 8 |
| 4 | Protocol State Constraints | 12 |
| 5 | Memory Bounds | 9 |
| 6 | Input Sanitization | 10 |
| 7 | Secure Defaults | 6 |
| 8 | Concurrency Ordering | 7 |
| 9 | Resource Lifecycles | 8 |
| 10 | Object Lifecycles | 7 |
| | **Total** | **78** |

Each entry is `o = <G, C, Q>`: relation graphs, the obligation condition
(`Pre`, `Must`, `Stage`, `Scope`), and the query manual (`What`, `Where`,
`Interpret`, `Next`). Entries contain no historical program names, source
locations, CVE identifiers, or payloads.

## 3. Benchmark scenarios

The 102 online scenarios are under `benchmark/scenarios/`:

- `CP-01` to `CP-30`: Cross-program, 30 scenarios.
- `CH-01` to `CH-20`: Multiple-root-cause, 20 scenarios.
- `SP-01` to `SP-52`: Single-program, 52 scenarios.

`benchmark/manifest.json` lists all 102. Each scenario directory contains:

- `docker-compose.yml` and `Dockerfile`: deployment configuration;
- `scenario.json`: CVE, group, hops, annotation status, and expected log path;
- `symptom.json`: symptom-event slot; `status: not_captured` until a log exists;
- `annotation.json`: source-level ground truth where available, otherwise
  `pending`;
- `audit/manifest.json`: expected sysdig log path and capture status;
- `harness/` and `config/`: attack/benign harness stubs and configuration slot.

The upstream source trees and captured logs are external; the Docker files are
deployment scaffolds, not a claim that the vulnerability was run.

## 4. Setup

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e .
```

Copy `.env.example` to `.env` and set:

```bash
OPENROUTER_API_KEY=...
OBLIRCA_MODEL=deepseek/deepseek-chat-v3.1
OBLIRCA_BASE_URL=https://openrouter.ai/api/v1
```

No key is committed. Without a key, the model client runs in mock mode so that
schemas, storage, and tools remain testable.

## 5. Offline stage: data flywheel

### 5.1 Inputs

The offline corpus is a JSONL file. One line per case:

```json
{"case_id": "case-0001", "cve": "CVE-...", "project": "...",
 "category": "Memory Bounds", "vulnerable_version": "...",
 "fixed_version": "...", "patch_path": "...", "vulnerable_source": "...",
 "fixed_source": "...", "vulnerable_log": "...",
 "ground_truth": [{"locations": [{"file": "...", "function": "...", "line": 0}]}]}
```

### 5.2 Scripts

```bash
python scripts/init_db.py
python scripts/validate_obligations.py
python scripts/freeze_library.py
python scripts/run_offline.py --corpus data/corpus.jsonl --limit 20
```

- `init_db.py` creates the storage schema and imports `obligations/*.yaml`.
- `validate_obligations.py` checks graph structure, roles, conditions, query
  manual, and abstractness.
- `freeze_library.py` writes the immutable `obligations/frozen/` snapshot and
  its SHA-256 manifest.
- `run_offline.py` runs the flywheel. `--limit` is useful for a first pass;
  omit it for the full corpus.

### 5.3 What each case goes through

1. **Extraction Agent** parses the patch, compares vulnerable and fixed
   versions, reads the vulnerable log, and produces a candidate entry under
   three constraints: protection semantics only, no concrete answers, and no
   historical identifiers.
2. **Assessment Agent** receives only the candidate entry, the vulnerable
   source, and the vulnerable log. It runs a fresh Localization / SOI / Rank
   session with the ground truth hidden and returns a ranked list.
3. **Consolidation Agent** checks top-K membership, verifies abstraction and
   `Pre/Must/Stage/Scope`, and either enriches an existing entry or creates a
   new one. At most three automatic revisions are attempted; failures go to
   `data/human_review_queue.jsonl`.

### 5.4 Outputs

- accepted or enriched entries in the database and `obligations/`;
- flywheel statistics (cases, first-round, revised, manual, created, enriched);
- a human-review queue for entries that still fail acceptance;
- evidence records for each attempt.

### 5.5 Offline edge cases

- Missing patch: use source and log evidence; mark confidence lower.
- Missing vulnerable log: Assessment is skipped; the entry is not accepted on a
  skipped assessment.
- Missing source: Assessment is skipped; the case is recorded, not silently
  treated as a failure.
- Tests-only or refactor-only patch: return a no-obligation result.
- Duplicate semantic entry: enrich the existing entry; do not create a copy.
- More than one independent fix: split only when the case contains separate
  sub-events; otherwise choose the requirement that explains the symptom.
- Revision limit reached: enqueue for human review; do not loop forever.

## 6. Online stage: source-level RCA

### 6.1 Inputs

- a sysdig text log (or a JSON/JSONL event list);
- a symptom event id;
- one source root per application, at the incident version.

Example:

```bash
python scripts/run_online.py \
  --scenario tests/fixtures/scenario.json \
  --logs tests/fixtures/logs/nginx.sysdig \
  --source nginx=tests/fixtures/source \
  --symptom-event e5 --no-llm
```

For a benchmark scenario, replace the scenario path with the scenario id and
provide the captured log and source roots:

```bash
python scripts/run_online.py \
  --scenario CP-01 \
  --logs data/logs/CP-01.sysdig \
  --source nginx=data/sources/CP-01/nginx \
  --source haproxy=data/sources/CP-01/haproxy
```

### 6.2 What the script does

1. **Localization Agent** builds the shared code framework from the symptom
   application and its adjacent syscall sequence. It matches the sequence to a
   lightweight CFG, maps blocks to functions, and extracts source slices.
2. **SOIs** run in parallel, one per obligation entry. Each SOI screens
   applicability, binds graph roles to current source objects, follows the query
   manual, and checks `Pre/Must/Stage/Scope`. At a boundary it can request one
   hop from Localization.
3. **Rank Agent** merges duplicate hypotheses, instantiates the obligation
   condition, verifies the gap type (insufficient existing safeguard or missing
   necessary safeguard), optionally runs angr, sends targeted feedback to the
   originating SOI, and ranks the verified candidates.
4. The script prints a Markdown report with locations, obligations, defect
   mechanisms, explanations, and repair suggestions.

### 6.3 Outputs

- `inv_framework`: append-only function slices and event references;
- `inv_log_refs`: log records used by the investigation;
- `inv_hypotheses`: SOI hypotheses and evidence;
- `inv_feedback`: Rank-to-SOI feedback rounds;
- `inv_rankings`: final rank, score, explanation, and fix suggestion;
- a Markdown report on stdout.

### 6.4 Online edge cases

- Missing log or source root: the pipeline returns an error or skips the
  scenario; it does not invent a location.
- Symptom event not found: the pipeline stops with a clear error.
- No CFG path matches the syscall sequence: the framework records the unmatched
  events and the investigation continues with the available material.
- No peer at a boundary: Localization returns `unresolved`; the SOI records the
  boundary instead of fabricating a peer.
- Ambiguous peer: all candidates are returned with the ambiguity reason.
- Budget exhausted: the SOI records the limit and evaluates existing evidence.
- Multiple root causes: Rank verifies and reports each separately.
- No verified hypothesis: the report says so and lists unresolved questions; an
  unresolved candidate is not promoted to a confirmed root cause.

## 7. Evaluation

```bash
python scripts/run_evaluation.py \
  --manifest benchmark/manifest.json \
  --log-dir data/logs \
  --source-dir data/sources
```

Scenarios without logs or source roots are skipped and reported. Metrics:
F@1/3/5, L@1/3/5, MRR@10, Recall@5, Precision@5, and RootSet@5/10.
`--no-llm` uses the deterministic fallback.

### 7.1 Baseline adapters

`src/obli_rca/evaluation/baselines.py` provides adapters for LocAgent,
Agentless-FL, FuseFL, AutoFL, FlexFL, ARCUS, AURORA, BENZENE, and ObliRCA-P.
Each adapter accepts the evidence that method is allowed to use and returns
ranked functions and locations:

```python
from obli_rca.evaluation.baselines import BaselineInput, run_baseline

data = BaselineInput(
    scenario_id="CP-01",
    source_roots={"app": "data/sources/CP-01/app"},
    functions=[{"file": "a.c", "function": "handle", "line": 10}],
    problem_report="request reaches a protected operation",
)
result = run_baseline("LocAgent", data)
print(result.ranked_functions)
```

Adapters are deterministic and auditable; they do not claim to be full external
system reimplementations.

```bash
python scripts/run_baselines.py --list
python scripts/run_baselines.py --method LocAgent --input data/baseline_input.json
```

## 8. Storage

SQLite is the tested backend (`data/obli_rca.db`). The MySQL 8.x schema is at
`src/obli_rca/storage/mysql_schema.sql`; the table names and separation match
the paper. For a MySQL deployment, set `OBLIRCA_DB_URL` and replace the SQLite
upserts with `ON DUPLICATE KEY UPDATE`.

## 9. Tests and validation

```bash
python -m pytest -q
python scripts/validate_obligations.py
python scripts/check_scenarios.py
```

The 41 tests cover obligation loading, log parsing, syscall-CFG matching,
cross-application search, storage round trips, metrics, object mapping,
explanations, taint paths, statistics, baseline adapters, artifact counts,
edge cases, and an end-to-end online fixture.

## 10. Limitations

- The benchmark directories are scaffolds. Source trees, configuration, and
  sysdig logs must be supplied before a scenario can run.
- The online stage uses only audit logs, the symptom event, and incident-version
  source. Patches, fixed versions, PoCs, and reference root causes are excluded.
- The prototype does not claim a symbolic proof when angr is unavailable; the
  fallback is a source-evidence check and is reported as such.
- The obligation library is frozen before evaluation; the category distribution
  and graph counts follow the paper's appendix.
