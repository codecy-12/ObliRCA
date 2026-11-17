"""Generate the 102-scenario benchmark manifest and Docker scaffolds.

The paper's benchmark metadata lives in the sibling JSON files:
``benchmark_scenarios_2025plus.json`` and ``single_program_cves_2025plus.json``.
This script keeps the manifest reproducible and creates one auditable Docker
directory per scenario.  Upstream source trees and captured logs are external;
the scaffolds deliberately do not claim to be complete reproductions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PARENT = ROOT.parent
BENCH_JSON = PARENT / "benchmark_scenarios_2025plus.json"
SINGLE_JSON = PARENT / "single_program_cves_2025plus.json"
OUT = ROOT / "benchmark"
SCEN = OUT / "scenarios"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def app_label(text: str) -> str:
    text = re.sub(r"\s+", " ", text or "").strip()
    return text[:160]


def ascii_label(text: str) -> list[str]:
    label = app_label(text)
    return [label] if label and label.isascii() else []


def base_image(language: str) -> str:
    lang = (language or "").lower()
    if "java" in lang:
        return "eclipse-temurin:17-jdk"
    if "python" in lang:
        return "python:3.11-slim"
    if "go" in lang:
        return "golang:1.22"
    if "ruby" in lang:
        return "ruby:3.3"
    if "php" in lang:
        return "php:8.2-cli"
    if "node" in lang or "javascript" in lang:
        return "node:20"
    return "ubuntu:22.04"


def compose(group: str, scenario_id: str) -> str:
    if group == "single_program":
        services = """
  target:
    build: .
    container_name: obli-${SCENARIO_ID:-scenario}-target
    working_dir: /src
    command: ["/bin/bash", "-lc", "sleep infinity"]
"""
    else:
        services = """
  target:
    build: .
    container_name: obli-${SCENARIO_ID:-scenario}-target
    working_dir: /src
    command: ["/bin/bash", "-lc", "sleep infinity"]
  peer:
    image: alpine:3.20
    container_name: obli-${SCENARIO_ID:-scenario}-peer
    command: ["/bin/sh", "-lc", "sleep infinity"]
"""
    return f"""# ObliRCA benchmark scaffold: {scenario_id}
# The incident-version source tree is not vendored.  Mount or copy it into
# ./sources and adapt the Dockerfile before running.
services:{services}
  capture:
    image: sysdig/sysdig:latest
    container_name: obli-${{SCENARIO_ID:-scenario}}-capture
    privileged: true
    pid: host
    volumes:
      - /var/run/docker.sock:/host/var/run/docker.sock
      - ./captures:/captures
    command: ["sleep", "infinity"]
    profiles: ["capture"]
"""


def dockerfile(language: str, scenario_id: str) -> str:
    image = base_image(language)
    return f"""# ObliRCA benchmark scaffold: {scenario_id}
# Base image chosen from the scenario language.  Replace the placeholder
# commands with the project's own build instructions.
FROM {image}

ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /src

# The incident-version source tree is intentionally not vendored.
# Copy it into ./sources before building, or mount it at /src.
COPY . /src

# Example build hooks (edit per project):
# RUN ./configure && make -j"$(nproc)"
# RUN mvn -q -DskipTests package
# RUN pip install -r requirements.txt

CMD ["/bin/bash", "-lc", "sleep infinity"]
"""


def harness_attack(scenario_id: str) -> str:
    return f"""#!/usr/bin/env bash
# ObliRCA benchmark scaffold: {scenario_id}
set -euo pipefail
# Replace ATTACK_CMD with the scenario's trigger command.  The default is a
# no-op so that the scaffold can be inspected without executing an exploit.
export SCENARIO_ID="{scenario_id}"
docker compose run --rm -e ATTACK_CMD="${{ATTACK_CMD:-true}}" target /bin/bash -lc "$ATTACK_CMD"
"""


def harness_benign(scenario_id: str) -> str:
    return f"""#!/usr/bin/env bash
# ObliRCA benchmark scaffold: {scenario_id}
set -euo pipefail
# Replace BENIGN_CMD with a representative normal request.
export SCENARIO_ID="{scenario_id}"
docker compose run --rm -e BENIGN_CMD="${{BENIGN_CMD:-true}}" target /bin/bash -lc "$BENIGN_CMD"
"""


def scenario_readme(item: dict[str, Any]) -> str:
    cves = ", ".join(item["cves"]) or "—"
    return f"""# {item['id']}

- **Group:** {item['group']}
- **CVE(s):** {cves}
- **Application:** {item['metadata'].get('application_description', '—')}
- **Entrypoint:** {item['metadata'].get('entrypoint', '—')}
- **Status:** benchmark scaffold; source and logs are external.

## Layout

```
scenario.json      machine-readable metadata
docker-compose.yml target/peer/capture services
Dockerfile         language-specific build scaffold
harness/           attack and benign harness stubs
config/            scenario configuration placeholder
```

The incident-version source tree is **not vendored**.  Place it under
`./sources` (or mount it at `/src`) and replace the placeholder build commands
before running the scenario.

## Reproduction boundary

This directory records the deployment topology and metadata needed for audit.
It is not a claim that the vulnerability was reproduced.  The paper's benchmark
status is recorded in `scenario.json` (`annotation_status`, `n_l`,
`runtime_reproduced`).

## Commands (after adapting the scaffold)

```bash
export SCENARIO_ID={item['id']}
docker compose up -d --build
./harness/run_attack.sh
./harness/run_benign.sh
docker compose down -v
```
"""


def write_scenario(item: dict[str, Any]) -> None:
    directory = SCEN / item["id"]
    (directory / "harness").mkdir(parents=True, exist_ok=True)
    (directory / "config").mkdir(parents=True, exist_ok=True)
    (directory / "sources").mkdir(parents=True, exist_ok=True)
    (directory / "sources" / ".gitkeep").write_text("", encoding="utf-8")
    (directory / "captures").mkdir(parents=True, exist_ok=True)
    (directory / "captures" / ".gitkeep").write_text("", encoding="utf-8")
    (directory / "audit").mkdir(parents=True, exist_ok=True)
    (directory / "scenario.json").write_text(
        json.dumps(item, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (directory / "docker-compose.yml").write_text(compose(item["group"], item["id"]), encoding="utf-8")
    (directory / "Dockerfile").write_text(
        dockerfile(item["metadata"].get("language", ""), item["id"]), encoding="utf-8"
    )
    (directory / "harness" / "run_attack.sh").write_text(harness_attack(item["id"]), encoding="utf-8")
    (directory / "harness" / "run_benign.sh").write_text(harness_benign(item["id"]), encoding="utf-8")
    (directory / "config" / ".gitkeep").write_text("", encoding="utf-8")
    (directory / "audit" / "manifest.json").write_text(
        json.dumps(
            {
                "scenario_id": item["id"],
                "status": "not_captured",
                "format": "sysdig",
                "expected_path": item["log_path"],
                "note": "Capture the incident-version syscall log and place it at the expected path.",
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    (directory / "symptom.json").write_text(
        json.dumps(
            {
                "scenario_id": item["id"],
                "status": "not_captured",
                "event_id": None,
                "application": None,
                "description": "",
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    roots = item.get("root_causes", [])
    locations = []
    for root in roots:
        for location in root.get("locations", []):
            if location not in locations:
                locations.append(location)
    (directory / "annotation.json").write_text(
        json.dumps(
            {
                "scenario_id": item["id"],
                "status": item.get("annotation_status", "pending"),
                "n_l": bool(item.get("n_l", False)),
                "locations": locations,
                "roots": roots,
                "notes": "Source-review annotation; captured logs are external.",
            },
            ensure_ascii=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    bench = load_json(BENCH_JSON)
    single = load_json(SINGLE_JSON)
    scenarios: list[dict[str, Any]] = []

    for entry in bench["cross_process"]:
        group = "cross_program"
        fine = entry.get("fine_grained_annotation", {})
        scenarios.append(
            {
                "id": entry["ID"],
                "group": group,
                "cves": entry.get("CVEs", []),
                "applications": [],
                "versions": {},
                "directory": f"benchmark/scenarios/{entry['ID']}",
                "log_path": f"data/logs/{entry['ID']}.sysdig",
                "source_root": f"data/sources/{entry['ID']}/vuln",
                "symptom": None,
                "hops": 1,
                "root_causes": [],
                "n_l": bool(fine.get("fine_eligible", False)),
                "annotation_status": fine.get("annotation_status", "pending"),
                "metadata": {},
            }
        )

    for entry in bench["chain_cve"]:
        fine = entry.get("fine_grained_annotation", {})
        scenarios.append(
            {
                "id": entry["ID"],
                "group": "multiple_root",
                "cves": entry.get("CVEs", []),
                "applications": [],
                "versions": {},
                "directory": f"benchmark/scenarios/{entry['ID']}",
                "log_path": f"data/logs/{entry['ID']}.sysdig",
                "source_root": f"data/sources/{entry['ID']}/vuln",
                "symptom": None,
                "hops": 1,
                "root_causes": [],
                "n_l": bool(fine.get("fine_eligible", False)),
                "annotation_status": fine.get("annotation_status", "pending"),
                "metadata": {},
            }
        )

    for index, row in enumerate(single["rows"], start=1):
        spans = row.get("line_spans", [])
        locations = [
            {
                "file": row.get("source_file", ""),
                "function": row.get("function", ""),
                "line": span.get("start", 0),
            }
            for span in spans
        ]
        scenario_id = f"SP-{index:02d}"
        scenarios.append(
            {
                "id": scenario_id,
                "group": "single_program",
                "cves": [row.get("cve", "")],
                "applications": ascii_label(row.get("application", "")),
                "versions": {
                    "vulnerable": row.get("vulnerable_version", ""),
                    "fixed": row.get("fixed_version", ""),
                },
                "directory": f"benchmark/scenarios/{scenario_id}",
                "log_path": f"data/logs/{scenario_id}.sysdig",
                "source_root": f"data/sources/{scenario_id}/vuln",
                "symptom": None,
                "hops": 0,
                "root_causes": [
                    {
                        "locations": locations,
                        "obligations": [],
                        "mechanisms": [],
                        "notes": "",
                    }
                ],
                "n_l": bool(row.get("fine_eligible", False)),
                "annotation_status": row.get("fine_status", "pending"),
                "metadata": {"language": row.get("language", "")},
            }
        )

    OUT.mkdir(parents=True, exist_ok=True)
    SCEN.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": "1.0",
        "metadata": {
            "source": "paper benchmark manifest",
            "note": "Docker scaffolds are auditable deployment definitions; source trees and logs are external.",
            "paper_counts": {
                "scenarios": 102,
                "cves": 105,
                "applications": 38,
                "n_l": 59,
            },
        },
        "scenarios": scenarios,
    }
    (OUT / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    for item in scenarios:
        write_scenario(item)
    print(f"wrote {len(scenarios)} scenarios and manifest")


if __name__ == "__main__":
    main()
