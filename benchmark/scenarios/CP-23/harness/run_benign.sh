#!/usr/bin/env bash
# ObliRCA benchmark scaffold: CP-23
set -euo pipefail
# Replace BENIGN_CMD with a representative normal request.
export SCENARIO_ID="CP-23"
docker compose run --rm -e BENIGN_CMD="${BENIGN_CMD:-true}" target /bin/bash -lc "$BENIGN_CMD"
