#!/usr/bin/env bash
# ObliRCA benchmark scaffold: CP-30
set -euo pipefail
# Replace BENIGN_CMD with a representative normal request.
export SCENARIO_ID="CP-30"
docker compose run --rm -e BENIGN_CMD="${BENIGN_CMD:-true}" target /bin/bash -lc "$BENIGN_CMD"
