#!/usr/bin/env bash
# ObliRCA benchmark scaffold: CP-18
set -euo pipefail
# Replace BENIGN_CMD with a representative normal request.
export SCENARIO_ID="CP-18"
docker compose run --rm -e BENIGN_CMD="${BENIGN_CMD:-true}" target /bin/bash -lc "$BENIGN_CMD"
