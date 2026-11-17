#!/usr/bin/env bash
# ObliRCA benchmark scaffold: SP-27
set -euo pipefail
# Replace BENIGN_CMD with a representative normal request.
export SCENARIO_ID="SP-27"
docker compose run --rm -e BENIGN_CMD="${BENIGN_CMD:-true}" target /bin/bash -lc "$BENIGN_CMD"
