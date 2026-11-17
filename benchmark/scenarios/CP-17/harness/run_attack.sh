#!/usr/bin/env bash
# ObliRCA benchmark scaffold: CP-17
set -euo pipefail
# Replace ATTACK_CMD with the scenario's trigger command.  The default is a
# no-op so that the scaffold can be inspected without executing an exploit.
export SCENARIO_ID="CP-17"
docker compose run --rm -e ATTACK_CMD="${ATTACK_CMD:-true}" target /bin/bash -lc "$ATTACK_CMD"
