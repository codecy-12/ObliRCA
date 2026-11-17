#!/usr/bin/env bash
# ObliRCA benchmark scaffold: SP-45
set -euo pipefail
# Replace ATTACK_CMD with the scenario's trigger command.  The default is a
# no-op so that the scaffold can be inspected without executing an exploit.
export SCENARIO_ID="SP-45"
docker compose run --rm -e ATTACK_CMD="${ATTACK_CMD:-true}" target /bin/bash -lc "$ATTACK_CMD"
