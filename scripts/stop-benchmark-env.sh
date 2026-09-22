#!/usr/bin/env bash
# stop-benchmark-env.sh — tear down the container started by
# start-benchmark-env.sh. Idempotent: no-ops when there's nothing to stop.

set -euo pipefail

CONTAINER_NAME="${CONTAINER_NAME:-easyshop-app}"

if ! command -v docker >/dev/null 2>&1; then
    exit 0
fi

if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}\$"; then
    echo "[benchmark] stopping ${CONTAINER_NAME}"
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
else
    echo "[benchmark] no ${CONTAINER_NAME} container to stop"
fi
