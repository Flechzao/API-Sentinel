#!/usr/bin/env bash
# start-benchmark-env.sh — bring up the easyshop-app as a local container
# so BenchmarkIntegrationTest has something to point at.
#
# Usage:
#   ./scripts/start-benchmark-env.sh        # starts the container
#   ./scripts/stop-benchmark-env.sh         # removes it
#
# Requirements: docker. If docker isn't on PATH the script exits 0 with a
# clear message — it's a convenience, not a gate. The test itself also
# uses Assumptions to skip when the app is unreachable.
#
# The app listens on ${BENCHMARK_PORT:-8089}. CI typically pins the port;
# local runs can override with `BENCHMARK_PORT=18089 ./scripts/...`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE_NAME="${IMAGE_NAME:-api-sentinel-easyshop}"
CONTAINER_NAME="${CONTAINER_NAME:-easyshop-app}"
PORT="${BENCHMARK_PORT:-8089}"

if ! command -v docker >/dev/null 2>&1; then
    echo "[benchmark] docker not on PATH; skipping container bring-up."
    echo "[benchmark] Run easyshop-app manually with:"
    echo "    cd ${REPO_ROOT}/easyshop-app && mvn spring-boot:run"
    exit 0
fi

# Build the image. The context is the repo root so the Dockerfile can
# COPY easyshop-app/target/easyshop-1.0.0.jar from there. The jar must
# exist — if it doesn't, tell the user how to produce it rather than
# trying to run Maven ourselves (which would pull the internet).
JAR="${REPO_ROOT}/easyshop-app/target/easyshop-1.0.0.jar"
if [[ ! -f "${JAR}" ]]; then
    echo "[benchmark] missing ${JAR}; build it with:"
    echo "    mvn -f ${REPO_ROOT}/easyshop-app/pom.xml package"
    exit 1
fi

echo "[benchmark] building image ${IMAGE_NAME}"
docker build -t "${IMAGE_NAME}" \
    -f "${REPO_ROOT}/easyshop-app/Dockerfile" \
    "${REPO_ROOT}"

# Tear down any stale container with the same name (e.g. a prior run that
# didn't reach stop-benchmark-env.sh).
docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "[benchmark] starting container ${CONTAINER_NAME} on port ${PORT}"
docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "${PORT}:8089" \
    "${IMAGE_NAME}"

# Wait for the app to answer. Spring Boot on a cold JVM + Alpine takes
# ~3-8s; budget 30s before giving up.
echo "[benchmark] waiting for http://localhost:${PORT}/web/dashboard"
for i in $(seq 1 30); do
    if curl -fsS "http://localhost:${PORT}/web/dashboard" >/dev/null 2>&1; then
        echo "[benchmark] up after ${i}s"
        exit 0
    fi
    sleep 1
done

echo "[benchmark] app did not come up within 30s; check \`docker logs ${CONTAINER_NAME}\`"
exit 1
