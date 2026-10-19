#!/usr/bin/env bash
#
# Builds the IACS_Monitor Docker image.
#
# Usage:
#   ./build.sh                  # builds iasc-monitor:latest
#   ./build.sh v1.2.0           # also tags iasc-monitor:v1.2.0
#   PYTHON_VERSION=3.12 ./build.sh   # override the Python version build-arg
#
# After building, run it with:
#   docker compose up            (recommended - wires up the data volume)
#   docker run -p 8000:8000 -v iasc_data:/data iasc-monitor:latest

set -euo pipefail

IMAGE_NAME="iasc-monitor"
EXTRA_TAG="${1:-}"
PYTHON_VERSION="${PYTHON_VERSION:-3.11}"   # keep in step with the Dockerfile default (verified on 3.11.15)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v docker >/dev/null 2>&1; then
    echo "Error: docker is not installed or not on PATH." >&2
    exit 1
fi

if [ ! -f "Dockerfile" ]; then
    echo "Error: Dockerfile not found in $SCRIPT_DIR - run this script from the project root." >&2
    exit 1
fi

echo "Building ${IMAGE_NAME}:latest (Python ${PYTHON_VERSION})..."

BUILD_ARGS=(
    --build-arg "PYTHON_VERSION=${PYTHON_VERSION}"
    --target runtime
    --tag "${IMAGE_NAME}:latest"
)
# Behind a TLS-inspecting proxy: PIP_CA=/path/to/ca.pem ./build.sh
if [ -n "${PIP_CA:-}" ]; then
    BUILD_ARGS+=(--secret "id=pip_ca,src=${PIP_CA}")
fi

if [ -n "$EXTRA_TAG" ]; then
    BUILD_ARGS+=(--tag "${IMAGE_NAME}:${EXTRA_TAG}")
    echo "Also tagging as ${IMAGE_NAME}:${EXTRA_TAG}"
fi

docker build "${BUILD_ARGS[@]}" .

echo
echo "Build complete: ${IMAGE_NAME}:latest${EXTRA_TAG:+, ${IMAGE_NAME}:${EXTRA_TAG}}"
echo
echo "Run it with:"
echo "  docker compose up -d"
echo "or:"
echo "  docker run -d -p 127.0.0.1:8000:8000 -v iasc_data:/data ${IMAGE_NAME}:latest"
echo
echo "Then check:"
echo "  curl http://localhost:8000/health"
