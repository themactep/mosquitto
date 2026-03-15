#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CMAKE_BIN="${CMAKE_BIN:-cmake}"
BUILD_DIR="${BUILD_DIR:-build-mbedtls}"
JOBS="${JOBS:-$(nproc)}"

# Build only deliverable binaries/libs by default. Override with BUILD_TARGETS.
if [[ -n "${BUILD_TARGETS:-}" ]]; then
	read -r -a TARGETS <<< "${BUILD_TARGETS}"
else
	TARGETS=(mosquitto mosquitto_pub mosquitto_sub libmosquitto)
fi

"${CMAKE_BIN}" -S "${ROOT_DIR}" -B "${ROOT_DIR}/${BUILD_DIR}" \
	-DWITH_TLS=ON \
	-DWITH_TLS_BACKEND=mbedtls \
	-DWITH_TLS_PSK=OFF \
	-DWITH_WEBSOCKETS=OFF \
	-DWITH_DOCS=OFF \
	-DWITH_TESTS=OFF

"${CMAKE_BIN}" --build "${ROOT_DIR}/${BUILD_DIR}" --target "${TARGETS[@]}" -j"${JOBS}"

echo "Build completed."
echo "Broker: ${ROOT_DIR}/${BUILD_DIR}/src/mosquitto"
echo "Clients: ${ROOT_DIR}/${BUILD_DIR}/client/mosquitto_pub and ${ROOT_DIR}/${BUILD_DIR}/client/mosquitto_sub"
