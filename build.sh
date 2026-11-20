#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CMAKE_BIN="${CMAKE_BIN:-cmake}"
BUILD_DIR="${BUILD_DIR:-build-mbedtls}"
JOBS="${JOBS:-$(nproc)}"

# Some distributions ship mbedtls in a versioned prefix (e.g. Arch's mbedtls3
# installs to /usr/lib/mbedtls3) rather than exposing it on the default
# pkg-config and linker search paths. Add the first such prefix found so that
# a plain ./build.sh works without manual environment setup. Any explicitly
# provided PKG_CONFIG_PATH / LIBRARY_PATH is appended to, never replaced.
MBEDTLS_PREFIX=""
if ! pkg-config --exists mbedtls 2>/dev/null; then
	for candidate in /usr/lib/mbedtls3 /usr/local/lib/mbedtls3; do
		if [[ -f "${candidate}/pkgconfig/mbedtls.pc" ]]; then
			MBEDTLS_PREFIX="${candidate}"
			export PKG_CONFIG_PATH="${candidate}/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
			export LIBRARY_PATH="${candidate}${LIBRARY_PATH:+:${LIBRARY_PATH}}"
			break
		fi
	done
fi

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
if [[ -n "${MBEDTLS_PREFIX}" ]]; then
	echo "mbedtls: ${MBEDTLS_PREFIX}"
	echo "Note: binaries link against ${MBEDTLS_PREFIX}, so set"
	echo "      LD_LIBRARY_PATH=${MBEDTLS_PREFIX} when running them."
fi
