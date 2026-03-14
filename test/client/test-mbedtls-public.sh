#!/usr/bin/env bash

# Build Mosquitto against mbed TLS for the host architecture, then run a
# smoke test against test.mosquitto.org:8883 using the compiled clients.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build-host-mbedtls"

CC_BIN="${CC_BIN:-/usr/bin/gcc}"
CXX_BIN="${CXX_BIN:-/usr/bin/g++}"
PKG_CONFIG_BIN="${PKG_CONFIG_BIN:-/usr/bin/pkg-config}"

CAFILE="${TMPDIR:-/tmp}/mosquitto.org.crt"
BROKER_HOST="test.mosquitto.org"
BROKER_PORT="8883"
TEST_TOPIC="copilot/mbedtls/tls/verify-$(date +%s)-$$"
TEST_PAYLOAD="retained-ok"

SUB_LOG="$(mktemp)"

cleanup()
{
	if [[ -x "${BUILD_DIR}/client/mosquitto_pub" && -f "${CAFILE}" ]]; then
		"${BUILD_DIR}/client/mosquitto_pub" -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
			--cafile "${CAFILE}" -t "${TEST_TOPIC}" -n -r >/dev/null 2>&1 || true
	fi
	rm -f "${SUB_LOG}" "${CAFILE}"
}
trap cleanup EXIT

require_cmd()
{
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "Error: Required command '$1' not found." >&2
		exit 1
	fi
}

require_cmd cmake
require_cmd curl
require_cmd ldd

if [[ ! -x "${CC_BIN}" ]]; then
	echo "Error: Compiler not found or not executable: ${CC_BIN}" >&2
	exit 1
fi
if [[ ! -x "${CXX_BIN}" ]]; then
	echo "Error: C++ compiler not found or not executable: ${CXX_BIN}" >&2
	exit 1
fi
if [[ ! -x "${PKG_CONFIG_BIN}" ]]; then
	echo "Error: pkg-config not found or not executable: ${PKG_CONFIG_BIN}" >&2
	exit 1
fi

echo "==> Configuring host build with mbed TLS"
CC="${CC_BIN}" CXX="${CXX_BIN}" PKG_CONFIG="${PKG_CONFIG_BIN}" \
	cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" \
	-DWITH_TLS=ON \
	-DWITH_TLS_BACKEND=mbedtls \
	-DWITH_TLS_PSK=OFF \
	-DWITH_WEBSOCKETS=OFF \
	-DWITH_DOCS=OFF \
	-DWITH_TESTS=OFF

echo "==> Building"
CC="${CC_BIN}" CXX="${CXX_BIN}" PKG_CONFIG="${PKG_CONFIG_BIN}" \
	cmake --build "${BUILD_DIR}" --parallel

echo "==> Verifying mbed TLS linkage"
if ! ldd "${BUILD_DIR}/lib/libmosquitto.so" | grep -Eq 'libmbedtls|libmbedx509|libmbedcrypto'; then
	echo "Error: libmosquitto is not linked against mbed TLS libraries." >&2
	exit 1
fi

echo "==> Downloading test.mosquitto.org CA certificate"
curl -fsSL "https://test.mosquitto.org/ssl/mosquitto.org.crt" -o "${CAFILE}"

export LD_LIBRARY_PATH="${BUILD_DIR}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

echo "==> Publishing retained test message to ${BROKER_HOST}:${BROKER_PORT}"
publish_ok=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
	if "${BUILD_DIR}/client/mosquitto_pub" -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
		--cafile "${CAFILE}" -t "${TEST_TOPIC}" -m "${TEST_PAYLOAD}" -r >/dev/null 2>&1; then
		echo "Publish succeeded on attempt ${attempt}"
		publish_ok=1
		break
	fi
	echo "Publish failed on attempt ${attempt}, retrying..."
	sleep 1
done
if [[ "${publish_ok}" -ne 1 ]]; then
	echo "Error: Failed to publish retained message over TLS." >&2
	exit 1
fi

echo "==> Subscribing to verify retained payload"
subscribe_ok=0
for attempt in 1 2 3 4 5; do
	if "${BUILD_DIR}/client/mosquitto_sub" -h "${BROKER_HOST}" -p "${BROKER_PORT}" \
		--cafile "${CAFILE}" -t "${TEST_TOPIC}" -C 1 -W 10 >"${SUB_LOG}" 2>/dev/null; then
		got_payload="$(cat "${SUB_LOG}")"
		if [[ "${got_payload}" == "${TEST_PAYLOAD}" ]]; then
			echo "Subscribe succeeded on attempt ${attempt}"
			subscribe_ok=1
			break
		fi
		echo "Received unexpected payload: '${got_payload}'"
	else
		echo "Subscribe failed on attempt ${attempt}, retrying..."
	fi
	sleep 1
done
if [[ "${subscribe_ok}" -ne 1 ]]; then
	echo "Error: Failed to verify retained message over TLS." >&2
	exit 1
fi

echo "SUCCESS: Host mbed TLS build + test.mosquitto.org TLS smoke test passed."
