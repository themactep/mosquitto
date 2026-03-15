#!/usr/bin/env bash
set -euo pipefail

# Colorized output — disabled automatically when stdout is not a tty or NO_COLOR is set.
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
	RED=$'\033[0;31m'
	GREEN=$'\033[0;32m'
	YELLOW=$'\033[0;33m'
	CYAN=$'\033[0;36m'
	BOLD=$'\033[1m'
	RESET=$'\033[0m'
else
	RED='' GREEN='' YELLOW='' CYAN='' BOLD='' RESET=''
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-build-mbedtls}"
PUB_BIN="${PUB_BIN:-${ROOT_DIR}/${BUILD_DIR}/client/mosquitto_pub}"
SUB_BIN="${SUB_BIN:-${ROOT_DIR}/${BUILD_DIR}/client/mosquitto_sub}"

HOST="${HOST:-test.mosquitto.org}"
PORT_PLAIN="${PORT_PLAIN:-1883}"
# Default TLS port is 8886 (Let's Encrypt cert — works with system CA bundles).
# Use PORT_TLS=8883 only if you supply --cafile mosquitto.org.crt (custom CA).
PORT_TLS="${PORT_TLS:-8886}"
TIMEOUT_SECS="${TIMEOUT_SECS:-10}"
TOPIC_PREFIX="${TOPIC_PREFIX:-copilot/mosquitto-smoketest}"
TLS_MODE="off"
ALL_MODE="off"
# Default insecure=0: port 8886 (Let's Encrypt) doesn't need --insecure.
TLS_INSECURE="${TLS_INSECURE:-0}"
CAFILE_PATH="${CAFILE_PATH:-}"
DEBUG_MODE="${DEBUG_MODE:-0}"
VERBOSE_MODE="${VERBOSE_MODE:-0}"
QOS="${QOS:-0}"

declare -a RESULTS=()

usage() {
	cat <<EOF
Usage: ./test-test-mosquitto.sh [options]

Smoke-test compiled mosquitto_pub/mosquitto_sub binaries against test.mosquitto.org.

Options:
  --all                 Loop through all testable endpoints and show a summary
  --tls                 Also run a TLS test on port \$PORT_TLS (default: 8886)
  --debug               Run clients in protocol debug mode (-d)
  --verbose             Run subscriber in verbose mode (-v)
  --qos <0|1|2>         Publish/subscribe QoS level (default: ${QOS})
  --insecure            For TLS test, skip certificate verification (--insecure)
  --cafile <path>       For TLS test, use this CA file for certificate verification
  --timeout <seconds>   Subscriber timeout (default: ${TIMEOUT_SECS})
  -h, --help            Show this help

test.mosquitto.org TLS port guide:
  1883  plain MQTT, no auth
  8883  MQTT+TLS, self-signed CA  → CA auto-downloaded when testing this port
  8884  MQTT+TLS, client cert required  (skipped in --all mode)
  8886  MQTT+TLS, Let's Encrypt CA → system CA bundle works (default TLS port)
  8887  MQTT+TLS, expired cert     → use --insecure for testing error paths

Environment overrides:
  BUILD_DIR, PUB_BIN, SUB_BIN, HOST, PORT_PLAIN, PORT_TLS,
  TIMEOUT_SECS, TOPIC_PREFIX, TLS_INSECURE, CAFILE_PATH,
  DEBUG_MODE, VERBOSE_MODE, QOS
EOF
}

print_cmd() {
	local prefix="$1"
	shift
	printf '%s' "${prefix}"
	for arg in "$@"; do
		printf ' %q' "${arg}"
	done
	printf '\n'
}

record_result() {
	RESULTS+=("$1:$2")
}

# Returns the path of the first readable system CA bundle, or fails.
find_system_ca() {
	local -a candidates=(
		/etc/ssl/certs/ca-certificates.crt
		/etc/ssl/certs/ca-bundle.crt
		/etc/pki/tls/certs/ca-bundle.crt
		/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
		/etc/ssl/cert.pem
	)
	local f
	for f in "${candidates[@]}"; do
		[[ -r "${f}" ]] && printf '%s' "${f}" && return 0
	done
	return 1
}

print_summary() {
	local pass=0 fail=0 skip=0
	echo ""
	printf '%s=== Test Summary ===%s\n' "${BOLD}" "${RESET}"
	printf '%-38s %s\n' "Endpoint" "Result"
	printf '%-38s %s\n' "--------" "------"
	for entry in "${RESULTS[@]}"; do
		local label="${entry%:*}"
		local status="${entry##*:}"
		case "${status}" in
			PASS) printf '%-38s %s\n' "${label}" "${GREEN}PASS${RESET}"; ((pass+=1)) ;;
			FAIL) printf '%-38s %s\n' "${label}" "${RED}FAIL${RESET}";  ((fail+=1)) ;;
			SKIP) printf '%-38s %s\n' "${label}" "${YELLOW}SKIP${RESET}"; ((skip+=1)) ;;
		esac
	done
	echo ""
	printf '%s%d passed%s' "${GREEN}" "${pass}" "${RESET}"
	[[ ${fail} -gt 0 ]] && printf ', %s%d failed%s'  "${RED}"    "${fail}" "${RESET}"
	[[ ${skip} -gt 0 ]] && printf ', %s%d skipped%s' "${YELLOW}" "${skip}" "${RESET}"
	printf '\n'
	[[ ${fail} -eq 0 ]]
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--all)
			ALL_MODE="on"
			shift
			;;
		--tls)
			TLS_MODE="on"
			shift
			;;
		--debug)
			DEBUG_MODE="1"
			shift
			;;
		--verbose)
			VERBOSE_MODE="1"
			shift
			;;
		--qos)
			[[ $# -ge 2 ]] || { echo "Missing value for --qos" >&2; exit 2; }
			QOS="$2"
			shift 2
			;;
		--insecure)
			TLS_INSECURE="1"
			shift
			;;
		--cafile)
			[[ $# -ge 2 ]] || { echo "Missing value for --cafile" >&2; exit 2; }
			CAFILE_PATH="$2"
			shift 2
			;;
		--timeout)
			[[ $# -ge 2 ]] || { echo "Missing value for --timeout" >&2; exit 2; }
			TIMEOUT_SECS="$2"
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

if [[ ! -x "${PUB_BIN}" ]]; then
	echo "mosquitto_pub not found or not executable: ${PUB_BIN}" >&2
	exit 1
fi
if [[ ! -x "${SUB_BIN}" ]]; then
	echo "mosquitto_sub not found or not executable: ${SUB_BIN}" >&2
	exit 1
fi

if ! [[ "${TIMEOUT_SECS}" =~ ^[0-9]+$ ]] || [[ "${TIMEOUT_SECS}" -le 0 ]]; then
	echo "TIMEOUT_SECS must be a positive integer, got: ${TIMEOUT_SECS}" >&2
	exit 2
fi

if ! [[ "${QOS}" =~ ^[0-2]$ ]]; then
	echo "QOS must be 0, 1, or 2, got: ${QOS}" >&2
	exit 2
fi

TMP_DIR="$(mktemp -d)"
# Track the subscriber PID so cleanup can kill it on interrupt.
CURRENT_SUB_PID=""

cleanup() {
	[[ -n "${CURRENT_SUB_PID}" ]] && kill "${CURRENT_SUB_PID}" >/dev/null 2>&1 || true
	# Kill any other background jobs spawned by this script.
	jobs -p | xargs -r kill >/dev/null 2>&1 || true
	rm -rf "${TMP_DIR}"
}

interrupted() {
	echo "" >&2
	echo "${RED}Interrupted.${RESET}" >&2
	cleanup
	# Re-raise SIGINT so the shell exits with the correct status (130).
	trap - INT
	kill -INT "$$"
}

trap cleanup EXIT
trap interrupted INT TERM

random_id() {
	printf '%s-%s-%s' "$$" "$(date +%s)" "$RANDOM"
}

# _run_attempt LABEL PORT TLS_ON CAFILE INSECURE ATTEMPT [CLIENT_CERT [CLIENT_KEY]]
#   Single test attempt. Returns 0 on pass, 1 on failure.
#   Does NOT call record_result — the caller handles that after retries.
_run_attempt() {
	local label="$1"
	local port="$2"
	local tls_on="$3"
	local cafile="$4"
	local insecure="$5"
	local attempt="$6"
	local certfile="${7:-}"
	local keyfile="${8:-}"
	local safe_label
	safe_label="$(printf '%s' "${label}" | tr -cs 'a-zA-Z0-9_-' '_')"
	local sub_out="${TMP_DIR}/sub-${safe_label}-${attempt}.out"
	local pub_out="${TMP_DIR}/pub-${safe_label}-${attempt}.out"
	local topic="${TOPIC_PREFIX}/${safe_label}/$(random_id)"
	local message="smoke-${safe_label}-$(random_id)"
	local sub_pid
	local sub_timeout
	local pub_timeout
	local -a tls_args=()
	local -a sub_cmd=()
	local -a pub_cmd=()

	sub_timeout="$((TIMEOUT_SECS + 3))"
	pub_timeout="$((TIMEOUT_SECS + 3))"

	if [[ "${tls_on}" == "on" ]]; then
		# mosquitto clients require --cafile (or --capath) to actually enable TLS;
		# without it they connect as plain MQTT even when --insecure is set.
		if [[ -z "${cafile}" ]]; then
			cafile="$(find_system_ca)" || {
				echo "${RED}[${label}] no system CA bundle found; cannot enable TLS${RESET}" >&2
				return 1
			}
		fi
		tls_args+=(--cafile "${cafile}")
		[[ "${insecure}" == "1" ]] && tls_args+=(--insecure)
		if [[ -n "${certfile}" && -n "${keyfile}" ]]; then
			tls_args+=(--cert "${certfile}" --key "${keyfile}")
		fi
	fi

	sub_cmd=("${SUB_BIN}" -h "${HOST}" -p "${port}" -t "${topic}" -C 1 -W "${TIMEOUT_SECS}" -q "${QOS}")
	pub_cmd=("${PUB_BIN}" -h "${HOST}" -p "${port}" -t "${topic}" -m "${message}" -q "${QOS}")

	if [[ "${DEBUG_MODE}" == "1" ]]; then
		sub_cmd+=(-d)
		pub_cmd+=(-d)
	fi
	[[ "${VERBOSE_MODE}" == "1" ]] && sub_cmd+=(-v)

	sub_cmd+=("${tls_args[@]}")
	pub_cmd+=("${tls_args[@]}")

	if [[ "${DEBUG_MODE}" == "1" ]]; then
		print_cmd "[${label}] sub cmd:" "${sub_cmd[@]}"
	fi
	timeout "${sub_timeout}s" "${sub_cmd[@]}" >"${sub_out}" 2>&1 &
	sub_pid=$!
	CURRENT_SUB_PID="${sub_pid}"

	# Give subscriber time to connect and subscribe before publishing.
	# Plain MQTT connects in <100 ms; 2 s gives ample margin even under load.
	sleep 2

	# Bail early if the subscriber already exited (connection failure).
	if ! kill -0 "${sub_pid}" 2>/dev/null; then
		CURRENT_SUB_PID=""
		echo "${RED}[${label}] subscriber exited before publisher ran.${RESET}" >&2
		echo "[${label}] subscriber output:" >&2
		sed -n '1,160p' "${sub_out}" >&2 || true
		return 1
	fi

	if [[ "${DEBUG_MODE}" == "1" ]]; then
		print_cmd "[${label}] pub cmd:" "${pub_cmd[@]}"
	fi
	if ! timeout "${pub_timeout}s" "${pub_cmd[@]}" >"${pub_out}" 2>&1; then
		echo "${RED}[${label}] publisher failed or timed out.${RESET}" >&2
		echo "[${label}] publisher output:" >&2
		sed -n '1,160p' "${pub_out}" >&2 || true
		kill "${sub_pid}" >/dev/null 2>&1 || true
		wait "${sub_pid}" >/dev/null 2>&1 || true
		CURRENT_SUB_PID=""
		return 1
	fi

	if ! wait "${sub_pid}"; then
		CURRENT_SUB_PID=""
		echo "${RED}[${label}] subscriber failed or timed out.${RESET}" >&2
		echo "[${label}] subscriber output:" >&2
		sed -n '1,160p' "${sub_out}" >&2 || true
		return 1
	fi
	CURRENT_SUB_PID=""

	if [[ "${VERBOSE_MODE}" == "1" ]]; then
		if ! grep -Fxq "${topic} ${message}" "${sub_out}"; then
			echo "${RED}[${label}] message mismatch.${RESET}" >&2
			echo "[${label}] expected verbose line: ${topic} ${message}" >&2
			echo "[${label}] got:" >&2
			sed -n '1,160p' "${sub_out}" >&2 || true
			return 1
		fi
	elif ! grep -Fxq "${message}" "${sub_out}"; then
		echo "${RED}[${label}] message mismatch.${RESET}" >&2
		echo "[${label}] expected: ${message}" >&2
		echo "[${label}] got:" >&2
		sed -n '1,160p' "${sub_out}" >&2 || true
		return 1
	fi

	if [[ "${DEBUG_MODE}" == "1" ]]; then
		echo "[${label}] subscriber output:"
		sed -n '1,160p' "${sub_out}" || true
		echo "[${label}] publisher output:"
		sed -n '1,160p' "${pub_out}" || true
	fi

	return 0
}

# run_single_test LABEL PORT TLS_ON CAFILE INSECURE [CLIENT_CERT [CLIENT_KEY]]
#   Retries up to MAX_RETRIES times on transient failures (QoS 0 loss, etc.).
#   Records and prints the final PASS/FAIL result.
MAX_RETRIES="${MAX_RETRIES:-3}"
run_single_test() {
	local label="$1"
	local port="$2"
	local attempt

	echo "${CYAN}[${label}]${RESET} subscribing on ${HOST}:${port} ..."

	for ((attempt=1; attempt<=MAX_RETRIES; attempt+=1)); do
		if _run_attempt "$1" "$2" "$3" "$4" "$5" "${attempt}" "${6:-}" "${7:-}"; then
			echo "${GREEN}[${label}] PASS${RESET}"
			record_result "${label}" "PASS"
			return 0
		fi
		if [[ ${attempt} -lt ${MAX_RETRIES} ]]; then
			echo "${YELLOW}[${label}] attempt ${attempt}/${MAX_RETRIES} failed — retrying ...${RESET}" >&2
		fi
	done

	echo "${RED}[${label}] FAIL (all ${MAX_RETRIES} attempts exhausted)${RESET}" >&2
	record_result "${label}" "FAIL"
	return 1
}

echo "Using pub: ${PUB_BIN}"
echo "Using sub: ${SUB_BIN}"
echo ""

fetch_mosquitto_ca() {
	local dest="$1"
	local url="https://test.mosquitto.org/ssl/mosquitto.org.crt"
	echo "${CYAN}Downloading mosquitto.org CA cert ...${RESET}"
	if ! curl -fsSL --max-time 15 -o "${dest}" "${url}"; then
		echo "${RED}Failed to download CA cert from ${url}${RESET}" >&2
		return 1
	fi
}

# fetch_8884_client_cert KEY_DEST CERT_DEST
#   Generates an RSA key + CSR, then POSTs the CSR to test.mosquitto.org for
#   signing. The signed certificate is written to CERT_DEST.
fetch_8884_client_cert() {
	local key_dest="$1"
	local cert_dest="$2"
	local csr="${TMP_DIR}/client8884.csr"
	local cn="smoketest-$$-$(date +%s)"
	echo "${CYAN}Generating client key and CSR for port 8884 ...${RESET}"
	if ! openssl genrsa -out "${key_dest}" 2048 2>/dev/null; then
		echo "${RED}openssl genrsa failed${RESET}" >&2
		return 1
	fi
	if ! openssl req -new -key "${key_dest}" \
			-subj "/C=US/O=MosquittoSmokeTest/CN=${cn}" \
			-out "${csr}" 2>/dev/null; then
		echo "${RED}openssl req failed${RESET}" >&2
		return 1
	fi
	echo "${CYAN}Submitting CSR to test.mosquitto.org for signing ...${RESET}"
	if ! curl -fsSL --max-time 30 -X POST \
			https://test.mosquitto.org/ssl/index.php \
			--data-urlencode "csr@${csr}" \
			-o "${cert_dest}"; then
		echo "${RED}Failed to POST CSR to test.mosquitto.org${RESET}" >&2
		return 1
	fi
	if ! grep -q "BEGIN CERTIFICATE" "${cert_dest}"; then
		echo "${RED}Response from test.mosquitto.org was not a certificate:${RESET}" >&2
		sed -n '1,10p' "${cert_dest}" >&2 || true
		return 1
	fi
}

run_all_tests() {
	local mosquitto_ca="${TMP_DIR}/mosquitto.org.crt"
	printf '%sRunning all test.mosquitto.org endpoints%s\n\n' "${BOLD}" "${RESET}"

	# 1883 — plain MQTT
	run_single_test "1883 plain" "${PORT_PLAIN}" "off" "" "0" || true

	# 8886 — TLS, Let's Encrypt CA (system bundle works)
	run_single_test "8886 tls (Let's Encrypt)" "8886" "on" "" "0" || true

	# 8883 — TLS, custom self-signed CA (auto-download)
	if fetch_mosquitto_ca "${mosquitto_ca}"; then
		run_single_test "8883 tls (custom CA)" "8883" "on" "${mosquitto_ca}" "0" || true
	else
		printf '%s[8883 tls (custom CA)]%s SKIP — CA download failed\n' "${YELLOW}" "${RESET}" >&2
		record_result "8883 tls (custom CA)" "SKIP"
	fi

	# 8884 — client certificate required; auto-generate key/CSR and submit to signing form
	local client_key="${TMP_DIR}/client8884.key"
	local client_cert="${TMP_DIR}/client8884.crt"
	if fetch_8884_client_cert "${client_key}" "${client_cert}"; then
		# Port 8884 uses the same mosquitto.org CA as 8883.
		# Re-download if not already present (e.g. 8883 download was skipped).
		if [[ ! -f "${mosquitto_ca}" ]]; then
			fetch_mosquitto_ca "${mosquitto_ca}" || true
		fi
		if [[ -f "${mosquitto_ca}" ]]; then
			run_single_test "8884 tls (client cert)" "8884" "on" "${mosquitto_ca}" "0" \
				"${client_cert}" "${client_key}" || true
		else
			echo "${RED}[8884 tls (client cert)] SKIP — CA cert unavailable${RESET}" >&2
			record_result "8884 tls (client cert)" "SKIP"
		fi
	else
		echo "${YELLOW}[8884 tls (client cert)] SKIP — could not obtain client cert${RESET}" >&2
		record_result "8884 tls (client cert)" "SKIP"
	fi

	# 8887 — expired cert; use --insecure to still exercise the MQTT path
	run_single_test "8887 tls (expired+insecure)" "8887" "on" "" "1" || true
}

if [[ "${ALL_MODE}" == "on" ]]; then
	run_all_tests
	print_summary
else
	run_single_test "${PORT_PLAIN} plain" "${PORT_PLAIN}" "off" "" "0"

	if [[ "${TLS_MODE}" == "on" ]]; then
		# For port 8883 (custom self-signed CA), auto-download the CA cert if none supplied.
		if [[ "${PORT_TLS}" == "8883" && -z "${CAFILE_PATH}" && "${TLS_INSECURE}" != "1" ]]; then
			CAFILE_PATH="${TMP_DIR}/mosquitto.org.crt"
			fetch_mosquitto_ca "${CAFILE_PATH}"
		fi
		run_single_test "${PORT_TLS} tls" "${PORT_TLS}" "on" "${CAFILE_PATH}" "${TLS_INSECURE}"
	fi

	print_summary
fi
