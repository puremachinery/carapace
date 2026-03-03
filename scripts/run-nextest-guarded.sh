#!/usr/bin/env bash
# Run cargo-nextest with a fail-fast watchdog for internal discovery stalls.
# If a test binary hangs on `--list --format terse`, capture diagnostics and fail quickly.

set -euo pipefail

if ! command -v cargo-nextest >/dev/null 2>&1; then
    echo "cargo-nextest is required. Install with: cargo install --locked cargo-nextest" >&2
    exit 1
fi

LIST_TIMEOUT_SECS="${NEXTEST_LIST_TIMEOUT_SECS:-90}"
POLL_SECS="${NEXTEST_LIST_WATCHDOG_POLL_SECS:-1}"
SAMPLE_SECS="${NEXTEST_LIST_SAMPLE_SECS:-5}"
DIAG_DIR="${NEXTEST_LIST_DIAG_DIR:-.local/reports/nextest-list-stalls}"

mkdir -p "${DIAG_DIR}"

timestamp() {
    date -u +"%Y%m%dT%H%M%SZ"
}

etime_to_seconds() {
    local etime="$1"
    if [ -z "${etime}" ]; then
        echo "0"
        return
    fi

    local days=0
    local clock="${etime}"
    if [[ "${clock}" == *-* ]]; then
        days="${clock%%-*}"
        clock="${clock#*-}"
    fi

    IFS=':' read -r a b c <<< "${clock}"
    local hours=0
    local minutes=0
    local seconds=0

    if [ -n "${c:-}" ]; then
        hours="${a:-0}"
        minutes="${b:-0}"
        seconds="${c:-0}"
    elif [ -n "${b:-}" ]; then
        minutes="${a:-0}"
        seconds="${b:-0}"
    else
        seconds="${a:-0}"
    fi

    echo $((days * 86400 + hours * 3600 + minutes * 60 + seconds))
}

capture_diagnostics() {
    local stalled_pid="$1"
    local nextest_pid="$2"
    local stamp
    stamp="$(timestamp)"
    local base="${DIAG_DIR}/nextest-list-stall-${stamp}-pid${stalled_pid}"
    local log_file="${base}.log"

    {
        echo "nextest list stall detected"
        echo "timestamp_utc=${stamp}"
        echo "stalled_pid=${stalled_pid}"
        echo "nextest_pid=${nextest_pid}"
        echo "list_timeout_secs=${LIST_TIMEOUT_SECS}"
        echo "poll_secs=${POLL_SECS}"
        echo "cwd=$(pwd)"
        echo
        echo "stalled process:"
        ps -p "${stalled_pid}" -o pid=,ppid=,etime=,command= || true
        echo
        echo "nextest process:"
        ps -p "${nextest_pid}" -o pid=,ppid=,etime=,command= || true
        echo
        echo "related process snapshot:"
        ps -Ao pid=,ppid=,etime=,command= 2>/dev/null | rg "cargo-nextest|--list --format terse|target/debug/deps/" || true
    } >"${log_file}"

    if [ "$(uname -s)" = "Darwin" ] && command -v sample >/dev/null 2>&1; then
        sample "${stalled_pid}" "${SAMPLE_SECS}" -file "${base}.sample.txt" >/dev/null 2>&1 || true
    fi

    echo "nextest discovery stall detected; diagnostics written to ${log_file}" >&2
    if [ -f "${base}.sample.txt" ]; then
        echo "macOS sample written to ${base}.sample.txt" >&2
    fi
}

list_discovery_pid_and_etime() {
    local nextest_pid="$1"
    ps -Ao pid=,ppid=,etime=,command= 2>/dev/null \
        | awk -v nextest_pid="${nextest_pid}" '$2 == nextest_pid && /--list --format terse/ {print $1 "|" $3}' \
        || true
}

cargo nextest run "$@" &
nextest_pid=$!

while kill -0 "${nextest_pid}" >/dev/null 2>&1; do
    while IFS='|' read -r pid etime; do
        [ -z "${pid}" ] && continue
        age_secs="$(etime_to_seconds "${etime}")"
        if [ "${age_secs}" -lt "${LIST_TIMEOUT_SECS}" ]; then
            continue
        fi

        capture_diagnostics "${pid}" "${nextest_pid}"
        kill "${pid}" >/dev/null 2>&1 || true
        kill "${nextest_pid}" >/dev/null 2>&1 || true
        wait "${nextest_pid}" || true
        exit 124
    done < <(list_discovery_pid_and_etime "${nextest_pid}")

    sleep "${POLL_SECS}"
done

wait "${nextest_pid}"
