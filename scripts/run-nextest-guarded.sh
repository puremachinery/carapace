#!/usr/bin/env bash
# Run cargo-nextest with a fail-fast watchdog for internal discovery stalls.
# If a test binary hangs on `--list --format terse`, capture diagnostics and fail quickly.

set -euo pipefail

if ! command -v cargo-nextest >/dev/null 2>&1; then
    echo "cargo-nextest is required. Install with: cargo install --locked cargo-nextest" >&2
    exit 1
fi

LIST_TIMEOUT_SECS="${NEXTEST_LIST_TIMEOUT_SECS:-180}"
POLL_SECS="${NEXTEST_LIST_WATCHDOG_POLL_SECS:-1}"
SAMPLE_SECS="${NEXTEST_LIST_SAMPLE_SECS:-5}"
REPRO_TIMEOUT_SECS="${NEXTEST_LIST_REPRO_TIMEOUT_SECS:-120}"
STRACE_SECS="${NEXTEST_LIST_STRACE_SECS:-3}"
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
    local stalled_etime="$3"
    local stalled_cmd="$4"
    local stalled_age_secs="$5"
    local stamp
    stamp="$(timestamp)"
    local base="${DIAG_DIR}/nextest-list-stall-${stamp}-pid${stalled_pid}"
    local log_file="${base}.log"
    local repro_script="${base}.repro.sh"
    local repro_log="${base}.repro.log"
    local stalled_sample="${base}.sample.txt"
    local stalled_lsof="${base}.lsof.txt"
    local stalled_gstack="${base}.gstack.txt"
    local stalled_pstack="${base}.pstack.txt"
    local stalled_strace="${base}.strace.txt"
    local suspected_binary=""
    local repro_cmd=""

    suspected_binary="$(printf '%s\n' "${stalled_cmd}" \
        | sed -E 's/[[:space:]]+--list[[:space:]]+--format[[:space:]]+terse.*$//' \
        | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    if [ -n "${suspected_binary}" ]; then
        printf -v repro_cmd '%q --list --format terse' "${suspected_binary}"
    fi

    {
        echo "nextest list stall detected"
        echo "timestamp_utc=${stamp}"
        echo "stalled_pid=${stalled_pid}"
        echo "nextest_pid=${nextest_pid}"
        echo "stalled_etime=${stalled_etime}"
        echo "stalled_age_secs=${stalled_age_secs}"
        echo "list_timeout_secs=${LIST_TIMEOUT_SECS}"
        echo "repro_timeout_secs=${REPRO_TIMEOUT_SECS}"
        echo "poll_secs=${POLL_SECS}"
        echo "cwd=$(pwd)"
        echo "stalled_command=${stalled_cmd}"
        echo "suspected_test_binary=${suspected_binary}"
        echo "repro_command=${repro_cmd}"
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

    if command -v lsof >/dev/null 2>&1; then
        lsof -p "${stalled_pid}" > "${stalled_lsof}" 2>&1 || true
    fi

    if [ "$(uname -s)" = "Darwin" ]; then
        if command -v sample >/dev/null 2>&1; then
            sample "${stalled_pid}" "${SAMPLE_SECS}" -file "${stalled_sample}" >/dev/null 2>&1 || true
        fi
    elif [ "$(uname -s)" = "Linux" ]; then
        if command -v gstack >/dev/null 2>&1; then
            gstack "${stalled_pid}" > "${stalled_gstack}" 2>&1 || true
        elif command -v pstack >/dev/null 2>&1; then
            pstack "${stalled_pid}" > "${stalled_pstack}" 2>&1 || true
        fi
        if command -v strace >/dev/null 2>&1; then
            strace -tt -f -p "${stalled_pid}" -o "${stalled_strace}" >/dev/null 2>&1 &
            strace_pid=$!
            sleep "${STRACE_SECS}"
            kill -INT "${strace_pid}" >/dev/null 2>&1 || true
            wait "${strace_pid}" || true
        fi
    fi

    if [ -n "${suspected_binary}" ]; then
        {
            echo "#!/usr/bin/env bash"
            echo "set -euo pipefail"
            printf 'cd %q\n' "$(pwd)"
            printf '%q --list --format terse\n' "${suspected_binary}"
        } > "${repro_script}"
        chmod +x "${repro_script}"

        if [ -x "${suspected_binary}" ]; then
            set +e
            "${suspected_binary}" --list --format terse > "${repro_log}" 2>&1 &
            repro_pid=$!
            remaining="${REPRO_TIMEOUT_SECS}"
            while [ "${remaining}" -gt 0 ]; do
                if ! kill -0 "${repro_pid}" >/dev/null 2>&1; then
                    wait "${repro_pid}"
                    exit_code=$?
                    {
                        echo
                        echo "repro_status=exited"
                        echo "repro_exit_code=${exit_code}"
                    } >> "${repro_log}"
                    break
                fi
                sleep 1
                remaining=$((remaining - 1))
            done

            if [ "${remaining}" -eq 0 ] && kill -0 "${repro_pid}" >/dev/null 2>&1; then
                {
                    echo
                    echo "repro_status=timed_out"
                    echo "repro_timeout_secs=${REPRO_TIMEOUT_SECS}"
                } >> "${repro_log}"

                if [ "$(uname -s)" = "Darwin" ]; then
                    if command -v sample >/dev/null 2>&1; then
                        sample "${repro_pid}" "${SAMPLE_SECS}" -file "${base}.repro.sample.txt" >/dev/null 2>&1 || true
                    fi
                elif [ "$(uname -s)" = "Linux" ]; then
                    if command -v gstack >/dev/null 2>&1; then
                        gstack "${repro_pid}" > "${base}.repro.gstack.txt" 2>&1 || true
                    elif command -v pstack >/dev/null 2>&1; then
                        pstack "${repro_pid}" > "${base}.repro.pstack.txt" 2>&1 || true
                    fi
                    if command -v strace >/dev/null 2>&1; then
                        strace -tt -f -p "${repro_pid}" -o "${base}.repro.strace.txt" >/dev/null 2>&1 &
                        repro_strace_pid=$!
                        sleep "${STRACE_SECS}"
                        kill -INT "${repro_strace_pid}" >/dev/null 2>&1 || true
                        wait "${repro_strace_pid}" || true
                    fi
                fi
                if command -v lsof >/dev/null 2>&1; then
                    lsof -p "${repro_pid}" > "${base}.repro.lsof.txt" 2>&1 || true
                fi

                kill "${repro_pid}" >/dev/null 2>&1 || true
                wait "${repro_pid}" || true
            fi
            set -e
        else
            echo "repro_status=skipped_non_executable_binary" > "${repro_log}"
        fi
    fi

    echo "nextest discovery stall detected; diagnostics written to ${log_file}" >&2
    if [ -n "${repro_cmd}" ]; then
        echo "repro command: ${repro_cmd}" >&2
    else
        echo "repro command: unavailable (could not parse stalled child command)" >&2
    fi
    if [ -f "${stalled_sample}" ]; then
        echo "macOS sample written to ${stalled_sample}" >&2
    fi
    if [ -f "${repro_script}" ]; then
        echo "repro script written to ${repro_script}" >&2
    fi
    if [ -f "${repro_log}" ]; then
        echo "repro log written to ${repro_log}" >&2
    fi
}

list_discovery_pid_etime_and_command() {
    local nextest_pid="$1"
    ps -Ao pid=,ppid=,etime=,command= 2>/dev/null \
        | awk -v nextest_pid="${nextest_pid}" '
            $2 == nextest_pid && /--list --format terse/ {
                pid=$1
                etime=$3
                $1=""; $2=""; $3=""
                sub(/^[[:space:]]+/, "", $0)
                print pid "|" etime "|" $0
            }
        ' \
        || true
}

cargo nextest run "$@" &
nextest_pid=$!

while kill -0 "${nextest_pid}" >/dev/null 2>&1; do
    while IFS='|' read -r pid etime cmd; do
        [ -z "${pid}" ] && continue
        age_secs="$(etime_to_seconds "${etime}")"
        if [ "${age_secs}" -lt "${LIST_TIMEOUT_SECS}" ]; then
            continue
        fi

        capture_diagnostics "${pid}" "${nextest_pid}" "${etime}" "${cmd}" "${age_secs}"
        kill "${pid}" >/dev/null 2>&1 || true
        kill "${nextest_pid}" >/dev/null 2>&1 || true
        wait "${nextest_pid}" || true
        exit 124
    done < <(list_discovery_pid_etime_and_command "${nextest_pid}")

    sleep "${POLL_SECS}"
done

wait "${nextest_pid}"
