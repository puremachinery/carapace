#!/usr/bin/env bash
# Run cargo-nextest with a fail-fast watchdog for internal discovery stalls.
# If a test binary hangs on `--list --format terse`, capture diagnostics and fail quickly.
#
# Runtime tuning knobs:
# - NEXTEST_LIST_TIMEOUT_SECS
# - NEXTEST_LIST_REPRO_TIMEOUT_SECS
# - NEXTEST_LIST_STRACE_SECS
# - NEXTEST_TERM_GRACE_SECS
# - NEXTEST_LIST_WATCHDOG_POLL_SECS
# - NEXTEST_LIST_SAMPLE_SECS
# - NEXTEST_LIST_DIAG_DIR

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
TERM_GRACE_SECS="${NEXTEST_TERM_GRACE_SECS:-5}"
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

record_diag_error() {
    local error_log="$1"
    shift
    printf '[%s] %s\n' "$(timestamp)" "$*" >> "${error_log}"
}

process_is_running() {
    local pid="$1"
    if ! kill -0 "${pid}" >/dev/null 2>&1; then
        return 1
    fi

    local stat
    if ! stat="$(ps -p "${pid}" -o stat= 2>/dev/null | tr -d '[:space:]')"; then
        return 1
    fi
    case "${stat}" in
        ""|Z*|*Z*)
            return 1
            ;;
    esac
    return 0
}

terminate_pid_bounded() {
    local pid="$1"
    local label="$2"
    local error_log="$3"

    if ! process_is_running "${pid}"; then
        return 0
    fi
    if ! kill "${pid}" 2>> "${error_log}"; then
        record_diag_error "${error_log}" "failed to send TERM to ${label} pid=${pid}"
    fi

    local remaining="${TERM_GRACE_SECS}"
    while [ "${remaining}" -gt 0 ]; do
        if ! process_is_running "${pid}"; then
            return 0
        fi
        sleep 1
        remaining=$((remaining - 1))
    done

    if process_is_running "${pid}"; then
        if ! kill -KILL "${pid}" 2>> "${error_log}"; then
            record_diag_error "${error_log}" "failed to send KILL to ${label} pid=${pid}"
            return 1
        fi
    fi

    local confirm_remaining="${TERM_GRACE_SECS}"
    while [ "${confirm_remaining}" -gt 0 ]; do
        if ! process_is_running "${pid}"; then
            return 0
        fi
        sleep 1
        confirm_remaining=$((confirm_remaining - 1))
    done

    record_diag_error "${error_log}" "${label} pid=${pid} still running after TERM/KILL grace windows"
    return 1
}

capture_process_artifacts() {
    local pid="$1"
    local output_prefix="$2"
    local error_log="${output_prefix}.errors.log"
    local os
    os="$(uname -s)"

    if command -v lsof >/dev/null 2>&1; then
        if ! lsof -p "${pid}" > "${output_prefix}.lsof.txt" 2>> "${error_log}"; then
            record_diag_error "${error_log}" "lsof failed for pid=${pid}"
        fi
    fi

    if [ "${os}" = "Darwin" ]; then
        if command -v sample >/dev/null 2>&1; then
            if ! sample "${pid}" "${SAMPLE_SECS}" -file "${output_prefix}.sample.txt" >> "${error_log}" 2>&1; then
                record_diag_error "${error_log}" "sample failed for pid=${pid}"
            fi
        fi
        return
    fi

    if [ "${os}" = "Linux" ]; then
        if command -v gstack >/dev/null 2>&1; then
            if ! gstack "${pid}" > "${output_prefix}.gstack.txt" 2>> "${error_log}"; then
                record_diag_error "${error_log}" "gstack failed for pid=${pid}"
            fi
        elif command -v pstack >/dev/null 2>&1; then
            if ! pstack "${pid}" > "${output_prefix}.pstack.txt" 2>> "${error_log}"; then
                record_diag_error "${error_log}" "pstack failed for pid=${pid}"
            fi
        fi

        if command -v strace >/dev/null 2>&1; then
            strace -tt -f -p "${pid}" -o "${output_prefix}.strace.txt" >> "${error_log}" 2>&1 &
            local strace_pid="$!"
            sleep "${STRACE_SECS}"
            terminate_pid_bounded "${strace_pid}" "strace" "${error_log}" || true
        fi
    fi
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
    local error_log="${base}.errors.log"
    local stripped_cmd=""
    local suspected_binary=""
    local -a suspected_pre_args=()
    local -a repro_command=()
    local repro_cmd=""
    local repro_pid=""
    local remaining=""
    local exit_code=""

    stripped_cmd="$(printf '%s\n' "${stalled_cmd}" \
        | sed -E 's/[[:space:]]+--list[[:space:]]+--format[[:space:]]+terse.*$//' \
        | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
    if [ -n "${stripped_cmd}" ]; then
        # shellcheck disable=SC2206
        local -a parts=(${stripped_cmd})
        suspected_binary="${parts[0]}"
        if [ "${#parts[@]}" -gt 1 ]; then
            suspected_pre_args=("${parts[@]:1}")
        fi

        repro_command=("${suspected_binary}")
        if [ "${#suspected_pre_args[@]}" -gt 0 ]; then
            repro_command+=("${suspected_pre_args[@]}")
        fi
        repro_command+=(--list --format terse)

        printf -v repro_cmd '%q' "${repro_command[0]}"
        if [ "${#repro_command[@]}" -gt 1 ]; then
            local i
            for ((i = 1; i < ${#repro_command[@]}; i++)); do
                printf -v repro_cmd '%s %q' "${repro_cmd}" "${repro_command[i]}"
            done
        fi
    fi
    if [ -n "${repro_cmd}" ]; then
        echo "repro command: ${repro_cmd}" >&2
    else
        echo "repro command: unavailable (could not parse stalled child command)" >&2
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
        if ! ps -p "${stalled_pid}" -o pid=,ppid=,etime=,command=; then
            echo "ps_failed_for_stalled_pid=true"
        fi
        echo
        echo "nextest process:"
        if ! ps -p "${nextest_pid}" -o pid=,ppid=,etime=,command=; then
            echo "ps_failed_for_nextest_pid=true"
        fi
        echo
        echo "related process snapshot:"
        if ! ps -Ao pid=,ppid=,etime=,command= 2>/dev/null | rg "cargo-nextest|--list --format terse|target/debug/deps/"; then
            echo "no_related_processes_matched_snapshot_pattern"
        fi
    } >"${log_file}"

    capture_process_artifacts "${stalled_pid}" "${base}"

    if [ -n "${suspected_binary}" ]; then
        {
            echo "#!/usr/bin/env bash"
            echo "set -euo pipefail"
            printf 'cd %q\n' "$(pwd)"
            printf '%s\n' "${repro_cmd}"
        } > "${repro_script}"
        chmod +x "${repro_script}"

        if [ -x "${suspected_binary}" ]; then
            set +e
            "${repro_command[@]}" > "${repro_log}" 2>&1 &
            local repro_pid
            local remaining
            local exit_code
            repro_pid=$!
            remaining="${REPRO_TIMEOUT_SECS}"
            while [ "${remaining}" -gt 0 ]; do
                if ! process_is_running "${repro_pid}"; then
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

            if [ "${remaining}" -eq 0 ] && process_is_running "${repro_pid}"; then
                {
                    echo
                    echo "repro_status=timed_out"
                    echo "repro_timeout_secs=${REPRO_TIMEOUT_SECS}"
                } >> "${repro_log}"
                capture_process_artifacts "${repro_pid}" "${base}.repro"
                terminate_pid_bounded "${repro_pid}" "repro process" "${error_log}" || true
            fi
            set -e
        else
            echo "repro_status=skipped_non_executable_binary" > "${repro_log}"
        fi
    fi

    echo "nextest discovery stall detected; diagnostics written to ${log_file}" >&2
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
        terminate_pid_bounded "${pid}" "stalled list child" "${DIAG_DIR}/nextest-kill.errors.log" || true
        terminate_pid_bounded "${nextest_pid}" "nextest parent" "${DIAG_DIR}/nextest-kill.errors.log" || true
        exit 124
    done < <(list_discovery_pid_etime_and_command "${nextest_pid}")

    sleep "${POLL_SECS}"
done

wait "${nextest_pid}"
