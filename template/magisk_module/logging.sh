#!/system/bin/sh

SUI_LOG_DIR="/data/adb/sui"

cleanup_sui_legacy_log_files() {
    [ -d "$SUI_LOG_DIR" ] || return 0
    rm -f "$SUI_LOG_DIR"/command-output.* "$SUI_LOG_DIR"/command-error.* 2>/dev/null || :
}

sui_legacy_logcat_running() {
    [ -r "$SUI_LOG_DIR/logcat.pid" ] || return 1
    read -r old_pid _ < "$SUI_LOG_DIR/logcat.pid" || return 1
    case "$old_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$old_pid" 2>/dev/null || return 1
    grep -qF '/data/adb/sui/sui.log' "/proc/$old_pid/cmdline" 2>/dev/null || return 1
    grep -qF '/system/bin/logcat' "/proc/$old_pid/cmdline" 2>/dev/null
}

sui_previous_native_collector_running() {
    [ -r "$SUI_LOG_DIR/logcat.pid" ] || return 1
    read -r old_pid _ < "$SUI_LOG_DIR/logcat.pid" || return 1
    case "$old_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$old_pid" 2>/dev/null || return 1
    [ "$(cat "/proc/$old_pid/comm" 2>/dev/null)" = sui_logcat ] || return 1
    grep -qF "$SUI_LOG_DIR" "/proc/$old_pid/cmdline" 2>/dev/null
}

start_sui_log_collector() {
    [ -x "$MODDIR/bin/sui_logcat" ] || return 1
    "$MODDIR/bin/sui_logcat" status "$SUI_LOG_DIR" >/dev/null 2>&1 && return 0
    sui_legacy_logcat_running && return 0
    sui_previous_native_collector_running && return 0
    nohup "$MODDIR/bin/sui_logcat" run "$SUI_LOG_DIR" </dev/null >/dev/null 2>&1 9>&- &
}

stop_sui_log_collector() {
    if sui_legacy_logcat_running; then
        read -r old_pid _ < "$SUI_LOG_DIR/logcat.pid"
        kill "$old_pid" 2>/dev/null || :
    fi
    [ -x "$MODDIR/bin/sui_logcat" ] || return 0
    "$MODDIR/bin/sui_logcat" stop "$SUI_LOG_DIR" >/dev/null 2>&1
}

start_sui_logged_daemon() {
    if [ ! -x "$MODDIR/bin/sui" ]; then
        log -p e -t Sui "[Daemon] Sui executable is missing or not executable"
        return 1
    fi
    nohup "$MODDIR/bin/sui" "$MODDIR" "$1" </dev/null >/dev/null 2>&1 9>&- &
}

run_sui_installer_command() {
    output_file="$SUI_LOG_DIR/command-output.$$"
    error_file="$SUI_LOG_DIR/command-error.$$"
    rm -f "$output_file" "$error_file" 2>/dev/null

    "$@" >"$output_file" 2>"$error_file" 9>&-
    command_status=$?
    cat "$output_file"
    if [ "$command_status" -ne 0 ]; then
        cat "$error_file" >&2
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        log -p i -t Sui -- "[Installer] $line"
    done < "$output_file"
    while IFS= read -r line || [ -n "$line" ]; do
        log -p e -t Sui -- "[Installer] $line"
    done < "$error_file"
    rm -f "$output_file" "$error_file"
    return "$command_status"
}
