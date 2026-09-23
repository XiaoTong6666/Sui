#!/system/bin/sh

SUI_LOG_DIR="/data/adb/sui"
SUI_LOG_FILE="$SUI_LOG_DIR/sui.log"
SUI_LOGCAT_PID_FILE="$SUI_LOG_DIR/logcat.pid"
SUI_LOGCAT_START_LOCK="/dev/.sui-logcat-start.lock"

# Keep this list in sync with logging tags used by Sui, the bundled UI, and
# server-shared. logcat is the only process that writes SUI_LOG_FILE.
SUI_LOGCAT_FILTERS="
Sui:V
SuiDaemon:V
SuiServer:V
SuiSystemServer:V
SuiManager:V
SuiSettings:V
SuiShortcut:V
SuiApk:V
SuiInstaller:V
SuiUninstaller:V
SuiUserServiceStarter:V
SuiConfirmationDialog:V
SuiSystemDialogRootView:V
SuiBridgeDebug:V
SuiViewModel:V
SuiShortcutRPC:V
Service:V
ClientRecord:V
UserServiceManager:V
UserServiceRecord:V
ConfigManager:V
ConfigPackageEntry:V
RemoteProcessHolder:V
TransferThread:V
SQLiteDataBaseRemoteCompat:V
AppLabelCache:V
AppIconCache:V
LayoutInflaterKt:V
TextUtilsCompat:V
*:S
"

sui_log_collector_running() {
    [ -r "$SUI_LOGCAT_PID_FILE" ] || return 1
    logcat_pid="$(cat "$SUI_LOGCAT_PID_FILE" 2>/dev/null)"
    case "$logcat_pid" in
        ''|*[!0-9]*) return 1 ;;
    esac
    kill -0 "$logcat_pid" 2>/dev/null || return 1
    [ -r "/proc/$logcat_pid/cmdline" ] || return 1
    grep -qF "logcat" "/proc/$logcat_pid/cmdline" 2>/dev/null || return 1
    grep -qF "$SUI_LOG_FILE" "/proc/$logcat_pid/cmdline" 2>/dev/null
}

start_sui_log_collector() {
    mkdir -p "$SUI_LOG_DIR" 2>/dev/null

    if sui_log_collector_running; then
        return 0
    fi

    if ! mkdir "$SUI_LOGCAT_START_LOCK" 2>/dev/null; then
        return 0
    fi

    if sui_log_collector_running; then
        rmdir "$SUI_LOGCAT_START_LOCK" 2>/dev/null
        return 0
    fi

    rm -f "$SUI_LOGCAT_PID_FILE" 2>/dev/null

    # Android logcat opens -f output with O_APPEND. Keeping one collector as
    # the sole writer avoids inter-process FileHandler and shell append races.
    # -T 1 resumes from the tail if the collector needs to be restarted.
    # shellcheck disable=SC2086
    /system/bin/logcat -b all -v threadtime -T 1 -f "$SUI_LOG_FILE" -r 1024 -n 1 $SUI_LOGCAT_FILTERS >/dev/null 2>&1 &
    logcat_pid=$!
    echo "$logcat_pid" > "$SUI_LOGCAT_PID_FILE"
    chmod 0600 "$SUI_LOGCAT_PID_FILE" 2>/dev/null

    rmdir "$SUI_LOGCAT_START_LOCK" 2>/dev/null
    return 0
}

ensure_sui_log_collector() {
    if ! sui_log_collector_running; then
        start_sui_log_collector
    fi
}

pipe_sui_output_to_logcat() {
    while IFS= read -r line || [ -n "$line" ]; do
        log -p i -t "Sui" "$line"
    done
}

run_sui_logged_command() {
    log_tag="$1"
    shift
    output_file="$SUI_LOG_DIR/command-output.$$"
    rm -f "$output_file" 2>/dev/null

    "$@" >"$output_file" 2>&1
    command_status=$?

    cat "$output_file"
    while IFS= read -r line || [ -n "$line" ]; do
        log -p i -t "$log_tag" "$line"
    done < "$output_file"
    rm -f "$output_file"
    return "$command_status"
}

stop_sui_log_collector() {
    if sui_log_collector_running; then
        kill "$logcat_pid" 2>/dev/null
        sleep 1
    fi
    rm -f "$SUI_LOGCAT_PID_FILE" 2>/dev/null
    rmdir "$SUI_LOGCAT_START_LOCK" 2>/dev/null
}
