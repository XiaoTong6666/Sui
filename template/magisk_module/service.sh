#!/system/bin/sh

MODDIR=${0%/*}

SUI_DIR="/data/adb/sui"
LOG_FILE="$SUI_DIR/sui.log"
TAG="SuiDaemon"

mkdir -p "$SUI_DIR" 2>/dev/null

rotate_log_file() {
    max_size=1048576

    if [ ! -f "$LOG_FILE" ]; then
        return
    fi

    log_size=$(wc -c < "$LOG_FILE" 2>/dev/null)
    if [ -n "$log_size" ] && [ "$log_size" -gt "$max_size" ]; then
        rm -f "$LOG_FILE.1" 2>/dev/null
        mv "$LOG_FILE" "$LOG_FILE.1" 2>/dev/null
    fi
}

print_log() {
    rotate_log_file
    echo "[$(date)] $1" >> "$LOG_FILE"
    log -p i -t "$TAG" "$1"
}

get_sui_root_pids() {
    if command -v pidof >/dev/null 2>&1; then
        pidof sui 2>/dev/null
        return
    fi

    ps -A 2>/dev/null | awk '$NF == "sui" { print $2 }'
}

get_sui_shell_pids() {
    if command -v pidof >/dev/null 2>&1; then
        pidof sui_shell 2>/dev/null
        return
    fi

    ps -A 2>/dev/null | awk '$NF == "sui_shell" { print $2 }'
}

count_pids() {
    pids="$1"
    if [ -z "$pids" ]; then
        echo 0
        return
    fi
    set -- $pids
    echo $#
}

collect_sui_state() {
    sui_root_pids="$(get_sui_root_pids)"
    sui_shell_pids="$(get_sui_shell_pids)"
    sui_root_count="$(count_pids "$sui_root_pids")"
    sui_shell_count="$(count_pids "$sui_shell_pids")"
}

is_sui_pair_healthy() {
    collect_sui_state
    [ "$sui_root_count" -eq 1 ] && [ "$sui_shell_count" -eq 1 ]
}

kill_pid_list() {
    pids="$1"
    signal="$2"

    if [ -z "$pids" ]; then
        return 0
    fi

    # shellcheck disable=SC2086
    kill "$signal" $pids 2>/dev/null
}

stop_sui_pair() {
    collect_sui_state

    kill_pid_list "$sui_shell_pids" -TERM
    kill_pid_list "$sui_root_pids" -TERM
    sleep 1

    collect_sui_state
    kill_pid_list "$sui_shell_pids" -KILL
    kill_pid_list "$sui_root_pids" -KILL
    sleep 1
}

read_metadata() {
    [ -f "$1" ] && cat "$1" 2>/dev/null
}

get_process_pids() {
    if command -v pidof >/dev/null 2>&1; then
        pidof "$1" 2>/dev/null
        return
    fi

    ps -A 2>/dev/null | awk -v process="$1" '$NF == process { print $2 }'
}

metadata_field() {
    printf '%s\n' "$1" | awk -v line="$2" 'NR == line { print; exit }'
}

get_pid_uid() {
    awk '/^Uid:/ { print $2; exit }' "/proc/$1/status" 2>/dev/null
}

get_pid_start_time() {
    awk '{ print $22 }' "/proc/$1/stat" 2>/dev/null
}

get_pid_process_name() {
    tr '\000' '\n' < "/proc/$1/cmdline" 2>/dev/null | awk 'NR == 1 { print; exit }'
}

kill_process_identity_once() {
    expected_uid="$1"
    process_name="$2"
    killed=0

    for pid in $(get_process_pids "$process_name"); do
        start_time="$(get_pid_start_time "$pid")"
        if [ -z "$start_time" ]; then
            continue
        fi
        if [ "$(get_pid_uid "$pid")" != "$expected_uid" ]; then
            continue
        fi
        if [ "$(get_pid_process_name "$pid")" != "$process_name" ]; then
            continue
        fi
        if [ "$(get_pid_start_time "$pid")" != "$start_time" ]; then
            continue
        fi
        print_log "Package metadata changed, restarting $process_name (uid: $expected_uid, pid: $pid)"
        if kill -9 "$pid" 2>/dev/null; then
            killed=1
        fi
    done

    [ "$killed" -eq 1 ]
}

restart_metadata_process() {
    metadata="$1"
    wait_attempts="$2"
    expected_uid="$(metadata_field "$metadata" 2)"
    process_name="$(metadata_field "$metadata" 3)"

    case "$expected_uid" in
        ""|*[!0-9]*) return ;;
    esac
    case "$process_name" in
        ""|init|system_server|zygote*) return ;;
    esac

    attempt=0
    while true; do
        if kill_process_identity_once "$expected_uid" "$process_name"; then
            return
        fi
        if [ "$attempt" -ge "$wait_attempts" ]; then
            return
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
}

restart_changed_metadata_processes() {
    old_metadata="$1"
    new_metadata="$2"
    old_identity="$(metadata_field "$old_metadata" 2):$(metadata_field "$old_metadata" 3)"
    new_identity="$(metadata_field "$new_metadata" 2):$(metadata_field "$new_metadata" 3)"

    if [ "$old_identity" != "$new_identity" ]; then
        restart_metadata_process "$old_metadata" 0
    fi
    restart_metadata_process "$new_metadata" 10
}

refresh_metadata() {
    old_system_ui="$(read_metadata "$MODDIR/system_ui")"
    old_settings="$(read_metadata "$MODDIR/settings")"

    print_log "Refreshing SystemUI and Settings package metadata..."
    refresh_status=0
    /system/bin/app_process -Djava.class.path="$MODDIR"/sui.dex /system/bin \
        --nice-name=sui_installer rikka.sui.installer.Installer "$MODDIR" \
        9>&- >> "$LOG_FILE" 2>&1 || refresh_status=$?

    new_system_ui="$(read_metadata "$MODDIR/system_ui")"
    new_settings="$(read_metadata "$MODDIR/settings")"
    if [ "$old_system_ui" != "$new_system_ui" ]; then
        restart_changed_metadata_processes "$old_system_ui" "$new_system_ui"
    fi
    if [ "$old_settings" != "$new_settings" ]; then
        restart_changed_metadata_processes "$old_settings" "$new_settings"
    fi

    if [ "$refresh_status" -ne 0 ]; then
        print_log "Package metadata refresh failed"
        return 1
    fi
    if [ ! -s "$MODDIR/system_ui" ] || [ ! -s "$MODDIR/settings" ]; then
        print_log "Package metadata is unavailable"
        return 1
    fi
    return 0
}

start_sui() {
    chmod 700 "$MODDIR/bin/sui" 2>/dev/null
    nohup "$MODDIR/bin/sui" "$MODDIR" 0 9>&- >> "$LOG_FILE" 2>&1 &
}

LOCK_FILE="$SUI_DIR/watchdog.lock.v2"
if ! exec 9>> "$LOCK_FILE"; then
    exit 1
fi
if command -v flock >/dev/null 2>&1; then
    if ! flock -n 9 2>/dev/null; then
        exit 0
    fi
elif [ -x /system/bin/toybox ]; then
    if /system/bin/toybox flock --help >/dev/null 2>&1; then
        if ! /system/bin/toybox flock -n 9 2>/dev/null; then
            exit 0
        fi
    else
        FALLBACK_LOCK_DIR="/dev/.sui-watchdog.lock"
        if ! mkdir "$FALLBACK_LOCK_DIR" 2>/dev/null; then
            exit 0
        fi
        trap 'rmdir "$FALLBACK_LOCK_DIR" 2>/dev/null' EXIT
    fi
else
    FALLBACK_LOCK_DIR="/dev/.sui-watchdog.lock"
    if ! mkdir "$FALLBACK_LOCK_DIR" 2>/dev/null; then
        exit 0
    fi
    trap 'rmdir "$FALLBACK_LOCK_DIR" 2>/dev/null' EXIT
fi
trap 'exit 0' INT TERM

metadata_ready=0
if refresh_metadata; then
    metadata_ready=1
fi

backoff=1
backoff_max=60
interval=5

while true; do
    if is_sui_pair_healthy; then
        if [ "$metadata_ready" -eq 0 ] && refresh_metadata; then
            metadata_ready=1
        fi
        backoff=1
        sleep "$interval"
        continue
    fi

    case "$sui_root_count:$sui_shell_count" in
        0:0) print_log "Sui root and shell servers are not running, restarting..." ;;
        0:*) print_log "Sui root server is not running, restarting pair..." ;;
        *:0) print_log "Sui shell server is not running, restarting pair..." ;;
        *) print_log "Sui process pair is inconsistent (root=$sui_root_pids shell=$sui_shell_pids), restarting..." ;;
    esac
    stop_sui_pair
    if [ "$metadata_ready" -eq 1 ] || refresh_metadata; then
        metadata_ready=1
        start_sui
    else
        print_log "Retrying metadata refresh later"
    fi
    sleep 2

    if is_sui_pair_healthy; then
        print_log "Sui process pair is running (root=$sui_root_pids shell=$sui_shell_pids)"
        backoff=1
        sleep "$interval"
        continue
    fi

    print_log "Sui daemon still not running, retry in ${backoff}s"
    sleep "$backoff"
    if [ "$backoff" -lt "$backoff_max" ]; then
        backoff=$((backoff * 2))
        if [ "$backoff" -gt "$backoff_max" ]; then
            backoff="$backoff_max"
        fi
    fi
done
