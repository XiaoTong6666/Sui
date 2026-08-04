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

get_sui_pids() {
    if command -v pidof >/dev/null 2>&1; then
        pidof sui 2>/dev/null
        return
    fi

    ps -A 2>/dev/null | awk '$NF == "sui" { print $2 }'
}

is_sui_running() {
    [ -n "$(get_sui_pids)" ]
}

refresh_metadata() {
    print_log "Refreshing SystemUI and Settings package metadata..."
    if ! /system/bin/app_process -Djava.class.path="$MODDIR"/sui.dex /system/bin \
        --nice-name=sui_installer rikka.sui.installer.Installer "$MODDIR" >> "$LOG_FILE" 2>&1; then
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
    if ! refresh_metadata; then
        print_log "Retrying Sui startup later"
        return 1
    fi

    chmod 700 "$MODDIR/bin/sui" 2>/dev/null
    nohup "$MODDIR/bin/sui" "$MODDIR" 0 >> "$LOG_FILE" 2>&1 &
}

refresh_metadata

LOCK_DIR="/data/adb/sui/watchdog.lock"
LOCK_PID="$LOCK_DIR/pid"

(
    mkdir -p "/data/adb/sui" 2>/dev/null

    if mkdir "$LOCK_DIR" 2>/dev/null; then
        echo "$$" > "$LOCK_PID" 2>/dev/null
    else
        if [ -f "$LOCK_PID" ]; then
            old_pid="$(cat "$LOCK_PID" 2>/dev/null)"
            if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
                exit 0
            fi
        fi
        rm -rf "$LOCK_DIR" 2>/dev/null
        mkdir "$LOCK_DIR" 2>/dev/null && echo "$$" > "$LOCK_PID" 2>/dev/null
    fi

    backoff=1
    backoff_max=60
    interval=5

    while true; do
        if is_sui_running; then
            backoff=1
            sleep "$interval"
            continue
        fi

        print_log "Sui daemon is not running, restarting..."
        start_sui
        sleep 2

        if is_sui_running; then
            pids="$(get_sui_pids)"
            print_log "Sui daemon is running (pid: $pids)"
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
) >/dev/null 2>&1 &

exit 0
