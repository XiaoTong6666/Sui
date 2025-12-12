#!/sbin/sh
MODDIR=${0%/*}
MODULES=$(dirname "$MODDIR")

cleanup_standalone() {
  PID_FILE="/data/adb/sui/sui_daemon.pid"
  MONITOR_PID_FILE="/data/adb/sui/sui_monitor.pid"

  if [ -f "$MONITOR_PID_FILE" ]; then
    kill -9 $(cat "$MONITOR_PID_FILE")
    rm "$MONITOR_PID_FILE"
  fi

  if [ -f "$PID_FILE" ]; then
    kill -9 $(cat "$PID_FILE")
    rm "$PID_FILE"
  fi
}

uninstall() {
  cleanup_standalone
  chmod 700 "$MODDIR"/bin/uninstall
  "$MODDIR"/bin/uninstall "$MODDIR"
  rm -rf "/data/adb/sui"
}

if [ -d "$MODULES/zygisk_sui" ]; then
  if [ -f "$MODULES/zygisk_sui/remove" ]; then
    uninstall
  fi
else
  uninstall
fi
