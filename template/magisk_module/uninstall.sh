#!/sbin/sh
MODDIR=${0%/*}
MODULES=$(dirname "$MODDIR")
. "$MODDIR/logging.sh"

uninstall() {
  chmod 700 "$MODDIR"/bin/uninstall
  "$MODDIR"/bin/uninstall "$MODDIR"
  rm -rf /data/local/tmp/sui_shell
  rm -rf /data/local/tmp/sui_shell_*
  rm -rf /data/system/sui
  stop_sui_log_collector
  rm -rf "/data/adb/sui"
}

if [ -d "$MODULES/zygisk_sui" ]; then
  if [ -f "$MODULES/zygisk_sui/remove" ]; then
    uninstall
  fi
else
  uninstall
fi
