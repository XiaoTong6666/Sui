#!/sbin/sh
MODDIR=${0%/*}
MODULES=$(dirname "$MODDIR")

uninstall() {
  "$MODDIR/bin/sui_supervisor" "$MODDIR" --stop || exit 1
  "$MODDIR/bin/sui_supervisor" "$MODDIR" --prune-legacy-all 2>/dev/null || :
  chmod 700 "$MODDIR"/bin/uninstall
  "$MODDIR"/bin/uninstall "$MODDIR"
  rm -rf /data/local/tmp/sui_shell
  rm -rf /data/local/tmp/sui_shell_*
  rm -rf "/data/adb/sui"
}

if [ -d "$MODULES/zygisk_sui" ]; then
  if [ -f "$MODULES/zygisk_sui/remove" ]; then
    uninstall
  fi
else
  uninstall
fi
