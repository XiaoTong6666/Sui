#!/system/bin/sh
MODDIR=${0%/*}
exec "$MODDIR/bin/sui_supervisor" "$MODDIR"
