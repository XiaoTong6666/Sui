#!/system/bin/sh
MODDIR=${0%/*}
MODULE_ID=$(basename "$MODDIR")

SUI_WORK_DIR="/data/system/sui"
API_LEVEL=$(getprop ro.build.version.sdk)
. "$MODDIR/logging.sh"

start_sui_log_collector

fix_oat_permissions_until_ready() {
    attempts=0
    max_attempts=180
    settle_rounds=0
    sleep_interval=1

    while [ "$attempts" -lt "$max_attempts" ]; do
        if [ -d "$SUI_WORK_DIR/oat" ]; then
            chmod -R a+rX "$SUI_WORK_DIR/oat" 2>/dev/null
            if find "$SUI_WORK_DIR/oat" -type f 2>/dev/null | read -r _; then
                settle_rounds=$((settle_rounds + 1))
                if [ "$settle_rounds" -ge 5 ]; then
                    break
                fi
            fi
        fi

        attempts=$((attempts + 1))
        if [ "$attempts" -ge 30 ]; then
            sleep_interval=5
        fi
        sleep "$sleep_interval"
    done
}

if [ "$API_LEVEL" -lt 26 ] && [ -d "$SUI_WORK_DIR" ]; then
    rm -rf "$SUI_WORK_DIR"
fi

if [ "$API_LEVEL" -le 27 ]; then
    mkdir -p "$SUI_WORK_DIR/oat"
    chown -R 1000:1000 "$SUI_WORK_DIR"
    chmod 771 "$SUI_WORK_DIR"
    chmod 777 "$SUI_WORK_DIR/oat"
fi

if [ "$API_LEVEL" -lt 26 ]; then
    rm -f "$SUI_WORK_DIR/sui.dex"
    cp "$MODDIR/sui.apk" "$SUI_WORK_DIR/sui.apk"
    chmod 644 "$SUI_WORK_DIR/sui.apk"

    if [ "$API_LEVEL" -le 23 ]; then
        fix_oat_permissions_until_ready &
    fi

    restorecon -R "$SUI_WORK_DIR"
    chcon -R u:object_r:system_data_file:s0 "$SUI_WORK_DIR"

elif [ "$API_LEVEL" -le 27 ]; then
    cp "$MODDIR/sui.dex" "$SUI_WORK_DIR/sui.dex"
    chmod 644 "$SUI_WORK_DIR/sui.dex"
    cp "$MODDIR/sui.apk" "$SUI_WORK_DIR/sui.apk"
    chmod 644 "$SUI_WORK_DIR/sui.apk"
    chcon -R u:object_r:system_file:s0 "$SUI_WORK_DIR"
fi

if [ "$ZYGISK_ENABLED" = false ]; then
  log -p w -t "Sui" "Zygisk is disabled"
  exit 1
fi

if [ "$KSU" = true ]; then
  log -p i -t "Sui" "KernelSU ksud version $KSU_VER ($KSU_VER_CODE)"
  log -p i -t "Sui" "KernelSU kernel version $KSU_KERNEL_VER_CODE"
  apply_sepolicy() {
    ksud sepolicy apply "$1"
  }
elif [  "$KERNELPATCH" = true  ]; then
  kp_major_char=${KERNELPATCH_VERSION:0:1}
  kp_minor_patch=${KERNELPATCH_VERSION:1}

  kp_major=$(( $(printf '%d' "'$kp_major_char") - 97 ))
  kp_minor=$(( 10 + ${kp_minor_patch:0:1} ))
  kp_patch=${kp_minor_patch:1}

  log -p i -t "Sui" "APatch version $APATCH_VER ($APATCH_VER_CODE)"
  log -p i -t "Sui" "KernelPatch version $kp_major.$kp_minor.$kp_patch"
  apply_sepolicy() {
    apd sepolicy apply "$1"
  }
else
  MAGISK_VER_CODE=$(magisk -V 2>/dev/null)

  log -p i -t "Sui" "Magisk version $MAGISK_VER_CODE"
  apply_sepolicy() {
    magiskpolicy --live --apply "$1" 2>/dev/null
  }
fi

log -p i -t "Sui" "Module path $MODDIR"

enable_once="/data/adb/sui/enable_adb_root_once"
enable_forever="/data/adb/sui/enable_adb_root"
adb_root_exit=0

if [ -f $enable_once ]; then
  log -p i -t "Sui" "adb root support is enabled for this time of boot"
  rm $enable_once
  enable_adb_root=true
fi

if [ -f $enable_forever ]; then
  log -p i -t "Sui" "adb root support is enabled forever"
  enable_adb_root=true
fi

if [ "$enable_adb_root" = true ]; then
  log -p i -t "Sui" "Setup adb root support"

  # Make sure sepolicy.rule be loaded
  chmod 755 "$MODDIR/sepolicy_checker"
  if ! "$MODDIR/sepolicy_checker"; then
    log -p e -t "Sui" "RootImpl does not load sepolicy.rule..."
    log -p e -t "Sui" "Try to load it..."
    apply_sepolicy "$MODDIR"/sepolicy.rule
    log -p i -t "Sui" "Apply finished"
  else
    log -p i -t "Sui" "RootImpl should have loaded sepolicy.rule correctly"
  fi

  # Setup adb root support
  rm "$MODDIR/bin/adb_root"
  ln -s "$MODDIR/bin/sui" "$MODDIR/bin/adb_root"
  chmod 700 "$MODDIR/bin/adb_root"
  "$MODDIR/bin/adb_root" "$MODDIR"
  adb_root_exit=$?
  log -p i -t "Sui" "Exited with $adb_root_exit"
else
  log -p i -t "Sui" "adb root support is disabled"
fi

# Setup uninstaller
rm "$MODDIR/bin/uninstall"
ln -s "$MODDIR/bin/sui" "$MODDIR/bin/uninstall"

# Run Sui server
chmod 700 "$MODDIR"/bin/sui

# define print_log
print_log() {
    log -p i -t "SuiDaemon" "$1"
}


print_log "Starting Sui native daemon..."

# strat the sui daemon
nohup "$MODDIR"/bin/sui "$MODDIR" "$adb_root_exit" 2>&1 | pipe_sui_output_to_logcat &

print_log "Sui daemon launched"

exit 0
