#!/system/bin/sh
MODDIR=${0%/*}

SUI_WORK_DIR="/data/system/sui"
API_LEVEL=$(getprop ro.build.version.sdk)
. "$MODDIR/logging.sh"

boot_log() {
    log -p "$1" -t Sui "[Boot] $2"
}

cleanup_sui_legacy_log_files
chmod 700 "$MODDIR/bin/sui" 2>/dev/null
start_sui_log_collector

fix_oat_permissions_until_ready() {
    attempts=0
    max_attempts=180
    settle_rounds=0
    sleep_interval=1

    while [ "$attempts" -lt "$max_attempts" ]; do
        if [ -d "$SUI_WORK_DIR/oat" ]; then
            chmod -R u+rX,go-rwx "$SUI_WORK_DIR/oat" 2>/dev/null
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
    if ! rm -rf "$SUI_WORK_DIR"; then
        boot_log w "Cannot clear legacy DEX directory $SUI_WORK_DIR"
    fi
fi

if [ "$API_LEVEL" -le 27 ]; then
    if ! mkdir -p "$SUI_WORK_DIR/oat" ||
       ! chown -R 1000:1000 "$SUI_WORK_DIR" ||
       ! chmod -R go-rwx "$SUI_WORK_DIR/oat" ||
       ! chmod 751 "$SUI_WORK_DIR" ||
       ! chmod 700 "$SUI_WORK_DIR/oat"; then
        boot_log e "Cannot prepare legacy DEX directory $SUI_WORK_DIR"
    fi
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
  boot_log w "Zygisk is disabled"
  exit 1
fi

if [ "$KSU" = true ]; then
  boot_log i "KernelSU ksud version $KSU_VER ($KSU_VER_CODE)"
  boot_log i "KernelSU kernel version $KSU_KERNEL_VER_CODE"
  apply_sepolicy() {
    ksud sepolicy apply "$1"
  }
elif [  "$KERNELPATCH" = true  ]; then
  kp_major_char=${KERNELPATCH_VERSION:0:1}
  kp_minor_patch=${KERNELPATCH_VERSION:1}

  kp_major=$(( $(printf '%d' "'$kp_major_char") - 97 ))
  kp_minor=$(( 10 + ${kp_minor_patch:0:1} ))
  kp_patch=${kp_minor_patch:1}

  boot_log i "APatch version $APATCH_VER ($APATCH_VER_CODE)"
  boot_log i "KernelPatch version $kp_major.$kp_minor.$kp_patch"
  apply_sepolicy() {
    apd sepolicy apply "$1"
  }
else
  MAGISK_VER_CODE=$(magisk -V 2>/dev/null)

  boot_log i "Magisk version $MAGISK_VER_CODE"
  apply_sepolicy() {
    magiskpolicy --live --apply "$1" 2>/dev/null
  }
fi

boot_log i "Module path $MODDIR"

enable_once="/data/adb/sui/enable_adb_root_once"
enable_forever="/data/adb/sui/enable_adb_root"
inject_opt_in="/data/adb/sui/enable_adb_root_injection"
inject_prepared="/data/adb/sui/adbd_inject_prepared"
adb_root_exit=0
rm -f "$inject_prepared"

if [ -f $enable_once ]; then
  boot_log i "adb root support is enabled for this time of boot"
  rm $enable_once
  enable_adb_root=true
fi

if [ -f $enable_forever ]; then
  boot_log i "adb root support is enabled forever"
  enable_adb_root=true
fi

if [ "$enable_adb_root" = true ]; then
  boot_log i "Setup adb root support"

  chmod 755 "$MODDIR/sepolicy_checker"
  if ! "$MODDIR/sepolicy_checker"; then
    boot_log e "RootImpl does not load sepolicy.rule..."
    boot_log e "Try to load it..."
    apply_sepolicy "$MODDIR"/sepolicy.rule
    boot_log i "Apply finished"
  else
    boot_log i "RootImpl should have loaded sepolicy.rule correctly"
  fi

  rm "$MODDIR/bin/adb_root"
  ln -s "$MODDIR/bin/sui" "$MODDIR/bin/adb_root"
  chmod 700 "$MODDIR/bin/adb_root"
  if [ -f "$inject_opt_in" ]; then
    if [ -f "$MODDIR/lib/libadbd_inject.so" ]; then
      boot_log i "ADB Root backend: ZN injection"
      "$MODDIR/bin/adb_root" "$MODDIR" --inject
      adb_root_exit=$?
    else
      boot_log e "ZN injection selected, but libadbd_inject.so is missing"
      adb_root_exit=1
    fi
  else
    boot_log i "ADB Root backend: Bind Mount"
    "$MODDIR/bin/adb_root" "$MODDIR"
    adb_root_exit=$?
  fi
  boot_log i "Exited with $adb_root_exit"
else
  boot_log i "adb root support is disabled"
fi

rm "$MODDIR/bin/uninstall"
ln -s "$MODDIR/bin/sui" "$MODDIR/bin/uninstall"

log -p i -t Sui "[Daemon] Starting Sui native daemon..."

start_sui_logged_daemon "$adb_root_exit"

log -p i -t Sui "[Daemon] Sui daemon launched"

exit 0
