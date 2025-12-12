#!/system/bin/sh
MODDIR=${0%/*}
MODULE_ID=$(basename "$MODDIR")

# @isStandalone@ 会在打包时被 Gradle 替换为 "true" 或 "false"
IS_STANDALONE="@isStandalone@"

log -p i -t "Sui" "Starting post-fs-data. Standalone Mode: $IS_STANDALONE"

# ==========================================
# 0. 环境检测与 SEPolicy 预备函数
# ==========================================
if [ "$KSU" = true ]; then
  log -p i -t "Sui" "KernelSU ksud version $KSU_VER ($KSU_VER_CODE)"
  apply_sepolicy() { ksud sepolicy apply "$1"; }
elif [ "$KERNELPATCH" = true ]; then
  log -p i -t "Sui" "APatch/KernelPatch detected"
  apply_sepolicy() { apd sepolicy apply "$1"; }
else
  log -p i -t "Sui" "Magisk detected"
  apply_sepolicy() { magiskpolicy --live --apply "$1"; }
fi

# 尽早加载 SEPolicy
if [ -f "$MODDIR/sepolicy.rule" ]; then
    apply_sepolicy "$MODDIR/sepolicy.rule"
fi

# ==========================================
# 1. 独立模式 (Standalone) 启动逻辑
# ==========================================
if [ "$IS_STANDALONE" = "true" ]; then
    # 架构检测，获取正确的 ABI 和 lib 目录
    ABI32="armeabi-v7a"
    ABI64="arm64-v8a"
    ABI=$(getprop ro.product.cpu.abi)
    case "$ABI" in
        arm64-v8a)
            LIB_DIR="$MODDIR/lib/$ABI64"
            DAEMON_PATH="$MODDIR/standalone_bin/$ABI64/sui_daemon"
            LOADER_DIR="$MODDIR/standalone_bin/$ABI64"
            ;;
        x86_64)
            ABI32="x86" # x86_64 设备通常也支持 32 位 x86
            LIB_DIR="$MODDIR/lib/$ABI"
            DAEMON_PATH="$MODDIR/standalone_bin/$ABI/sui_daemon"
            LOADER_DIR="$MODDIR/standalone_bin/$ABI"
            ;;
        armeabi*) # armeabi-v7a, armeabi
            LIB_DIR="$MODDIR/lib/$ABI32"
            DAEMON_PATH="$MODDIR/standalone_bin/$ABI32/sui_daemon"
            LOADER_DIR="$MODDIR/standalone_bin/$ABI32"
            ;;
        x86)
            LIB_DIR="$MODDIR/lib/$ABI"
            DAEMON_PATH="$MODDIR/standalone_bin/$ABI/sui_daemon"
            LOADER_DIR="$MODDIR/standalone_bin/$ABI"
            ;;
        *)
            # 默认回落到 arm64
            LIB_DIR="$MODDIR/lib/$ABI64"
            DAEMON_PATH="$MODDIR/standalone_bin/$ABI64/sui_daemon"
            LOADER_DIR="$MODDIR/standalone_bin/$ABI64"
            ;;
    esac
    PID_FILE="/data/adb/sui/sui_daemon.pid"
    MONITOR_PID_FILE="/data/adb/sui/sui_monitor.pid"

    # 设置正确的库加载路径
    export LD_LIBRARY_PATH="$LIB_DIR:$LOADER_DIR:$LD_LIBRARY_PATH"
    export TMP_PATH='/data/adb/sui'
    mkdir -p "$TMP_PATH"
    chmod 755 "$TMP_PATH"
    chcon u:object_r:system_file:s0 "$TMP_PATH"
    cp "$MODDIR/standalone_bin/$ABI/libsui_loader.so" "$TMP_PATH/libsui_loader.so"
    chmod 644 "$TMP_PATH/libsui_loader.so"
    chcon u:object_r:system_file:s0 "$TMP_PATH/libsui_loader.so"
    cp "$MODDIR/standalone_bin/$ABI/sui_monitor" "$TMP_PATH/sui_monitor"
    chmod 755 "$TMP_PATH/sui_monitor"
    chcon u:object_r:system_file:s0 "$TMP_PATH/sui_monitor"
    MONITOR_PATH="$TMP_PATH/sui_monitor"

    # 检查 sui_daemon 是否存在
    if [ ! -f "$DAEMON_PATH" ]; then
            log -p e "Sui: CRITICAL - sui_daemon for ABI '$ABI' not found!"
    else
        chmod +x "$DAEMON_PATH"
        export LD_LIBRARY_PATH="$LIB_DIR:$TMP_PATH:$LD_LIBRARY_PATH"

        if [ -f "$PID_FILE" ] && ps -p $(cat "$PID_FILE") > /dev/null; then
            log -p i "Sui: Standalone Daemon is already running."
        else
            log -p i "Sui: Launching Standalone Daemon..."
            (sh -c "exec '$DAEMON_PATH'" >/dev/null 2>&1 & echo $! > "$PID_FILE")
            sleep 1
        fi

        # 启动 Monitor
        if [ -f "$MONITOR_PID_FILE" ] && ps -p $(cat "$MONITOR_PID_FILE") > /dev/null; then
             log -p i "Sui: Standalone Monitor is already running."
        else
             log -p i "Sui: Launching Standalone Monitor..."
             # 传递 "monitor" 参数
             (sh -c "exec '$MONITOR_PATH' monitor" >/dev/null 2>&1 & echo $! > "$MONITOR_PID_FILE")
             # (sleep 5; sh -c "exec '$MONITOR_PATH' monitor" >/dev/null 2>&1 & echo $! > "$MONITOR_PID_FILE") &
        fi
    fi

# ==========================================
# 2. 原版 Zygisk 检测逻辑
# ==========================================
elif [ "$IS_STANDALONE" = "false" ]; then
    if [ "$ZYGISK_ENABLED" = false ]; then
      log -p w "Sui: Zygisk is disabled, module will not be loaded."
      exit 1
    fi
fi

# ==========================================
# 3. 通用逻辑
# ==========================================
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
exec "$MODDIR"/bin/sui "$MODDIR" "$adb_root_exit"
