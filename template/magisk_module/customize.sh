SKIPUNZIP=1

# Extract verify.sh
ui_print "- Extracting verify.sh"
unzip -o "$ZIPFILE" 'verify.sh' -d "$TMPDIR" >&2
if [ ! -f "$TMPDIR/verify.sh" ]; then
  ui_print "*********************************************************"
  ui_print "! Unable to extract verify.sh!"
  ui_print "! This zip may be corrupted, please try downloading again"
  abort "*********************************************************"
fi
. $TMPDIR/verify.sh

# Extract util_functions.sh
ui_print "- Extracting util_functions.sh"
extract "$ZIPFILE" 'util_functions.sh' "$TMPDIR"
. $TMPDIR/util_functions.sh

#########################################################

ROOT_PATH="/data/adb/sui"

enforce_install_from_magisk_app
check_magisk_version
check_android_version
check_arch

mkdir $ROOT_PATH
set_perm "$ROOT_PATH" 0 0 0600

# Extract libs
ui_print "- Extracting module files"

extract "$ZIPFILE" 'module.prop' "$MODPATH"
extract "$ZIPFILE" 'post-fs-data.sh' "$MODPATH"
extract "$ZIPFILE" 'service.sh' "$MODPATH"
extract "$ZIPFILE" 'uninstall.sh' "$MODPATH"
extract "$ZIPFILE" 'sepolicy.rule' "$MODPATH"

ui_print "- Extracting action script"
extract "$ZIPFILE" 'action.sh' "$MODPATH"
set_perm "$MODPATH/action.sh" 0 0 0755

ui_print "- Patching sepolicy.rule"
su_secon=$(id -Z | cut -d: -f3)
adb_data_file_secon=$(ls -Zd /data/adb | awk '{print $1}' | cut -d: -f3)
sed -i "s|%su_secon%|$su_secon|g" "$MODPATH/sepolicy.rule"
sed -i "s|%adb_data_file_secon%|$adb_data_file_secon|g" "$MODPATH/sepolicy.rule"

# Append legacy rules for API <= 27
if [ "$API" -le 27 ]; then
  ui_print "- Appending legacy sepolicy rules for API $API"
  cat >> "$MODPATH/sepolicy.rule" <<EOF

# Allow apps to execute their own data files (fix for API 25 private dir loading)
allow platform_app app_data_file file { read execute open getattr }
allow system_app app_data_file file { read execute open getattr }
allow system_app system_app_data_file file { read execute open getattr }

# Allow apps to access /data/system/sui when marked as system_file (API 26/27)
allow platform_app system_file file { read execute open getattr }
allow system_app system_file file { read execute open getattr }
allow platform_app system_file dir { search getattr }
allow system_app system_file dir { search getattr }

# Allow apps to access /data/system/sui when marked as system_data_file (API 25)
allow platform_app system_data_file file { read execute open getattr }
allow system_app system_data_file file { read execute open getattr }
allow platform_app system_data_file dir { search getattr }
allow system_app system_data_file dir { search getattr }

# Allow system_server to access /data/system/sui (critical for API 23 injection)
allow system_server system_data_file file { read execute open getattr map }
allow system_server system_data_file dir { search getattr }

# Allow dex2oat to access /data/system/sui (for OAT generation)
allow dex2oat system_data_file file { read write create getattr open }
allow dex2oat system_data_file dir { read write search add_name }
allow dex2oat system_app_data_file file { read write create getattr open }
allow dex2oat system_app_data_file dir { read write search add_name }
EOF
fi

mkdir "$MODPATH/zygisk"

extract "$ZIPFILE" "lib/$ARCH_NAME/libsui.so" "$MODPATH/zygisk" true
mv "$MODPATH/zygisk/libsui.so" "$MODPATH/zygisk/$ARCH_NAME.so"

if [ "$IS64BIT" = true ]; then
  extract "$ZIPFILE" "lib/$ARCH_NAME_SECONDARY/libsui.so" "$MODPATH/zygisk" true
  mv "$MODPATH/zygisk/libsui.so" "$MODPATH/zygisk/$ARCH_NAME_SECONDARY.so"
fi

mkdir "$MODPATH/bin"
mkdir "$MODPATH/lib"
extract "$ZIPFILE" "lib/$ARCH_NAME/libmain.so" "$MODPATH/bin" true
extract "$ZIPFILE" "lib/$ARCH_NAME/librish.so" "$MODPATH" true
extract "$ZIPFILE" "lib/$ARCH_NAME/libadbd_wrapper.so" "$MODPATH/bin" true
extract "$ZIPFILE" "lib/$ARCH_NAME/libadbd_preload.so" "$MODPATH/lib" true
extract "$ZIPFILE" "lib/$ARCH_NAME/libsepolicy_checker.so" "$MODPATH/bin" true

mv "$MODPATH/bin/libmain.so" "$MODPATH/bin/sui"
mv "$MODPATH/bin/libadbd_wrapper.so" "$MODPATH/bin/adbd_wrapper"
mv "$MODPATH/bin/libsepolicy_checker.so" "$MODPATH/bin/sepolicy_checker"

set_perm "$MODPATH/bin/sepolicy_checker" 0 0 0755
if [ "$API" -ge 24 ]; then
  ui_print "- Setting up adbd_wrapper"
else
  ui_print "- Android API < 24, skip adbd_wrapper setup"
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644

extract "$ZIPFILE" 'sui.dex' "$MODPATH"
extract "$ZIPFILE" 'sui.apk' "$MODPATH"

set_perm "$MODPATH/sui.dex" 0 0 0600
set_perm "$MODPATH/sui.apk" 0 0 0655
set_perm_recursive "$MODPATH/res" 0 0 0700 0600

ui_print "- Fetching information for SystemUI and Settings"
/system/bin/app_process -Djava.class.path="$MODPATH"/sui.dex /system/bin --nice-name=sui_installer rikka.sui.installer.Installer "$MODPATH"

ui_print "- Extracting files for rish"
extract "$ZIPFILE" 'rish' "$MODPATH"
extract "$ZIPFILE" 'post-install.example.sh' "$ROOT_PATH"
set_perm "$MODPATH/rish" 0 2000 0770
set_perm "$ROOT_PATH/post-install.example.sh" 0 0 0600

if [ -f $ROOT_PATH/post-install.sh ]; then
  cat "$ROOT_PATH/post-install.sh" | grep -q "SCRIPT_VERSION=2"
  if [ "$?" -eq 0 ]; then
    RISH_DEX=$MODPATH/sui.dex
    RISH_LIB=$MODPATH/librish.so
    RISH_SCRIPT=$MODPATH/rish
    ui_print "- Run /data/adb/sui/post-install.sh"
    source $ROOT_PATH/post-install.sh
  else
    ui_print "! To use new interactive shell tool (rish), post-install.sh needs update"
    ui_print "! Please check post-install.example.sh for more"
  fi
else
  ui_print "- Cannot find /data/adb/sui/post-install.sh"
fi

# Remove unused files
ui_print "- Removing old files"
rm -rf /data/adb/sui/res
rm -rf /data/adb/sui/res.new
rm -f /data/adb/sui/z
rm -f /data/adb/sui/com.android.systemui
rm -f /data/adb/sui/starter
rm -f /data/adb/sui/sui.dex
rm -f /data/adb/sui/sui.dex.new
rm -f /data/adb/sui/sui_wrapper

if [ "$(grep_prop ro.maple.enable)" == "1" ]; then
  ui_print "- Add ro.maple.enable=0"
  touch "$MODPATH/system.prop"
  echo "ro.maple.enable=0" >> "$MODPATH/system.prop"
fi
