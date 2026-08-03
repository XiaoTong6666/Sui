MODDIR=${0%/*}
if [ ! -r "$MODDIR/system_ui" ]; then
  log -t Sui "SystemUI package metadata is missing"
  exit 1
fi

IFS= read -r SYSTEMUI_PACKAGE < "$MODDIR/system_ui"
if [ -z "$SYSTEMUI_PACKAGE" ]; then
  log -t Sui "SystemUI package metadata is empty"
  exit 1
fi

API=$(getprop ro.build.version.sdk)
if [ "$API" -ge 29 ]; then
  am broadcast -a android.telephony.action.SECRET_CODE -d android_secret_code://784784 "$SYSTEMUI_PACKAGE"
else
  am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://784784 "$SYSTEMUI_PACKAGE"
fi
