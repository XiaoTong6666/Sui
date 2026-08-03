MODDIR=${0%/*}
SYSTEMUI_PACKAGE=com.android.systemui
if [ -r "$MODDIR/system_ui" ]; then
  IFS= read -r RESOLVED < "$MODDIR/system_ui"
  [ -n "$RESOLVED" ] && SYSTEMUI_PACKAGE="$RESOLVED"
fi

API=$(getprop ro.build.version.sdk)
if [ "$API" -ge 29 ]; then
  am broadcast -a android.telephony.action.SECRET_CODE -d android_secret_code://784784 "$SYSTEMUI_PACKAGE"
else
  am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://784784 "$SYSTEMUI_PACKAGE"
fi
