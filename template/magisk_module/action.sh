MODDIR=${0%/*}

# SystemUI is not always com.android.systemui (Meta Horizon OS ships com.meta.systemui).
# The installer resolves it and writes the package name here.
SYSTEMUI_PACKAGE=com.android.systemui
if [ -f "$MODDIR/systemui_package" ]; then
  RESOLVED=$(cat "$MODDIR/systemui_package")
  [ -n "$RESOLVED" ] && SYSTEMUI_PACKAGE="$RESOLVED"
fi

API=$(getprop ro.build.version.sdk)
if [ "$API" -ge 29 ]; then
  am broadcast -a android.telephony.action.SECRET_CODE -d android_secret_code://784784 "$SYSTEMUI_PACKAGE"
else
  am broadcast -a android.provider.Telephony.SECRET_CODE -d android_secret_code://784784 "$SYSTEMUI_PACKAGE"
fi
