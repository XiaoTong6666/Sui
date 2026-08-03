-keepattributes SourceFile,LineNumberTable,*Annotation*

-keepclassmembers class **.R$* {
    public static <fields>;
}

-keepnames class * implements android.os.Parcelable
-keepclassmembers class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator CREATOR;
}

-keep class rikka.sui.SuiActivity {
    public <init>(android.app.Application, android.content.res.Resources, android.content.ComponentName);
}

-keep class rikka.sui.SuiRequestPermissionDialog {
    public <init>(android.app.Application, android.content.res.Resources, int, int, java.lang.String, int);
}

-keep class rikka.sui.util.MiuixPopupTransition {
    public <init>();
}

-keep class rikka.sui.widget.MiuixDragHandleView {
    public <init>(android.content.Context, android.util.AttributeSet, int);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context);
}

-keep class rikka.sui.util.MiuixPullToRefreshView {
    public <init>(android.content.Context, android.util.AttributeSet, int);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context);
}

-keep class androidx.appcompat.widget.PopupMenu { *; }
-keep class androidx.appcompat.view.menu.MenuPopupHelper { *; }
-keep class androidx.appcompat.view.menu.MenuPopup { *; }
-keep class androidx.appcompat.view.menu.StandardMenuPopup { *; }
-keep class androidx.appcompat.view.menu.CascadingMenuPopup { *; }
-keep class androidx.appcompat.widget.MenuPopupWindow { *; }
-keep class androidx.appcompat.widget.MenuPopupWindow$MenuDropDownListView { *; }

-keepclassmembers class androidx.appcompat.widget.PopupMenu {
    *** mAnchor;
    *** mPopup;
}

-keepclassmembers class androidx.appcompat.** {
    *** mPopup;
    *** getPopup(...);
    *** getListView(...);
    void setForceShowIcon(boolean);
    void setOverlapAnchor(boolean);
    void setForceIgnoreOutsideTouch(boolean);
}

-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}
-assumenosideeffects class rikka.sui.util.Logger {
    public *** v(...);
    public *** d(...);
    public *** i(...);
    public *** w(...);
    public *** e(...);
}

-dontwarn androidx.**
-dontwarn android.support.**
-dontwarn org.jetbrains.annotations.**
