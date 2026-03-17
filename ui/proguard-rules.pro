-keepattributes SourceFile,LineNumberTable,*Annotation*

-keepclassmembers class **.R$* {
    public static <fields>;
}

-keepnames class * implements android.os.Parcelable
-keepclassmembers class * implements android.os.Parcelable {
  public static final android.os.Parcelable$Creator CREATOR;
}

-keep public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

-keep class androidx.appcompat.** { *; }
-keep interface androidx.appcompat.** { *; }

-keep class androidx.vectordrawable.** { *; }
-keep interface androidx.vectordrawable.** { *; }

-keep class androidx.core.** { *; }
-keep interface androidx.core.** { *; }

-keep class androidx.appcompat.widget.ResourceManagerInternal { *; }
-keep class androidx.appcompat.widget.AppCompatDrawableManager { *; }

-keep class rikka.sui.** { *; }
-keep interface rikka.sui.** { *; }

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

-keepattributes SourceFile,LineNumberTable
-keep class androidx.appcompat.app.AppCompatDelegateImpl$*
-keep class com.google.android.material.** { *; }
-keep interface com.google.android.material.** { *; }
-keep class com.google.android.material.theme.overlay.** { *; }
-keep class dev.rikka.rikkax.** { *; }
-keep interface dev.rikka.rikkax.** { *; }
-keep class rikka.material.** { *; }
-keep interface rikka.material.** { *; }
-keep class me.zhanghai.android.fastscroll.** { *; }
-keep interface me.zhanghai.android.fastscroll.** { *; }
-keep class me.zhanghai.android.appiconloader.** { *; }
-keep interface me.zhanghai.android.appiconloader.** { *; }
