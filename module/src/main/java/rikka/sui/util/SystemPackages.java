/*
 * This file is part of Sui.
 *
 * Sui is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Sui is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Sui.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Copyright (c) 2026 Sui Contributors
 */

package rikka.sui.util;

import android.annotation.SuppressLint;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.provider.Settings;
import androidx.annotation.Nullable;
import java.util.List;
import rikka.hidden.compat.PackageManagerApis;

public final class SystemPackages {

    private static final String LEGACY_SYSTEM_UI_PACKAGE = "com.android.systemui";
    private static final String LEGACY_SYSTEM_UI_SERVICE = "com.android.systemui.SystemUIService";
    private static final String LEGACY_SETTINGS_PACKAGE = "com.android.settings";
    private static final String LEGACY_TV_SETTINGS_PACKAGE = "com.android.tv.settings";

    public static final class SystemPackage {

        public final String packageName;
        public final int uid;
        public final String processName;

        private SystemPackage(String packageName, int uid, String processName) {
            this.packageName = packageName;
            this.uid = uid;
            this.processName = processName;
        }
    }

    private SystemPackages() {}

    private static boolean isSystemApplication(ApplicationInfo applicationInfo) {
        return (applicationInfo.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
    }

    private static @Nullable ApplicationInfo getSystemApplication(String packageName) {
        ApplicationInfo applicationInfo = PackageManagerApis.getApplicationInfoNoThrow(packageName, 0, 0);
        return applicationInfo != null && isSystemApplication(applicationInfo) ? applicationInfo : null;
    }

    private static @Nullable SystemPackage getSystemPackage(String packageName, @Nullable String processName) {
        try {
            ApplicationInfo applicationInfo = getSystemApplication(packageName);
            if (applicationInfo == null) {
                return null;
            }

            if (processName == null) {
                processName = applicationInfo.processName;
            }
            if (processName == null) {
                processName = packageName;
            }
            return new SystemPackage(packageName, applicationInfo.uid, processName);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private static @Nullable SystemPackage getSystemPackage(ComponentInfo componentInfo) {
        return getSystemPackage(componentInfo.packageName, componentInfo.processName);
    }

    private static @Nullable SystemPackage resolveLegacySystemUi(Context context) {
        try {
            ComponentName component = new ComponentName(LEGACY_SYSTEM_UI_PACKAGE, LEGACY_SYSTEM_UI_SERVICE);
            return getSystemPackage(context.getPackageManager().getServiceInfo(component, 0));
        } catch (PackageManager.NameNotFoundException | RuntimeException ignored) {
            return getSystemPackage(LEGACY_SYSTEM_UI_PACKAGE, null);
        }
    }

    @SuppressLint("DiscouragedApi")
    public static @Nullable SystemPackage resolveSystemUi(Context context) {
        try {
            int id = context.getResources().getIdentifier("config_systemUIServiceComponent", "string", "android");
            if (id != 0) {
                ComponentName component =
                        ComponentName.unflattenFromString(context.getResources().getString(id));
                if (component != null) {
                    ServiceInfo serviceInfo = context.getPackageManager().getServiceInfo(component, 0);
                    SystemPackage systemPackage = getSystemPackage(serviceInfo);
                    if (systemPackage != null) {
                        return systemPackage;
                    }
                }
            }
        } catch (PackageManager.NameNotFoundException | RuntimeException ignored) {
        }

        return resolveLegacySystemUi(context);
    }

    private static @Nullable SystemPackage getSettingsPackage(ResolveInfo resolveInfo) {
        if (resolveInfo == null || resolveInfo.activityInfo == null) {
            return null;
        }
        return getSystemPackage(resolveInfo.activityInfo);
    }

    private static @Nullable SystemPackage resolveLegacySettings(Context context) {
        boolean isTelevision =
                (context.getResources().getConfiguration().uiMode & android.content.res.Configuration.UI_MODE_TYPE_MASK)
                        == android.content.res.Configuration.UI_MODE_TYPE_TELEVISION;
        String[] packageNames = isTelevision
                ? new String[] {LEGACY_TV_SETTINGS_PACKAGE, LEGACY_SETTINGS_PACKAGE}
                : new String[] {LEGACY_SETTINGS_PACKAGE, LEGACY_TV_SETTINGS_PACKAGE};
        for (String packageName : packageNames) {
            SystemPackage systemPackage = getSystemPackage(packageName, null);
            if (systemPackage != null) {
                return systemPackage;
            }
        }
        return null;
    }

    @SuppressLint("InlinedApi")
    public static @Nullable SystemPackage resolveSettings(Context context) {
        PackageManager packageManager = context.getPackageManager();
        Intent intent = new Intent(Settings.ACTION_SETTINGS);
        int flags = PackageManager.MATCH_DEFAULT_ONLY;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            flags |= PackageManager.MATCH_DIRECT_BOOT_AWARE | PackageManager.MATCH_DIRECT_BOOT_UNAWARE;
        }

        try {
            SystemPackage systemPackage = getSettingsPackage(packageManager.resolveActivity(intent, flags));
            if (systemPackage != null && !"android".equals(systemPackage.packageName)) {
                return systemPackage;
            }

            List<ResolveInfo> resolveInfos = packageManager.queryIntentActivities(intent, flags);
            for (ResolveInfo resolveInfo : resolveInfos) {
                systemPackage = getSettingsPackage(resolveInfo);
                if (systemPackage != null && !"android".equals(systemPackage.packageName)) {
                    return systemPackage;
                }
            }
        } catch (RuntimeException ignored) {
        }

        return resolveLegacySettings(context);
    }
}
