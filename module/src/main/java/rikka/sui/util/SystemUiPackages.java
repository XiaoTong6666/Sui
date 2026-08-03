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

import android.content.ComponentName;
import android.content.res.Resources;
import androidx.annotation.Nullable;
import rikka.hidden.compat.PackageManagerApis;

/**
 * SystemUI hosts the management UI and the permission confirmation dialog.
 *
 * <p>Its package name is not always {@code com.android.systemui}: Meta Horizon OS (Quest) ships
 * {@code com.meta.systemui} instead. Resolve it from the framework config first so that devices we
 * have never seen keep working, and fall back to a list of known package names.
 */
public final class SystemUiPackages {

    public static final String SYSTEM_UI = "com.android.systemui";
    public static final String META_SYSTEM_UI = "com.meta.systemui";
    public static final String[] SYSTEM_UI_CANDIDATES = {SYSTEM_UI, META_SYSTEM_UI};

    private SystemUiPackages() {}

    public static @Nullable String resolveInstalledSystemUiPackage() {
        String packageName = resolveFromFrameworkConfig();
        if (packageName != null && isInstalled(packageName)) {
            return packageName;
        }
        for (String candidate : SYSTEM_UI_CANDIDATES) {
            if (isInstalled(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    public static String getPreferredSystemUiPackage() {
        String packageName = resolveInstalledSystemUiPackage();
        return packageName != null ? packageName : SYSTEM_UI;
    }

    private static boolean isInstalled(String packageName) {
        return PackageManagerApis.getApplicationInfoNoThrow(packageName, 0, 0) != null;
    }

    /**
     * {@code config_systemUIServiceComponent} is what SystemServer itself uses to start SystemUI,
     * so it names the package on any device that has one.
     */
    private static @Nullable String resolveFromFrameworkConfig() {
        try {
            Resources resources = Resources.getSystem();
            int id = resources.getIdentifier("config_systemUIServiceComponent", "string", "android");
            if (id == 0) {
                return null;
            }
            ComponentName component = ComponentName.unflattenFromString(resources.getString(id));
            return component != null ? component.getPackageName() : null;
        } catch (Throwable e) {
            return null;
        }
    }
}
