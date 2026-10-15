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

package rikka.sui.server;

import static rikka.sui.server.ServerConstants.LOGGER;

import android.annotation.SuppressLint;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageInfoHidden;
import android.content.pm.PackageManager;
import android.os.Build;
import android.util.ArrayMap;
import dev.rikka.tools.refine.Refine;
import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import rikka.hidden.compat.PackageManagerApis;
import rikka.hidden.compat.UserManagerApis;
import rikka.parcelablelist.ParcelableListSlice;
import rikka.sui.model.AppInfo;
import rikka.sui.util.MapUtil;
import rikka.sui.util.UserHandleCompat;

public class AppListBuilder {

    @SuppressLint({"DiscouragedPrivateApi", "PrivateApi"})
    @SuppressWarnings("unchecked")
    private static List<PackageInfo> getInstalledPackagesFallback(long flags, int user) {
        try {
            Class<?> appGlobalsClass = Class.forName("android.app.AppGlobals");
            Method getPackageManager = appGlobalsClass.getDeclaredMethod("getPackageManager");
            Object packageManager = getPackageManager.invoke(null);
            if (packageManager == null) {
                LOGGER.w("AppListBuilder: AppGlobals.getPackageManager() returned null for user %d", user);
                return Collections.emptyList();
            }

            String[] candidates = {"getInstalledPackagesAsUser", "getInstalledPackages"};

            for (String name : candidates) {
                try {
                    Method method = packageManager.getClass().getMethod(name, long.class, int.class);
                    Object result = method.invoke(packageManager, flags, user);
                    if (result instanceof android.content.pm.ParceledListSlice) {
                        List<PackageInfo> list = ((android.content.pm.ParceledListSlice<PackageInfo>) result).getList();
                        if (list != null) {
                            LOGGER.i("AppListBuilder: using AppGlobals.%s(long,int) fallback for user %d", name, user);
                            return list;
                        }
                    }
                } catch (NoSuchMethodException ignored) {
                }

                try {
                    Method method = packageManager.getClass().getMethod(name, int.class, int.class);
                    Object result = method.invoke(packageManager, (int) flags, user);
                    if (result instanceof android.content.pm.ParceledListSlice) {
                        List<PackageInfo> list = ((android.content.pm.ParceledListSlice<PackageInfo>) result).getList();
                        if (list != null) {
                            LOGGER.i("AppListBuilder: using AppGlobals.%s(int,int) fallback for user %d", name, user);
                            return list;
                        }
                    }
                } catch (NoSuchMethodException ignored) {
                }
            }

            LOGGER.w("AppListBuilder: no compatible AppGlobals package query method found for user %d", user);
        } catch (Throwable e) {
            LOGGER.w(e, "AppListBuilder: AppGlobals package query fallback failed for user %d", user);
        }
        return Collections.emptyList();
    }

    private static int getFlagsForUidInternal(SuiConfigManager configManager, int uid, int mask) {
        SuiConfig.PackageEntry entry = configManager.findExplicit(uid);
        if (entry != null) {
            return entry.flags & mask;
        }
        return 0;
    }

    public static ParcelableListSlice<AppInfo> build(
            SuiConfigManager configManager, int systemUiUid, int userId, boolean onlyShizuku) {

        int defaultPermissionFlags = configManager.getDefaultPermissionFlags();
        List<Integer> users = new ArrayList<>();
        if (userId == -1) {
            users.addAll(UserManagerApis.getUserIdsNoThrow());
        } else {
            users.add(userId);
        }

        Map<String, Boolean> existenceCache = new ArrayMap<>();
        List<AppInfo> list = new ArrayList<>();
        int installedBaseFlags = 0x00002000 /*MATCH_UNINSTALLED_PACKAGES*/ | PackageManager.GET_PERMISSIONS;

        for (int user : users) {
            List<PackageInfo> packages = PackageManagerApis.getInstalledPackagesNoThrow(installedBaseFlags, user);
            if (packages.isEmpty()) {
                LOGGER.w(
                        "AppListBuilder: PackageManagerApis.getInstalledPackagesNoThrow returned 0 packages for user %d",
                        user);
                packages = getInstalledPackagesFallback(installedBaseFlags, user);
            }

            for (PackageInfo pi : packages) {
                try {
                    if (pi.applicationInfo == null
                            || Refine.<PackageInfoHidden>unsafeCast(pi).overlayTarget != null
                            || (pi.applicationInfo.flags & ApplicationInfo.FLAG_HAS_CODE) == 0) {
                        continue;
                    }

                    int uid = pi.applicationInfo.uid;

                    if (onlyShizuku) {
                        boolean explicitlyAllowed = false;
                        SuiConfig.PackageEntry explicitEntry = configManager.findExplicit(uid);
                        if (explicitEntry != null && (explicitEntry.isAllowed() || explicitEntry.isAllowedShell())) {
                            explicitlyAllowed = true;
                        }

                        if (!explicitlyAllowed) {
                            if (pi.requestedPermissions == null) {
                                continue;
                            }
                            boolean requested = false;
                            for (String p : pi.requestedPermissions) {
                                if ("moe.shizuku.manager.permission.API_V23".equals(p)) {
                                    requested = true;
                                    break;
                                }
                            }
                            if (!requested) {
                                continue;
                            }
                        }
                    }

                    int appId = UserHandleCompat.getAppId(uid);
                    if (uid == systemUiUid) {
                        continue;
                    }

                    int flags = getFlagsForUidInternal(configManager, uid, SuiConfig.MASK_PERMISSION);
                    if (flags == 0 && uid != 2000 && appId < 10000) {
                        continue;
                    }

                    if (flags == 0) {
                        final String sourceDir = pi.applicationInfo.sourceDir;
                        final String dataDir = pi.applicationInfo.dataDir;
                        final String deviceProtectedDataDir = Build.VERSION.SDK_INT >= Build.VERSION_CODES.N
                                ? pi.applicationInfo.deviceProtectedDataDir
                                : null;
                        boolean hasApk = sourceDir != null
                                && MapUtil.getOrPut(existenceCache, sourceDir, () -> new File(sourceDir).exists());
                        boolean hasData = (dataDir != null
                                        && MapUtil.getOrPut(existenceCache, dataDir, () -> new File(dataDir).exists()))
                                || (deviceProtectedDataDir != null
                                        && MapUtil.getOrPut(
                                                existenceCache,
                                                deviceProtectedDataDir,
                                                () -> new File(deviceProtectedDataDir).exists()));

                        // Installed (or hidden): hasApk && hasData
                        // Uninstalled but keep data: !hasApk && hasData
                        // Installed in other users only: hasApk && !hasData
                        if (!(hasApk && hasData)) {
                            continue;
                        }
                    }

                    pi.activities = null;
                    pi.receivers = null;
                    pi.services = null;
                    pi.providers = null;

                    AppInfo item = new AppInfo();
                    item.packageInfo = pi;
                    item.flags = flags;
                    SuiConfig.PackageEntry effectiveEntry = configManager.find(uid);
                    item.effectiveFlags =
                            effectiveEntry != null ? (effectiveEntry.flags & SuiConfig.MASK_PERMISSION) : 0;
                    item.defaultFlags = defaultPermissionFlags;
                    list.add(item);
                } catch (Throwable e) {
                    LOGGER.w(e, "Error processing package %d %s", user, pi.packageName);
                }
            }
        }
        return new ParcelableListSlice<>(list);
    }
}
