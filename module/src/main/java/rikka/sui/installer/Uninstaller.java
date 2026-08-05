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
 * Copyright (c) 2022-2026 Sui Contributors
 */

package rikka.sui.installer;

import android.app.ActivityThread;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ShortcutManager;
import android.os.Build;
import android.os.Handler;
import android.os.IUserManager;
import android.os.Looper;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import java.util.ArrayList;
import java.util.List;
import rikka.sui.shortcut.ShortcutConstants;
import rikka.sui.util.SystemPackages;
import rikka.sui.util.SystemPackages.SystemPackage;

public class Uninstaller {

    private static final String TAG = "SuiUninstaller";
    private static final int SETTINGS_PACKAGE_RETRY_COUNT = 30;

    private static @Nullable String findInstalledSettingsPackage(String[] args) {
        for (String arg : args) {
            if (!arg.startsWith("--")) {
                return arg;
            }
        }
        return null;
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private static final class ShortcutCleaner {

        private static void remove(Context context, String packageName, List<String> shortcutIds) {
            try {
                Context packageContext = context.createPackageContext(packageName, 0);
                ShortcutManager shortcutManager = packageContext.getSystemService(ShortcutManager.class);
                if (shortcutManager == null) {
                    Log.w(TAG, "ShortcutManager is unavailable for " + packageName);
                    return;
                }
                shortcutManager.removeDynamicShortcuts(shortcutIds);
                shortcutManager.disableShortcuts(shortcutIds);
            } catch (PackageManager.NameNotFoundException e) {
                Log.w(TAG, "Settings package is unavailable: " + packageName, e);
            } catch (Throwable e) {
                Log.w(TAG, "Can't clean shortcuts for " + packageName, e);
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private static void removeShortcuts(Context context, @Nullable String installedPackageName)
            throws InterruptedException, RemoteException {
        IUserManager userManager = null;

        while (true) {
            if (userManager == null) {
                userManager = IUserManager.Stub.asInterface(ServiceManager.getService("user"));
            }
            if (ServiceManager.getService("shortcut") != null && userManager != null && userManager.isUserUnlocked(0)) {
                break;
            }

            //noinspection BusyWait
            Thread.sleep(1000);
            Log.v(TAG, "wait for services and user unlock 1s");
        }

        List<String> list = new ArrayList<>();
        list.add(ShortcutConstants.SHORTCUT_ID);
        list.add(ShortcutConstants.LEGACY_SHORTCUT_ID);

        List<String> packageNames = new ArrayList<>();
        if (installedPackageName != null) {
            packageNames.add(installedPackageName);
        }

        SystemPackage settingsPackage = null;
        for (int attempt = 0; settingsPackage == null && attempt < SETTINGS_PACKAGE_RETRY_COUNT; ++attempt) {
            settingsPackage = SystemPackages.resolveSettings(context);
            if (settingsPackage == null && attempt + 1 < SETTINGS_PACKAGE_RETRY_COUNT) {
                Thread.sleep(1000);
                Log.v(TAG, "wait for Settings package 1s (" + (attempt + 1) + "/" + SETTINGS_PACKAGE_RETRY_COUNT + ")");
            }
        }
        if (settingsPackage != null && !packageNames.contains(settingsPackage.packageName)) {
            packageNames.add(settingsPackage.packageName);
        }
        if (packageNames.isEmpty()) {
            Log.w(TAG, "No Settings package available for shortcut cleanup");
        }

        for (String packageName : packageNames) {
            ShortcutCleaner.remove(context, packageName, list);
        }
    }

    public static void main(String[] args) throws ErrnoException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }

        Log.i(TAG, "main");

        setSystemUid();

        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Context context = ActivityThread.systemMain().getSystemContext();
        String installedSettingsPackage = findInstalledSettingsPackage(args);

        new Handler(Looper.myLooper()).post(() -> {
            try {
                removeShortcuts(context, installedSettingsPackage);
            } catch (Throwable e) {
                Log.e(TAG, Log.getStackTraceString(e));
            }

            Log.i(TAG, "exit");
            System.exit(0);
        });

        Looper.loop();
    }

    @SuppressWarnings("deprecation")
    private static void setSystemUid() throws ErrnoException {
        Os.setuid(1000);
    }
}
