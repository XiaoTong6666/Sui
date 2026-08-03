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
import android.content.pm.IShortcutService;
import android.content.pm.IShortcutServiceV31;
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
import dev.rikka.tools.refine.Refine;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import rikka.sui.shortcut.ShortcutConstants;
import rikka.sui.util.SystemPackages;
import rikka.sui.util.SystemPackages.SystemPackage;

@RequiresApi(Build.VERSION_CODES.O)
public class Uninstaller {

    private static final String TAG = "SuiUninstaller";

    private static @Nullable String readInstalledSettingsPackage(@Nullable String rootPath) {
        if (rootPath == null) {
            return null;
        }

        File file = new File(rootPath, "settings");
        if (!file.isFile()) {
            return null;
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            return reader.readLine();
        } catch (IOException e) {
            Log.w(TAG, "Can't read installed Settings package", e);
            return null;
        }
    }

    private static void removeShortcuts(Context context, @Nullable String rootPath)
            throws InterruptedException, RemoteException {
        IShortcutService shortcutService = null;
        IUserManager userManager = null;

        while (true) {
            //noinspection ConstantConditions
            if (shortcutService == null) {
                shortcutService = IShortcutService.Stub.asInterface(ServiceManager.getService("shortcut"));
            }
            if (userManager == null) {
                userManager = IUserManager.Stub.asInterface(ServiceManager.getService("user"));
            }
            if (shortcutService != null && userManager != null && userManager.isUserUnlocked(0)) {
                break;
            }

            //noinspection BusyWait
            Thread.sleep(1000);
            Log.v(TAG, "wait 1s");
        }

        List<String> list = new ArrayList<>();
        list.add(ShortcutConstants.SHORTCUT_ID);

        List<String> packageNames = new ArrayList<>();
        String installedPackageName = readInstalledSettingsPackage(rootPath);
        if (installedPackageName != null) {
            packageNames.add(installedPackageName);
        }

        SystemPackage settingsPackage = SystemPackages.resolveSettings(context);
        while (settingsPackage == null && packageNames.isEmpty()) {
            Thread.sleep(1000);
            Log.v(TAG, "wait for Settings package 1s");
            settingsPackage = SystemPackages.resolveSettings(context);
        }
        if (settingsPackage != null && !packageNames.contains(settingsPackage.packageName)) {
            packageNames.add(settingsPackage.packageName);
        }

        for (String packageName : packageNames) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                Refine.<IShortcutServiceV31>unsafeCast(shortcutService).removeDynamicShortcuts(packageName, list, 0);
            } else {
                shortcutService.removeDynamicShortcuts(packageName, list, 0);
            }
        }
    }

    public static void main(String[] args) throws IOException, ErrnoException {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }

        Log.i(TAG, "main");

        setSystemUid();

        if (Looper.myLooper() == null) {
            Looper.prepare();
        }
        Context context = ActivityThread.systemMain().getSystemContext();
        String rootPath = args.length > 0 ? args[0] : null;

        new Handler(Looper.myLooper()).post(() -> {
            try {
                removeShortcuts(context, rootPath);
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
