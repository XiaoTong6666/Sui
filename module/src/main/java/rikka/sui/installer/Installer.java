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
 * Copyright (c) 2021-2026 Sui Contributors
 */

package rikka.sui.installer;

import android.content.pm.ApplicationInfo;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Locale;
import rikka.hidden.compat.PackageManagerApis;
import rikka.sui.util.SettingsPackages;
import rikka.sui.util.SystemUiPackages;

public class Installer {

    private static void saveApplicationInfoToFile(String path, String packageName, String fileName, String name)
            throws IOException {
        ApplicationInfo ai = PackageManagerApis.getApplicationInfoNoThrow(packageName, 0, 0);
        if (ai == null) {
            System.out.println("! Can't fetch application info for package " + packageName);
            return;
        }
        int uid = ai.uid;
        String processName = ai.processName != null ? ai.processName : packageName;
        System.out.println("- " + name + ": uid=" + uid + ", processName=" + processName);

        File file = new File(path, fileName);
        if (!file.exists() && !file.createNewFile()) {
            System.out.println("! Can't create " + file);
            return;
        }

        FileWriter writer = new FileWriter(file);
        writer.write(String.format(Locale.ENGLISH, "%d\n%s", uid, processName));
        writer.flush();
        writer.close();
    }

    private static void savePackageNameToFile(String path, String fileName, String packageName) throws IOException {
        File file = new File(path, fileName);
        if (!file.exists() && !file.createNewFile()) {
            System.out.println("! Can't create " + file);
            return;
        }

        FileWriter writer = new FileWriter(file);
        writer.write(packageName);
        writer.flush();
        writer.close();
    }

    public static void main(String[] args) throws IOException {
        System.out.println("- AppProcess: main");

        String systemUiPackageName = SystemUiPackages.resolveInstalledSystemUiPackage();
        if (systemUiPackageName == null) {
            System.out.println("! Can't fetch application info for SystemUI packages "
                    + java.util.Arrays.toString(SystemUiPackages.SYSTEM_UI_CANDIDATES));
        } else {
            // The file name stays com.android.systemui because the zygisk module uses it as a key.
            saveApplicationInfoToFile(args[0], systemUiPackageName, SystemUiPackages.SYSTEM_UI, "SystemUI");
            // action.sh sends the secret code broadcast to this package.
            savePackageNameToFile(args[0], "systemui_package", systemUiPackageName);
        }

        String settingsPackageName = SettingsPackages.resolveInstalledSettingsPackage();
        if (settingsPackageName == null) {
            System.out.println("! Can't fetch application info for settings packages "
                    + java.util.Arrays.toString(SettingsPackages.SETTINGS_CANDIDATES));
        } else {
            saveApplicationInfoToFile(args[0], settingsPackageName, SettingsPackages.SETTINGS, "Settings");
        }
        System.out.println("- AppProcess: exit");
    }
}
