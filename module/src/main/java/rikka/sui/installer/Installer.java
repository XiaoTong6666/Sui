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

import android.app.ActivityThread;
import android.content.Context;
import android.os.Looper;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Locale;
import rikka.sui.util.SystemPackages;
import rikka.sui.util.SystemPackages.SystemPackage;

public class Installer {

    private static final int PACKAGE_INFO_RETRY_COUNT = 120;

    private static boolean saveApplicationInfoToFile(
            String path, String fileName, String name, SystemPackage systemPackage) throws IOException {
        if (systemPackage == null) {
            System.out.println("! Can't resolve the " + name + " package");
            return false;
        }

        System.out.println("- " + name + ": packageName=" + systemPackage.packageName + ", uid=" + systemPackage.uid
                + ", processName=" + systemPackage.processName);

        File file = new File(path, fileName);
        File temporaryFile = new File(path, fileName + ".new");
        if (temporaryFile.exists() && !temporaryFile.delete()) {
            throw new IOException("Can't delete " + temporaryFile);
        }

        try (FileWriter writer = new FileWriter(temporaryFile)) {
            writer.write(String.format(
                    Locale.ENGLISH,
                    "%s\n%d\n%s",
                    systemPackage.packageName,
                    systemPackage.uid,
                    systemPackage.processName));
        }

        if (!temporaryFile.renameTo(file)) {
            temporaryFile.delete();
            throw new IOException("Can't replace " + file);
        }
        return true;
    }

    private static SystemPackage[] resolvePackages(Context context) throws InterruptedException {
        SystemPackage systemUi = null;
        SystemPackage settings = null;

        for (int attempt = 0; attempt < PACKAGE_INFO_RETRY_COUNT; ++attempt) {
            if (systemUi == null) {
                systemUi = SystemPackages.resolveSystemUi(context);
            }
            if (settings == null) {
                settings = SystemPackages.resolveSettings(context);
            }
            if (systemUi != null && settings != null) {
                break;
            }

            if (attempt == 0 || (attempt + 1) % 10 == 0) {
                System.out.println(
                        "- Waiting for PackageManager (" + (attempt + 1) + "/" + PACKAGE_INFO_RETRY_COUNT + ")");
            }
            Thread.sleep(1000);
        }

        return new SystemPackage[] {systemUi, settings};
    }

    @SuppressWarnings("deprecation")
    public static void main(String[] args) throws IOException, InterruptedException {
        System.out.println("- AppProcess: main");

        if (Looper.getMainLooper() == null) {
            Looper.prepareMainLooper();
        }
        Context context = ActivityThread.systemMain().getSystemContext();
        SystemPackage[] packages = resolvePackages(context);

        if (packages[0] == null || packages[1] == null) {
            System.out.println("! PackageManager did not resolve all required packages");
            System.exit(1);
            return;
        }

        if (!saveApplicationInfoToFile(args[0], "system_ui", "SystemUI", packages[0])
                || !saveApplicationInfoToFile(args[0], "settings", "Settings", packages[1])) {
            System.out.println("! Failed to save package metadata");
            System.exit(1);
            return;
        }
        System.out.println("- AppProcess: exit");
    }
}
