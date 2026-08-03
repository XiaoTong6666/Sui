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

    private static void saveApplicationInfoToFile(
            String path, String fileName, String name, SystemPackage systemPackage) throws IOException {
        File file = new File(path, fileName);
        if (systemPackage == null) {
            if (file.exists() && !file.delete()) {
                System.out.println("! Can't delete stale " + file);
            }
            System.out.println("! Can't resolve the " + name + " package");
            return;
        }

        System.out.println("- " + name + ": packageName=" + systemPackage.packageName + ", uid=" + systemPackage.uid
                + ", processName=" + systemPackage.processName);

        if (!file.exists() && !file.createNewFile()) {
            System.out.println("! Can't create " + file);
            return;
        }

        try (FileWriter writer = new FileWriter(file)) {
            writer.write(String.format(
                    Locale.ENGLISH,
                    "%s\n%d\n%s",
                    systemPackage.packageName,
                    systemPackage.uid,
                    systemPackage.processName));
        }
    }

    @SuppressWarnings("deprecation")
    public static void main(String[] args) throws IOException {
        System.out.println("- AppProcess: main");

        if (Looper.getMainLooper() == null) {
            Looper.prepareMainLooper();
        }
        Context context = ActivityThread.systemMain().getSystemContext();

        saveApplicationInfoToFile(args[0], "system_ui", "SystemUI", SystemPackages.resolveSystemUi(context));
        saveApplicationInfoToFile(args[0], "settings", "Settings", SystemPackages.resolveSettings(context));
        System.out.println("- AppProcess: exit");
    }
}
