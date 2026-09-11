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

package rikka.sui.server;

import android.os.Build;
import java.io.File;
import java.util.Locale;
import rikka.shizuku.server.UserServiceManager;

public class SuiUserServiceManager extends UserServiceManager {

    public static final String USER_SERVICE_CMD_DEBUG;

    private static final String USER_SERVICE_CMD_FORMAT = "(CLASSPATH='%s' %s%s%s /system/bin " + "--nice-name='%s' %s "
            + "--token='%s' --package='%s' --class='%s' --uid=%d --server-uid=%d --sui-process-group=%d%s)&";

    static {
        int sdk = Build.VERSION.SDK_INT;
        if (sdk >= 30) {
            USER_SERVICE_CMD_DEBUG = "-Xcompiler-option" + " --debuggable" + " -XjdwpProvider:adbconnection"
                    + " -XjdwpOptions:suspend=n,server=y";
        } else if (sdk >= 28) {
            USER_SERVICE_CMD_DEBUG = "-Xcompiler-option" + " --debuggable" + " -XjdwpProvider:internal"
                    + " -XjdwpOptions:transport=dt_android_adb,suspend=n,server=y";
        } else {
            USER_SERVICE_CMD_DEBUG = "-Xcompiler-option" + " --debuggable"
                    + " -agentlib:jdwp=transport=dt_android_adb,suspend=n,server=y";
        }
    }

    private static String dexPath;

    public static void setStartDex(String path) {
        SuiUserServiceManager.dexPath = path;
    }

    @Override
    protected long beginUserServiceCapabilityCreation(int uid, int pid) {
        SuiService service = SuiService.getInstance();
        if (service == null) {
            throw new IllegalStateException("Sui service unavailable");
        }
        return service.beginUserServiceCapabilityCreation(uid, pid);
    }

    @Override
    protected boolean isUserServiceCapabilityCurrent(rikka.shizuku.server.UserServiceRecord record) {
        SuiService service = SuiService.getInstance();
        return service != null && service.isUserServiceCapabilityCurrent(record);
    }

    @Override
    protected boolean finishUserServiceCapabilityCreation(
            rikka.shizuku.server.UserServiceRecord record, Runnable publisher) {
        SuiService service = SuiService.getInstance();
        return service != null && service.finishUserServiceCapabilityCreation(record, publisher);
    }

    @Override
    protected void abortUserServiceCapabilityCreation(rikka.shizuku.server.UserServiceRecord record) {
        SuiService service = SuiService.getInstance();
        if (service != null) {
            service.abortUserServiceCapabilityCreation(record);
        }
    }

    @Override
    protected boolean requiresUserServiceProcessRegistration() {
        return true;
    }

    @Override
    public String getUserServiceStartCmd(
            rikka.shizuku.server.UserServiceRecord record,
            String key,
            String token,
            String packageName,
            String classname,
            String processNameSuffix,
            int callingUid,
            boolean use32Bits,
            boolean debug) {
        String appProcess = "/system/bin/app_process";
        if (use32Bits && new File("/system/bin/app_process32").exists()) {
            appProcess = "/system/bin/app_process32";
        }
        String setsid = new File("/system/bin/setsid").canExecute() ? "/system/bin/setsid " : "";
        String processName = String.format("%s:%s", packageName, processNameSuffix);
        return String.format(
                Locale.ENGLISH,
                USER_SERVICE_CMD_FORMAT,
                dexPath,
                setsid,
                appProcess,
                debug ? (" " + SuiUserServiceManager.USER_SERVICE_CMD_DEBUG) : "",
                processName,
                "rikka.sui.server.userservice.Starter",
                token,
                packageName,
                classname,
                callingUid,
                SuiService.isShellMode() ? 2000 : 0,
                setsid.isEmpty() ? 0 : 1,
                debug ? (" " + "--debug-name=" + processName) : "");
    }
}
