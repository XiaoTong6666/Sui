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

package rikka.sui.util;

/**
 * Sui-owned logging facade shared by the module and UI Gradle source sets.
 * The shared Shizuku API intentionally keeps its original android.util.Log tags.
 */
public final class Log {

    public static final int VERBOSE = android.util.Log.VERBOSE;
    public static final int DEBUG = android.util.Log.DEBUG;
    public static final int INFO = android.util.Log.INFO;
    public static final int WARN = android.util.Log.WARN;
    public static final int ERROR = android.util.Log.ERROR;

    private Log() {}

    private static String component(String tag) {
        if (tag == null || tag.isEmpty()) {
            return "Unknown";
        }
        if ("Sui".equals(tag)) {
            return "App";
        }
        return tag.startsWith("Sui") ? tag.substring(3) : tag;
    }

    public static int println(int priority, String component, String message) {
        return android.util.Log.println(priority, "Sui", "[" + component(component) + "] " + message);
    }

    public static String getStackTraceString(Throwable throwable) {
        return android.util.Log.getStackTraceString(throwable);
    }

    private static int withThrowable(int priority, String tag, String msg, Throwable tr) {
        return println(priority, tag, msg + '\n' + getStackTraceString(tr));
    }

    public static int v(String tag, String msg) {
        return println(VERBOSE, tag, msg);
    }

    public static int d(String tag, String msg) {
        return println(DEBUG, tag, msg);
    }

    public static int i(String tag, String msg) {
        return println(INFO, tag, msg);
    }

    public static int w(String tag, String msg) {
        return println(WARN, tag, msg);
    }

    public static int w(String tag, String msg, Throwable tr) {
        return withThrowable(WARN, tag, msg, tr);
    }

    public static int e(String tag, String msg) {
        return println(ERROR, tag, msg);
    }

    public static int e(String tag, String msg, Throwable tr) {
        return withThrowable(ERROR, tag, msg, tr);
    }
}
