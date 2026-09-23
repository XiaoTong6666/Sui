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

import android.util.Log;
import java.util.Locale;

public class Logger {

    private final String TAG;

    public Logger(String TAG) {
        this.TAG = TAG;
    }

    public boolean isLoggable(String tag, int level) {
        return true;
    }

    public void v(String msg) {
        if (isLoggable(TAG, Log.VERBOSE)) {
            println(Log.VERBOSE, msg);
        }
    }

    public void v(String fmt, Object... args) {
        if (isLoggable(TAG, Log.VERBOSE)) {
            println(Log.VERBOSE, String.format(Locale.ENGLISH, fmt, args));
        }
    }

    public void v(String msg, Throwable tr) {
        if (isLoggable(TAG, Log.VERBOSE)) {
            println(Log.VERBOSE, msg + '\n' + Log.getStackTraceString(tr));
        }
    }

    public void d(String msg) {
        if (isLoggable(TAG, Log.DEBUG)) {
            println(Log.DEBUG, msg);
        }
    }

    public void d(String fmt, Object... args) {
        if (isLoggable(TAG, Log.DEBUG)) {
            println(Log.DEBUG, String.format(Locale.ENGLISH, fmt, args));
        }
    }

    public void d(String msg, Throwable tr) {
        if (isLoggable(TAG, Log.DEBUG)) {
            println(Log.DEBUG, msg + '\n' + Log.getStackTraceString(tr));
        }
    }

    public void i(String msg) {
        if (isLoggable(TAG, Log.INFO)) {
            println(Log.INFO, msg);
        }
    }

    public void i(String fmt, Object... args) {
        if (isLoggable(TAG, Log.INFO)) {
            println(Log.INFO, String.format(Locale.ENGLISH, fmt, args));
        }
    }

    public void i(String msg, Throwable tr) {
        if (isLoggable(TAG, Log.INFO)) {
            println(Log.INFO, msg + '\n' + Log.getStackTraceString(tr));
        }
    }

    public void w(String msg) {
        if (isLoggable(TAG, Log.WARN)) {
            println(Log.WARN, msg);
        }
    }

    public void w(String fmt, Object... args) {
        if (isLoggable(TAG, Log.WARN)) {
            println(Log.WARN, String.format(Locale.ENGLISH, fmt, args));
        }
    }

    public void w(Throwable tr, String fmt, Object... args) {
        if (isLoggable(TAG, Log.WARN)) {
            println(Log.WARN, String.format(Locale.ENGLISH, fmt, args) + '\n' + Log.getStackTraceString(tr));
        }
    }

    public void w(String msg, Throwable tr) {
        if (isLoggable(TAG, Log.WARN)) {
            println(Log.WARN, msg + '\n' + Log.getStackTraceString(tr));
        }
    }

    public void e(String msg) {
        if (isLoggable(TAG, Log.ERROR)) {
            println(Log.ERROR, msg);
        }
    }

    public void e(String fmt, Object... args) {
        if (isLoggable(TAG, Log.ERROR)) {
            println(Log.ERROR, String.format(Locale.ENGLISH, fmt, args));
        }
    }

    public void e(String msg, Throwable tr) {
        if (isLoggable(TAG, Log.ERROR)) {
            println(Log.ERROR, msg + '\n' + Log.getStackTraceString(tr));
        }
    }

    public void e(Throwable tr, String fmt, Object... args) {
        if (isLoggable(TAG, Log.ERROR)) {
            println(Log.ERROR, String.format(Locale.ENGLISH, fmt, args) + '\n' + Log.getStackTraceString(tr));
        }
    }

    public int println(int priority, String msg) {
        return Log.println(priority, TAG, msg);
    }
}
