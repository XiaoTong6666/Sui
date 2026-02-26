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

package rikka.sui.settings;

import static rikka.sui.settings.SettingsConstants.LOGGER;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.app.ActivityThread;
import android.app.Application;
import android.app.Instrumentation;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.UserManager;
import android.util.Log;
import androidx.annotation.NonNull;
import java.util.Arrays;
import rikka.sui.resource.SuiApk;
import rikka.sui.shortcut.SuiShortcut;

public class SettingsProcess {

    private static boolean reflection = false;
    private static Handler handler;
    private static HandlerThread handlerThread;

    private static String getOrGenerateToken(Context context) {
        android.content.SharedPreferences prefs = context.getSharedPreferences("sui_settings", Context.MODE_PRIVATE);
        String token = prefs.getString("shortcut_token", null);
        if (token == null) {
            token = java.util.UUID.randomUUID().toString();
            prefs.edit().putString("shortcut_token", token).apply();
            LOGGER.v("Generated and saved secure token");
        }
        return token;
    }

    @TargetApi(Build.VERSION_CODES.O)
    private static void shortcutStuff(Application application, Resources resources) {
        UserManager userManager = application.getSystemService(UserManager.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && !userManager.isUserUnlocked()) {
            LOGGER.v("Not unlocked, wait 5s");
            handler.postDelayed(() -> shortcutStuff(application, resources), 5000);
            return;
        }

        String token = getOrGenerateToken(application);

        boolean hasDynamic;
        try {
            hasDynamic = SuiShortcut.updateExistingShortcuts(application, resources, token);
        } catch (Throwable e) {
            LOGGER.e(e, "updateExistingShortcuts");
            hasDynamic = false;
        }

        if (!hasDynamic) {
            try {
                SuiShortcut.addDynamicShortcut(application, resources, token);
            } catch (Throwable e) {
                LOGGER.e(e, "addDynamicShortcut");
            }
        } else {
            LOGGER.i("Dynamic shortcut exists and up to date");
        }
        handlerThread.quit();
    }

    @android.annotation.SuppressLint("UnspecifiedRegisterReceiverFlag")
    private static void postBindApplication(ActivityThread activityThread) {
        LOGGER.i("postBindApplication: Entered.");
        SuiApk suiApk = SuiApk.createForSettings();
        if (suiApk == null) {
            LOGGER.e("Cannot load apk");
            return;
        }
        LOGGER.d("postBindApplication: SuiApk loaded successfully.");

        Instrumentation instrumentation = ActivityThreadUtil.getInstrumentation(activityThread);
        SettingsInstrumentation newInstrumentation = new SettingsInstrumentation(instrumentation, suiApk);
        ActivityThreadUtil.setInstrumentation(activityThread, newInstrumentation);
        LOGGER.i("postBindApplication: Instrumentation hooked: %s -> %s", instrumentation, newInstrumentation);
        new Handler(Looper.getMainLooper()).post(() -> {
            LOGGER.d("postBindApplication [Delayed]: Starting check for Application object...");

            Application application = activityThread.getApplication();
            if (application == null) {
                LOGGER.e(
                        "postBindApplication [Delayed]: FAILED, Application is still null even after posting to main looper.");
                return;
            }
            LOGGER.d("postBindApplication [Delayed]: SUCCESS, Application object is available now!");

            try {
                BroadcastReceiver shortcutReceiver = new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        if ("rikka.sui.ACTION_REQUEST_PINNED_SHORTCUT".equals(intent.getAction())) {
                            LOGGER.i("Shortcut creation request received via broadcast!");
                            WorkerHandler.get().post(() -> {
                                try {
                                    String token = getOrGenerateToken(application);
                                    SuiShortcut.requestPinnedShortcut(application, suiApk.getResources(), token);
                                } catch (Throwable e) {
                                    LOGGER.e(e, "Failed to create shortcut from broadcast receiver");
                                }
                            });
                        }
                    }
                };
                IntentFilter filter = new IntentFilter();
                filter.addAction("rikka.sui.ACTION_REQUEST_PINNED_SHORTCUT");
                try {
                    if (Build.VERSION.SDK_INT >= 33) {
                        application.registerReceiver(
                                shortcutReceiver,
                                filter,
                                "android.permission.WRITE_SECURE_SETTINGS",
                                null,
                                Context.RECEIVER_EXPORTED);
                    } else {
                        application.registerReceiver(
                                shortcutReceiver, filter, "android.permission.WRITE_SECURE_SETTINGS", null);
                    }
                    LOGGER.i("Shortcut/UI request receiver registered securely");
                } catch (Throwable e) {
                    LOGGER.e(e, "Failed to register receiver securely");
                }
            } catch (Throwable e) {
                LOGGER.e(e, "Failed to setup shortcut creation broadcast receiver.");
            }

            Resources resources = newInstrumentation.getResources();
            if (resources != null) {
                handlerThread = new HandlerThread("Sui");
                handlerThread.start();
                handler = new Handler(handlerThread.getLooper());
                handler.post(() -> shortcutStuff(application, resources));
                LOGGER.d("postBindApplication [Delayed]: shortcutStuff has been posted.");
            }
        });
    }

    @SuppressLint("DiscouragedPrivateApi")
    public static boolean execTransact(@NonNull Binder binder, int code, long dataObj, long replyObj, int flags) {
        if (!reflection) {
            return false;
        }

        String descriptor = binder.getInterfaceDescriptor();

        if (!"android.app.IApplicationThread".equals(descriptor)) {
            return false;
        }

        ActivityThread activityThread = ActivityThread.currentActivityThread();
        if (activityThread == null) {
            LOGGER.w("ActivityThread is null");
            return false;
        }

        Handler handler = ActivityThreadUtil.getH(activityThread);
        int bindApplicationCode = ActivityThreadUtil.getBindApplication();

        Handler.Callback original = HandlerUtil.getCallback(handler);
        HandlerUtil.setCallback(handler, msg -> {
            if (msg.what == bindApplicationCode && ActivityThreadUtil.isAppBindData(msg.obj)) {
                LOGGER.v("call original bindApplication");
                handler.handleMessage(msg);
                LOGGER.v("bindApplication finished");
                postBindApplication(activityThread);
                return true;
            }
            if (original != null) {
                return original.handleMessage(msg);
            }
            return false;
        });

        return false;
    }

    public static void main(String[] args) {
        LOGGER.d("main: %s", Arrays.toString(args));

        try {
            ActivityThreadUtil.init();
            HandlerUtil.init();
            reflection = true;
            LOGGER.d("SettingsProcess.main: Reflection utils initialized successfully.");
        } catch (Throwable e) {
            LOGGER.e(Log.getStackTraceString(e));
        }
    }
}
