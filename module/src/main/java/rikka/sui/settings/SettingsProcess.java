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
import androidx.annotation.RequiresApi;
import java.util.Arrays;
import rikka.sui.resource.SuiApk;
import rikka.sui.shortcut.SuiShortcut;
import rikka.sui.util.BridgeServiceClient;

public class SettingsProcess {

    private static boolean reflection = false;
    private static Handler handler;
    private static HandlerThread handlerThread;

    @RequiresApi(Build.VERSION_CODES.O)
    private static void shortcutStuff(Application application, SettingsInstrumentation instrumentation) {
        Resources resources = instrumentation.getResources();
        if (resources == null) {
            handler.postDelayed(() -> shortcutStuff(application, instrumentation), 5000);
            return;
        }

        UserManager userManager = application.getSystemService(UserManager.class);
        if (!userManager.isUserUnlocked()) {
            LOGGER.v("Not unlocked, wait 5s");
            handler.postDelayed(() -> shortcutStuff(application, instrumentation), 5000);
            return;
        }

        String token = BridgeServiceClient.getShortcutToken();

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

        BridgeServiceClient.prefetchShortcutToken();

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
                                    String token = BridgeServiceClient.getShortcutToken();
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

            try {
                BroadcastReceiver overlayReceiver = new BroadcastReceiver() {
                    @Override
                    public void onReceive(Context context, Intent intent) {
                        if ("android.intent.action.OVERLAY_CHANGED".equals(intent.getAction())) {
                            LOGGER.i("Overlay changed broadcast received! Reloading resources.");
                            try {
                                suiApk.reloadResources();
                            } catch (Exception e) {
                                LOGGER.e(e, "Failed to reload resources upon overlay change");
                            }
                        }
                    }
                };
                IntentFilter overlayFilter = new IntentFilter("android.intent.action.OVERLAY_CHANGED");
                overlayFilter.addDataScheme("package");
                try {
                    if (Build.VERSION.SDK_INT >= 33) {
                        application.registerReceiver(overlayReceiver, overlayFilter, Context.RECEIVER_EXPORTED);
                    } else {
                        application.registerReceiver(overlayReceiver, overlayFilter);
                    }
                    LOGGER.i("Overlay changed receiver registered.");
                } catch (Throwable e) {
                    LOGGER.e(e, "Failed to register overlay receiver");
                }
            } catch (Throwable e) {
                LOGGER.e(e, "Failed to setup overlay changed broadcast receiver.");
            }

            if (newInstrumentation.getResources() != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    handlerThread = new HandlerThread("Sui");
                    handlerThread.start();
                    handler = new Handler(handlerThread.getLooper());
                    handler.post(() -> shortcutStuff(application, newInstrumentation));
                }
                LOGGER.d("postBindApplication [Delayed]: shortcutStuff has been posted.");
            }
        });
    }

    @SuppressLint("DiscouragedPrivateApi")
    public static boolean execTransact(@NonNull Binder binder, int code, long dataObj, long replyObj, int flags) {
        if (!reflection) {
            LOGGER.w("execTransact: reflection is not initialized, code=%d", code);
            return false;
        }

        String descriptor = binder.getInterfaceDescriptor();
        LOGGER.i("execTransact: code=%d flags=%d descriptor=%s", code, flags, descriptor);

        if (!"android.app.IApplicationThread".equals(descriptor)) {
            LOGGER.w("execTransact: unexpected descriptor=%s", descriptor);
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
        Handler.Callback callback = msg -> {
            if (msg.what == bindApplicationCode) {
                boolean isBindData = ActivityThreadUtil.isAppBindData(msg.obj);
                LOGGER.i("bindApplication message received: what=%d isAppBindData=%s", msg.what, isBindData);
                if (!isBindData) {
                    if (original != null) {
                        return original.handleMessage(msg);
                    }
                    return false;
                }

                LOGGER.i("call original bindApplication");
                handler.handleMessage(msg);
                LOGGER.i("bindApplication finished");
                postBindApplication(activityThread);
                return true;
            }
            if (original != null) {
                return original.handleMessage(msg);
            }
            return false;
        };
        HandlerUtil.setCallback(handler, callback);
        LOGGER.i(
                "execTransact: installed bindApplication callback, expected=%d installed=%s",
                bindApplicationCode, HandlerUtil.getCallback(handler) == callback);

        return false;
    }

    public static void main(String[] args) {
        LOGGER.d("main: %s", Arrays.toString(args));

        try {
            ActivityThreadUtil.init();
            HandlerUtil.init();
            reflection = true;
            LOGGER.i(
                    "SettingsProcess.main: Reflection utils initialized successfully, bindApplicationCode=%d",
                    ActivityThreadUtil.getBindApplication());
        } catch (Throwable e) {
            LOGGER.e(Log.getStackTraceString(e));
        }
    }
}
