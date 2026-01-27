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

package rikka.sui.manager;

import static rikka.shizuku.ShizukuApiConstants.ATTACH_APPLICATION_API_VERSION;
import static rikka.shizuku.ShizukuApiConstants.ATTACH_APPLICATION_PACKAGE_NAME;
import static rikka.shizuku.ShizukuApiConstants.SERVER_VERSION;
import static rikka.sui.manager.ManagerConstants.LOGGER;

import android.app.ActivityThread;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import android.provider.Telephony;
import android.telephony.TelephonyManager;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import moe.shizuku.server.IShizukuApplication;
import moe.shizuku.server.IShizukuService;
import rikka.sui.resource.SuiApk;
import rikka.sui.server.ServerConstants;
import rikka.sui.shortcut.SuiShortcut;
import rikka.sui.util.BridgeServiceClient;

public class ManagerProcess {

    private static Intent intent;
    private static SuiApk suiApk;

    private static final IShizukuApplication APPLICATION = new IShizukuApplication.Stub() {

        @Override
        public void bindApplication(Bundle data) {}

        @Override
        public void dispatchRequestPermissionResult(int requestCode, Bundle data) {}

        @Override
        public void showPermissionConfirmation(
                int requestUid, int requestPid, String requestPackageName, int requestCode) {
            LOGGER.i(
                    "showPermissionConfirmation: %d %d %s %d", requestUid, requestPid, requestPackageName, requestCode);

            if (suiApk == null) {
                LOGGER.e("Cannot load apk");
                return;
            }

            try {
                suiApk.getSuiRequestPermissionDialogConstructor()
                        .newInstance(
                                ActivityThread.currentActivityThread().getApplication(),
                                suiApk.getResources(),
                                requestUid,
                                requestPid,
                                requestPackageName,
                                requestCode);
            } catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
                LOGGER.e(e, "showPermissionConfirmation");
            }
        }

        @Override
        public boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
            if (code == ServerConstants.BINDER_TRANSACTION_SEND_SHORTCUT_BROADCAST) {
                new android.os.Handler(android.os.Looper.getMainLooper()).post(() -> {
                    try {
                        Context context = ActivityThread.currentActivityThread().getApplication();
                        if (context != null) {
                            LOGGER.i("Sending shortcut creation broadcast...");
                            Intent intent = new Intent("rikka.sui.ACTION_REQUEST_PINNED_SHORTCUT");
                            intent.setPackage("com.android.settings");
                            context.sendBroadcast(intent);
                        }
                    } catch (Throwable e) {
                        LOGGER.e(e, "Failed to send shortcut creation broadcast");
                    }
                });
                return true;
            }
            return super.onTransact(code, data, reply, flags);
        }
    };

    private static void showManagement() {
        Context context;
        try {
            context = ActivityThread.currentActivityThread().getApplication();
            if (intent == null) {
                intent = SuiShortcut.getIntent(context, true);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            }
            context.startActivity(intent);
        } catch (Throwable e) {
            LOGGER.w(e, "showManagement");
        }
    }

    private static final BroadcastReceiver SHOW_MANAGEMENT_RECEIVER = new BroadcastReceiver() {

        @Override
        public void onReceive(Context context, Intent intent) {
            LOGGER.i("showManagement: action=%s", intent != null ? intent.getAction() : "(null)");
            showManagement();
        }
    };

    private static void sendToService() {
        IShizukuService service = BridgeServiceClient.getService();
        if (service == null) {
            LOGGER.w("service is null, wait 1s");
            WorkerHandler.get().postDelayed(ManagerProcess::sendToService, 1000);
            return;
        }

        Bundle args = new Bundle();
        args.putString(ATTACH_APPLICATION_PACKAGE_NAME, "com.android.systemui");
        args.putInt(ATTACH_APPLICATION_API_VERSION, SERVER_VERSION);

        try {
            service.attachApplication(APPLICATION, args);
            LOGGER.i("attachApplication");
        } catch (RemoteException e) {
            LOGGER.w(e, "attachApplication");
            WorkerHandler.get().postDelayed(ManagerProcess::sendToService, 1000);
        }

        suiApk = SuiApk.createForSystemUI();
    }

    private static void registerListener() {
        Context context = null;
        try {
            context = ActivityThread.currentActivityThread().getApplication();
        } catch (Throwable e) {
            LOGGER.w(e, "getApplication");
        }

        if (context == null) {
            LOGGER.w("application is null, wait 1s");
            WorkerHandler.get().postDelayed(ManagerProcess::registerListener, 1000);
            return;
        }

        WorkerHandler.get().post(ManagerProcess::sendToService);

        IntentFilter intentFilter = new IntentFilter();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            intentFilter.addAction(TelephonyManager.ACTION_SECRET_CODE);
        } else {
            intentFilter.addAction(Telephony.Sms.Intents.SECRET_CODE_ACTION);
        }
        intentFilter.addDataAuthority("784784", null);
        intentFilter.addDataScheme("android_secret_code");

        try {
            context.registerReceiver(
                    SHOW_MANAGEMENT_RECEIVER, intentFilter, "android.permission.CONTROL_INCALL_EXPERIENCE", null);
            LOGGER.i("registerReceiver android.provider.Telephony.SECRET_CODE");
        } catch (Exception e) {
            LOGGER.w(e, "registerReceiver android.provider.Telephony.SECRET_CODE");
        }
    }

    public static void main(String[] args) {
        LOGGER.d("main: %s", Arrays.toString(args));
        WorkerHandler.get().postDelayed(ManagerProcess::registerListener, 5000);
    }
}
