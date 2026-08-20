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

package rikka.sui.systemserver;

import static rikka.sui.systemserver.SystemServerConstants.LOGGER;

import android.os.Binder;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import moe.shizuku.server.IShizukuService;
import rikka.sui.server.SuiConfig;
import rikka.sui.util.BridgeConstants;

public class BridgeService {

    private static final int RETRY_MAX = 3;
    private static final long RETRY_DELAY_MS = 1000;

    private static final IBinder.DeathRecipient DEATH_RECIPIENT_ROOT = () -> {
        rootServiceBinder = null;
        rootService = null;
        serviceStarted = false;
        LOGGER.i("root service is dead");
    };
    private static final IBinder.DeathRecipient DEATH_RECIPIENT_SHELL = () -> {
        shellServiceBinder = null;
        shellService = null;
        LOGGER.i("shell service is dead");
    };

    private static volatile IBinder rootServiceBinder;
    private static IShizukuService rootService;
    private static volatile IBinder shellServiceBinder;
    private static IShizukuService shellService;
    private static volatile boolean serviceStarted;

    public static IShizukuService get() {
        return rootService;
    }

    public static IShizukuService getShell() {
        return shellService;
    }

    public static boolean isServiceStarted() {
        return serviceStarted;
    }

    private void sendBinder(IBinder binder, boolean isRoot) {
        if (binder == null) {
            LOGGER.w("received empty binder");
            return;
        }

        try {
            if (isRoot) {
                if (rootServiceBinder == null) {
                    PackageReceiver.register();
                } else {
                    rootServiceBinder.unlinkToDeath(DEATH_RECIPIENT_ROOT, 0);
                }
            } else {
                if (shellServiceBinder != null) {
                    shellServiceBinder.unlinkToDeath(DEATH_RECIPIENT_SHELL, 0);
                }
            }
        } catch (Throwable e) {
            LOGGER.w(e, "Error during receiver registration or unlink");
        }

        if (isRoot) {
            rootServiceBinder = binder;
            rootService = IShizukuService.Stub.asInterface(rootServiceBinder);
            try {
                rootServiceBinder.linkToDeath(DEATH_RECIPIENT_ROOT, 0);
            } catch (RemoteException ignored) {
            }
            LOGGER.i("root binder received");
        } else {
            shellServiceBinder = binder;
            shellService = IShizukuService.Stub.asInterface(shellServiceBinder);
            try {
                shellServiceBinder.linkToDeath(DEATH_RECIPIENT_SHELL, 0);
            } catch (RemoteException ignored) {
            }
            LOGGER.i("shell binder received");
        }
    }

    public boolean isServiceTransaction(int code) {
        return code == BridgeConstants.TRANSACTION_CODE;
    }

    @Nullable public static IBinder getBinderForUid(int uid) {
        int permissionFlags = Bridge.getPermissionFlags(uid);
        if ((permissionFlags & SuiConfig.FLAG_HIDDEN) != 0) {
            return null;
        }
        if ((permissionFlags & SuiConfig.FLAG_ALLOWED) != 0) {
            return rootServiceBinder;
        }
        if ((permissionFlags & SuiConfig.FLAG_ALLOWED_SHELL) != 0) {
            return shellServiceBinder;
        }
        // Ask and deny both need the root service for their normal result flows.
        return rootServiceBinder;
    }

    public boolean onTransact(int code, @NonNull Parcel data, @Nullable Parcel reply, int flags) {
        data.enforceInterface(BridgeConstants.SERVICE_DESCRIPTOR);

        int action = data.readInt();
        LOGGER.d(
                "onTransact: action=%d, callingUid=%d, callingPid=%d",
                action, Binder.getCallingUid(), Binder.getCallingPid());

        switch (action) {
            case BridgeConstants.ACTION_SEND_BINDER: {
                int callingUid = Binder.getCallingUid();
                if (callingUid == 0 || callingUid == 2000) {
                    IBinder binder = data.readStrongBinder();
                    long identity = Binder.clearCallingIdentity();
                    try {
                        sendBinder(binder, callingUid == 0);
                    } finally {
                        Binder.restoreCallingIdentity(identity);
                    }
                    if (reply != null) {
                        reply.writeNoException();
                    }
                    return true;
                }
                break;
            }
            case BridgeConstants.ACTION_GET_BINDER: {
                int callingUid = Binder.getCallingUid();
                int targetUid = callingUid;
                Integer requestedServerUid = null;
                if ((callingUid == 0 || callingUid == 2000) && data.dataAvail() >= Integer.BYTES) {
                    int value = data.readInt();
                    if (value == BridgeConstants.SERVER_UID_ROOT || value == BridgeConstants.SERVER_UID_SHELL) {
                        requestedServerUid = value;
                    }
                }

                int permissionFlags = Bridge.getPermissionFlags(targetUid);

                if (requestedServerUid == null && (permissionFlags & SuiConfig.FLAG_HIDDEN) != 0) {
                    return false;
                }

                // Wait for the requested binder to be available
                IBinder requestedBinder = null;
                for (int i = 0; i < RETRY_MAX; i++) {
                    if (requestedServerUid != null) {
                        requestedBinder = requestedServerUid == BridgeConstants.SERVER_UID_ROOT
                                ? rootServiceBinder
                                : shellServiceBinder;
                    } else {
                        requestedBinder = getBinderForUid(targetUid);
                    }

                    if (requestedBinder != null) break;

                    try {
                        LOGGER.w("binder missing, wait %d ms (try %d/%d)", RETRY_DELAY_MS, i + 1, RETRY_MAX);
                        Thread.sleep(RETRY_DELAY_MS);
                    } catch (InterruptedException ignored) {
                    }
                }

                LOGGER.d(
                        "getBinder: callingUid=%d, targetUid=%d, requestedServer=%s, selected=%s",
                        callingUid,
                        targetUid,
                        requestedServerUid == null
                                ? "auto"
                                : (requestedServerUid == BridgeConstants.SERVER_UID_ROOT ? "root" : "shell"),
                        requestedBinder == rootServiceBinder
                                ? "root"
                                : requestedBinder == shellServiceBinder ? "shell" : "null");

                if (reply != null) {
                    reply.writeNoException();
                    LOGGER.d("saved binder is %s", requestedBinder);
                    reply.writeStrongBinder(requestedBinder);
                }
                return true;
            }
            case BridgeConstants.ACTION_NOTIFY_FINISHED: {
                if (Binder.getCallingUid() == 0) {
                    serviceStarted = true;

                    if (reply != null) {
                        reply.writeNoException();
                    }
                    return true;
                }
                break;
            }
            case BridgeConstants.ACTION_SYNC_UIDS: {
                if (Binder.getCallingUid() == 0) {
                    int[] hiddenUids = data.createIntArray();
                    int[] rootUids = data.createIntArray();
                    int[] shellUids = data.createIntArray();
                    int defaultFlags = 0;
                    int[] deniedUids = new int[0];

                    if (data.dataAvail() >= Integer.BYTES) {
                        defaultFlags = data.readInt();
                    }

                    if (data.dataAvail() >= Integer.BYTES) {
                        deniedUids = data.createIntArray();
                    }
                    SystemProcess.updateUids(hiddenUids, rootUids, deniedUids, shellUids, defaultFlags);
                    if (reply != null) {
                        reply.writeNoException();
                    }
                    return true;
                }
                break;
            }
        }
        return false;
    }
}
