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

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.List;
import moe.shizuku.server.IShizukuService;
import rikka.parcelablelist.ParcelableListSlice;
import rikka.sui.model.AppInfo;

public class BridgeServiceClient {

    private static final int BINDER_TRANSACTION_getApplications = 10001;
    private static final int BINDER_TRANSACTION_REQUEST_PINNED_SHORTCUT_FROM_UI = 10005;
    private static final int BINDER_TRANSACTION_BATCH_UPDATE_UNCONFIGURED = 10006;
    private static final int RETRY_MAX = 5;
    private static final long RETRY_DELAY_MS = 1000;
    private static IBinder binder;
    private static IShizukuService service;

    private static final int BRIDGE_TRANSACTION_CODE = ('_' << 24) | ('S' << 16) | ('U' << 8) | 'I';
    private static final String BRIDGE_SERVICE_DESCRIPTOR = "android.app.IActivityManager";
    private static final String BRIDGE_SERVICE_NAME = "activity";
    private static final int BRIDGE_ACTION_GET_BINDER = 2;

    private static final IBinder.DeathRecipient DEATH_RECIPIENT = () -> {
        final String TAG = "SuiBridgeDebug";
        android.util.Log.w(TAG, "Bridge binder died. Resetting connection.");
        synchronized (BridgeServiceClient.class) {
            binder = null;
            service = null;
        }
    };

    private static IBinder requestBinderFromBridge() {
        final String TAG = "SuiBridgeDebug";

        android.util.Log.d(TAG, "Attempting to request binder from bridge...");

        for (int i = 0; i < RETRY_MAX; i++) {
            IBinder activityBinder = ServiceManager.getService(BRIDGE_SERVICE_NAME);

            if (activityBinder == null) {
                android.util.Log.e(
                        TAG,
                        "CRITICAL FAILURE: ServiceManager.getService(\"activity\") returned null! Retry count: "
                                + (i + 1));
            } else {
                android.util.Log.d(TAG, "'activity' service binder obtained. Preparing custom transact...");

                Parcel data = Parcel.obtain();
                Parcel reply = Parcel.obtain();
                try {
                    data.writeInterfaceToken(BRIDGE_SERVICE_DESCRIPTOR);
                    data.writeInt(BRIDGE_ACTION_GET_BINDER);

                    android.util.Log.d(TAG, "Executing binder.transact with custom code...");
                    activityBinder.transact(BRIDGE_TRANSACTION_CODE, data, reply, 0);
                    android.util.Log.d(TAG, "Transact call has returned. Reading reply...");

                    reply.readException();
                    android.util.Log.d(TAG, "readException() completed without throwing an exception.");

                    IBinder received = reply.readStrongBinder();
                    if (received != null) {
                        android.util.Log.i(TAG, "SUCCESS! Received a non-null binder from the bridge.");
                        return received;
                    } else {
                        android.util.Log.w(
                                TAG,
                                "FAILURE: Transact was successful, but the returned binder is NULL. The bridge likely rejected the request (or not ready). Retry count: "
                                        + (i + 1));
                    }
                } catch (Throwable e) {
                    android.util.Log.e(
                            TAG, "FATAL FAILURE: An exception was thrown during the transact/reply process.", e);
                } finally {
                    data.recycle();
                    reply.recycle();
                }
            }

            if (i < RETRY_MAX - 1) {
                try {
                    Thread.sleep(RETRY_DELAY_MS);
                } catch (InterruptedException ignored) {
                }
            }
        }

        android.util.Log.e(TAG, "requestBinderFromBridge is returning NULL after all retries.");
        return null;
    }

    protected static synchronized void setBinder(@Nullable IBinder newBinder) {
        if (binder == newBinder) return;

        if (binder != null) {
            try {
                binder.unlinkToDeath(DEATH_RECIPIENT, 0);
            } catch (Throwable ignored) {
            }
        }

        binder = newBinder;
        if (newBinder != null) {
            service = IShizukuService.Stub.asInterface(newBinder);
            try {
                binder.linkToDeath(DEATH_RECIPIENT, 0);
            } catch (Throwable ignored) {
            }
        } else {
            service = null;
        }
    }

    public static synchronized IShizukuService getService() {
        if (service == null || binder == null || !binder.isBinderAlive()) {
            setBinder(requestBinderFromBridge());
        }
        return service;
    }

    @SuppressWarnings("unchecked")
    public static List<AppInfo> getApplications(int userId) {
        IShizukuService s = getService();
        if (s == null) {
            android.util.Log.e("SuiBridgeDebug", "getApplications: Service is null! Returning empty list.");
            return Collections.emptyList();
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        List<AppInfo> result;
        try {
            data.writeInterfaceToken("moe.shizuku.server.IShizukuService");
            data.writeInt(userId);
            try {
                s.asBinder().transact(BINDER_TRANSACTION_getApplications, data, reply, 0);
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
            reply.readException();
            if ((0 != reply.readInt())) {
                //noinspection unchecked
                result = ParcelableListSlice.CREATOR.createFromParcel(reply).getList();
            } else {
                result = null;
            }
        } finally {
            reply.recycle();
            data.recycle();
        }
        return result;
    }

    public static void requestPinnedShortcut() throws RemoteException {
        IShizukuService s = getService();
        if (s == null) {
            throw new RemoteException("Sui service is not available.");
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken("moe.shizuku.server.IShizukuService");
            s.asBinder().transact(BINDER_TRANSACTION_REQUEST_PINNED_SHORTCUT_FROM_UI, data, reply, 0);
            reply.readException();
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static void batchUpdateUnconfigured(int targetMode) throws RemoteException {
        IShizukuService s = getService();
        if (s == null) {
            throw new RemoteException("Sui service is not available.");
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(rikka.shizuku.ShizukuApiConstants.BINDER_DESCRIPTOR);
            data.writeInt(targetMode);

            s.asBinder().transact(BINDER_TRANSACTION_BATCH_UPDATE_UNCONFIGURED, data, reply, 0);

            reply.readException();
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
}
