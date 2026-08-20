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
import rikka.shizuku.ShizukuApiConstants;
import rikka.sui.model.AppInfo;

public class BridgeServiceClient {

    public static final int FLAG_SHOW_ONLY_SHIZUKU_APPS = 1 << 0;
    public static final int FLAG_MONET_DISABLED = 1 << 1;
    public static final int FLAG_LEGACY_SHIZUKU_BINDER_COMPAT = 1 << 2;

    private static final int BINDER_TRANSACTION_getApplications = 10001;
    private static final int BINDER_TRANSACTION_REQUEST_PINNED_SHORTCUT_FROM_UI = 10005;
    private static final int BINDER_TRANSACTION_BATCH_UPDATE_UNCONFIGURED = 10006;
    private static final int BINDER_TRANSACTION_setGlobalSettings = 10007;
    private static final int BINDER_TRANSACTION_getGlobalSettings = 10008;
    private static final int RETRY_MAX = 5;
    private static final long RETRY_DELAY_MS = 1000;
    private static IBinder binder;
    private static IShizukuService service;

    @Nullable public static Integer getGlobalSettingsOrNull() {
        android.util.Log.d("SuiBridgeDebug", "Fetching global settings via BINDER_TRANSACTION_getGlobalSettings.");
        IShizukuService s = getService();
        if (s == null) {
            android.util.Log.e("SuiBridgeDebug", "Service is null when fetching global settings.");
            return null;
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken("moe.shizuku.server.IShizukuService");
            s.asBinder().transact(BINDER_TRANSACTION_getGlobalSettings, data, reply, 0);
            reply.readException();
            int flags = reply.readInt();
            android.util.Log.i("SuiBridgeDebug", "Successfully fetched global settings flags: " + flags);
            return flags;
        } catch (RemoteException e) {
            android.util.Log.e("SuiBridgeDebug", "RemoteException when calling getGlobalSettings via binder", e);
            return null;
        } catch (Throwable e) {
            android.util.Log.e("SuiBridgeDebug", "Exception when calling getGlobalSettings via binder", e);
            return null;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    public static int getGlobalSettings() {
        Integer flags = getGlobalSettingsOrNull();
        return flags != null ? flags : 0;
    }

    public static boolean setGlobalSettings(int flags) {
        android.util.Log.d(
                "SuiBridgeDebug", "Setting global settings via BINDER_TRANSACTION_setGlobalSettings. Flags = " + flags);
        IShizukuService s = getService();
        if (s == null) {
            android.util.Log.e("SuiBridgeDebug", "Service is null when setting global settings.");
            return false;
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken("moe.shizuku.server.IShizukuService");
            data.writeInt(flags);
            s.asBinder().transact(BINDER_TRANSACTION_setGlobalSettings, data, reply, 0);
            reply.readException();
            android.util.Log.i("SuiBridgeDebug", "Successfully set global settings flags: " + flags);
            return true;
        } catch (RemoteException e) {
            android.util.Log.e("SuiBridgeDebug", "RemoteException when calling setGlobalSettings via binder", e);
            return false;
        } catch (Throwable e) {
            android.util.Log.e("SuiBridgeDebug", "Exception when calling setGlobalSettings via binder", e);
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

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
            IBinder activityBinder = ServiceManager.getService(BridgeConstants.SERVICE_NAME);

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
                    data.writeInterfaceToken(BridgeConstants.SERVICE_DESCRIPTOR);
                    data.writeInt(BridgeConstants.ACTION_GET_BINDER);

                    android.util.Log.d(TAG, "Executing binder.transact with custom code...");
                    activityBinder.transact(BridgeConstants.TRANSACTION_CODE, data, reply, 0);
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
    public static List<AppInfo> getApplications(int userId, boolean onlyShizuku) {
        int retryCount = 0;
        long retryDelay = 500;
        while (retryCount < 3) {
            IShizukuService s = getService();
            if (s == null) {
                android.util.Log.e("SuiBridgeDebug", "getApplications: Service is null! (Retry " + retryCount + ")");
                try {
                    Thread.sleep(retryDelay);
                    retryDelay *= 2;
                } catch (InterruptedException ie) {
                    android.util.Log.w("SuiBridgeDebug", "Retry sleep interrupted");
                    Thread.currentThread().interrupt();
                    return Collections.emptyList();
                }
                retryCount++;
                continue;
            }

            Parcel data = Parcel.obtain();
            Parcel reply = Parcel.obtain();
            List<AppInfo> result;
            try {
                data.writeInterfaceToken("moe.shizuku.server.IShizukuService");
                data.writeInt(userId);
                data.writeInt(onlyShizuku ? 1 : 0);
                try {
                    s.asBinder().transact(BINDER_TRANSACTION_getApplications, data, reply, 0);
                } catch (android.os.DeadObjectException e) {
                    android.util.Log.w(
                            "SuiBridgeDebug",
                            "DeadObjectException explicitly caught in getApplications. Invalidating binder and retrying...",
                            e);
                    setBinder(null);
                    try {
                        Thread.sleep(retryDelay);
                        retryDelay *= 2;
                    } catch (InterruptedException ie) {
                        android.util.Log.w("SuiBridgeDebug", "Retry sleep interrupted");
                        Thread.currentThread().interrupt();
                        return Collections.emptyList();
                    }
                    retryCount++;
                    continue;
                } catch (android.os.TransactionTooLargeException e) {
                    android.util.Log.e(
                            "SuiBridgeDebug",
                            "TransactionTooLargeException in getApplications. The list is too big.",
                            e);
                    return Collections.emptyList();
                } catch (Throwable e) {
                    throw new RuntimeException(e);
                }
                reply.readException();
                if ((0 != reply.readInt())) {
                    result = ParcelableListSlice.CREATOR.createFromParcel(reply).getList();
                } else {
                    result = null;
                }
                return result;
            } finally {
                reply.recycle();
                data.recycle();
            }
        }
        android.util.Log.e("SuiBridgeDebug", "getApplications failed after max retries.");
        return Collections.emptyList();
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
            data.writeInterfaceToken(ShizukuApiConstants.BINDER_DESCRIPTOR);
            data.writeInt(targetMode);

            s.asBinder().transact(BINDER_TRANSACTION_BATCH_UPDATE_UNCONFIGURED, data, reply, 0);

            reply.readException();
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
}
