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
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.os.ServiceManager;
import androidx.annotation.Nullable;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.ShizukuApiConstants;
import rikka.sui.server.ServerConstants;

public class BridgeServiceClient {

    private static IBinder binder;
    private static IShizukuService service;

    private static final int BRIDGE_TRANSACTION_CODE = ('_' << 24) | ('S' << 16) | ('U' << 8) | 'I';
    private static final String BRIDGE_SERVICE_DESCRIPTOR = "android.app.IActivityManager";
    private static final String BRIDGE_SERVICE_NAME = "activity";
    private static final int BRIDGE_ACTION_GET_BINDER = 2;

    private static final IBinder.DeathRecipient DEATH_RECIPIENT = () -> {
        binder = null;
        service = null;
    };

    private static IBinder requestBinderFromBridge() {
        IBinder binder = ServiceManager.getService(BRIDGE_SERVICE_NAME);
        if (binder == null) return null;

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(BRIDGE_SERVICE_DESCRIPTOR);
            data.writeInt(BRIDGE_ACTION_GET_BINDER);
            binder.transact(BRIDGE_TRANSACTION_CODE, data, reply, 0);
            reply.readException();
            IBinder received = reply.readStrongBinder();
            if (received != null) {
                return received;
            }
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            data.recycle();
            reply.recycle();
        }
        return null;
    }

    protected static void setBinder(@Nullable IBinder binder) {
        if (BridgeServiceClient.binder == binder) return;

        if (BridgeServiceClient.binder != null) {
            BridgeServiceClient.binder.unlinkToDeath(DEATH_RECIPIENT, 0);
        }

        if (binder == null) {
            BridgeServiceClient.binder = null;
            BridgeServiceClient.service = null;
        } else {
            BridgeServiceClient.binder = binder;
            BridgeServiceClient.service = IShizukuService.Stub.asInterface(binder);

            try {
                BridgeServiceClient.binder.linkToDeath(DEATH_RECIPIENT, 0);
            } catch (Throwable ignored) {
            }
        }
    }

    public static IShizukuService getService() {
        if (service == null) {
            setBinder(requestBinderFromBridge());
        }
        return service;
    }

    public static ParcelFileDescriptor openApk() {
        ParcelFileDescriptor result;

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken("moe.shizuku.server.IShizukuService");
            try {
                getService().asBinder().transact(ServerConstants.BINDER_TRANSACTION_openApk, data, reply, 0);
            } catch (Throwable e) {
                throw new RuntimeException(e);
            }
            reply.readException();
            if (reply.readInt() != 0) {
                result = ParcelFileDescriptor.CREATOR.createFromParcel(reply);
            } else {
                result = null;
            }
        } finally {
            data.recycle();
            reply.recycle();
        }
        return result;
    }

    public static void requestPinnedShortcut() throws RemoteException {
        IShizukuService service = getService();
        if (service == null) {
            throw new RemoteException("Sui service is not available.");
        }
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(ShizukuApiConstants.BINDER_DESCRIPTOR);
            service.asBinder()
                    .transact(ServerConstants.BINDER_TRANSACTION_REQUEST_PINNED_SHORTCUT_FROM_UI, data, reply, 0);
            reply.readException();
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
}
