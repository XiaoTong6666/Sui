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

package rikka.sui.server.userservice;

import static rikka.shizuku.ShizukuApiConstants.USER_SERVICE_ARG_TOKEN;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.ServiceManager;
import android.util.Log;
import android.util.Pair;
import moe.shizuku.server.IShizukuService;
import rikka.shizuku.server.UserService;
import rikka.sui.server.ServerConstants;
import rikka.sui.util.BridgeConstants;

public class Starter {

    private static final String TAG = "SuiUserServiceStarter";

    private static int parseServerUid(String[] args) {
        for (String arg : args) {
            if (arg.startsWith("--server-uid=")) {
                try {
                    int uid = Integer.parseInt(arg.substring(13));
                    if (uid == BridgeConstants.SERVER_UID_ROOT || uid == BridgeConstants.SERVER_UID_SHELL) {
                        return uid;
                    }
                    Log.w(TAG, "Unsupported --server-uid=" + uid);
                    return -1;
                } catch (NumberFormatException e) {
                    Log.w(TAG, "Invalid --server-uid argument", e);
                    return -1;
                }
            }
        }
        return -1;
    }

    private static String parseToken(String[] args) {
        for (String arg : args) {
            if (arg.startsWith("--token=")) {
                return arg.substring(8);
            }
        }
        return null;
    }

    public static void main(String[] args) {
        if (Looper.myLooper() == null) {
            if (Looper.getMainLooper() == null) {
                prepareMainLooper();
            } else {
                Looper.prepare();
            }
        }

        IBinder service;
        String token = parseToken(args);
        int serverUid = parseServerUid(args);

        if (token == null || serverUid == -1) {
            Log.e(TAG, "Missing token or server uid");
            System.exit(1);
            return;
        }

        IBinder serverBinder = requestBinderFromBridge(serverUid);
        if (serverBinder == null || !registerProcess(serverBinder, token)) {
            Log.e(TAG, "Unable to register user-service process before loading app code");
            System.exit(1);
            return;
        }

        UserService.setTag(TAG);
        Pair<IBinder, String> result = UserService.create(args);

        if (result == null) {
            System.exit(1);
            return;
        }

        service = result.first;
        if (!token.equals(result.second)) {
            Log.e(TAG, "User-service token changed unexpectedly");
            System.exit(1);
            return;
        }

        if (!sendBinder(service, token, serverBinder)) {
            System.exit(1);
        }

        Looper.loop();
        System.exit(0);

        Log.i(TAG, "service exited");
    }

    @SuppressWarnings("deprecation")
    private static void prepareMainLooper() {
        Looper.prepareMainLooper();
    }

    private static IBinder requestBinderFromBridge(int serverUid) {
        IBinder binder = ServiceManager.getService(BridgeConstants.SERVICE_NAME);
        if (binder == null) return null;

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(BridgeConstants.SERVICE_DESCRIPTOR);
            data.writeInt(BridgeConstants.ACTION_GET_BINDER);
            if (serverUid == BridgeConstants.SERVER_UID_ROOT || serverUid == BridgeConstants.SERVER_UID_SHELL) {
                data.writeInt(serverUid);
            }
            binder.transact(BridgeConstants.TRANSACTION_CODE, data, reply, 0);
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

    private static boolean registerProcess(IBinder serverBinder, String token) {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(rikka.shizuku.ShizukuApiConstants.BINDER_DESCRIPTOR);
            data.writeString(token);
            if (!serverBinder.transact(ServerConstants.BINDER_TRANSACTION_registerUserServiceProcess, data, reply, 0)) {
                return false;
            }
            reply.readException();
            return reply.readInt() != 0;
        } catch (Throwable e) {
            Log.w(TAG, "Failed to register user-service process", e);
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private static boolean sendBinder(IBinder binder, String token, IBinder serverBinder) {
        IShizukuService shizukuService = IShizukuService.Stub.asInterface(serverBinder);
        if (shizukuService == null) {
            return false;
        }

        Bundle data = new Bundle();
        data.putString(USER_SERVICE_ARG_TOKEN, token);
        try {
            shizukuService.attachUserService(binder, data);
        } catch (Throwable e) {
            Log.w(TAG, Log.getStackTraceString(e));
            return false;
        }
        return true;
    }
}
