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
 * Copyright (c) 2026 Sui Contributors
 */

package rikka.sui.systemserver;

import static rikka.sui.systemserver.SystemServerConstants.LOGGER;

import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import androidx.annotation.Nullable;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import moe.shizuku.server.IShizukuService;
import rikka.hidden.compat.PackageManagerApis;
import rikka.shizuku.ShizukuApiConstants;
import rikka.sui.server.ServerConstants;

final class LegacyShizukuBinderCompat {

    private static final String ACTIVITY_MANAGER_DESCRIPTOR = "android.app.IActivityManager";
    private static final String REQUEST_BINDER_ACTION = "rikka.shizuku.intent.action.REQUEST_BINDER";
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";
    private static final String EXTRA_DATA = "data";
    private static final String EXTRA_BINDER = "binder";
    private static final int CALLBACK_TRANSACTION = 1;
    private static final int FLAG_LEGACY_SHIZUKU_BINDER_COMPAT = 1 << 2;

    private static final int broadcastIntentTransaction = findTransaction("TRANSACTION_broadcastIntent");
    private static final int broadcastIntentWithFeatureTransaction =
            findTransaction("TRANSACTION_broadcastIntentWithFeature");
    private static final int broadcastIntentStringArgumentCount = findIntentStringArgumentCount("broadcastIntent");
    private static final int broadcastIntentWithFeatureStringArgumentCount =
            findIntentStringArgumentCount("broadcastIntentWithFeature");

    private LegacyShizukuBinderCompat() {}

    private static int findTransaction(String fieldName) {
        try {
            Class<?> stub = Class.forName("android.app.IActivityManager$Stub");
            Field field = stub.getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.getInt(null);
        } catch (Throwable e) {
            return -1;
        }
    }

    private static int findIntentStringArgumentCount(String methodName) {
        try {
            Class<?> activityManager = Class.forName("android.app.IActivityManager");
            for (Method method : activityManager.getDeclaredMethods()) {
                if (!methodName.equals(method.getName())) {
                    continue;
                }

                Class<?>[] parameterTypes = method.getParameterTypes();
                if (parameterTypes.length == 0 || !parameterTypes[0].isInterface()) {
                    continue;
                }

                int stringArgumentCount = 0;
                for (int i = 1; i < parameterTypes.length; i++) {
                    if (parameterTypes[i] == Intent.class) {
                        return stringArgumentCount;
                    }
                    if (parameterTypes[i] != String.class) {
                        break;
                    }
                    stringArgumentCount++;
                }
            }
        } catch (Throwable e) {
            LOGGER.w(e, "resolve %s signature", methodName);
        }
        return -1;
    }

    static boolean handle(Binder binder, int code, Parcel data, @Nullable Parcel reply) {
        int stringArgumentCount = code == broadcastIntentTransaction
                ? broadcastIntentStringArgumentCount
                : code == broadcastIntentWithFeatureTransaction ? broadcastIntentWithFeatureStringArgumentCount : -1;
        if (stringArgumentCount == -1) {
            return false;
        }

        int position = data.dataPosition();
        try {
            if (!ACTIVITY_MANAGER_DESCRIPTOR.equals(binder.getInterfaceDescriptor())) {
                return false;
            }

            data.enforceInterface(ACTIVITY_MANAGER_DESCRIPTOR);
            Intent intent = readBroadcastIntent(data, stringArgumentCount);
            if (!isLegacyRequest(intent)) {
                return false;
            }

            int callingUid = Binder.getCallingUid();
            if (!isEnabled() || isShizukuInstalled(callingUid) || SystemProcess.isUidHiddenEffective(callingUid)) {
                return false;
            }

            Bundle extras = intent.getBundleExtra(EXTRA_DATA);
            IBinder callback = extras != null ? extras.getBinder(EXTRA_BINDER) : null;
            if (callback == null) {
                return false;
            }

            IBinder service = BridgeService.getBinderForUid(callingUid);
            if (service == null) {
                return false;
            }

            Parcel callbackData = Parcel.obtain();
            try {
                callbackData.writeStrongBinder(service);
                callbackData.writeString(null);
                if (!callback.transact(CALLBACK_TRANSACTION, callbackData, null, IBinder.FLAG_ONEWAY)) {
                    return false;
                }
            } finally {
                callbackData.recycle();
            }
            if (reply != null) {
                reply.writeNoException();
                reply.writeInt(0);
            }
            LOGGER.i("served legacy Shizuku binder request from uid=%d", callingUid);
            return true;
        } catch (Throwable e) {
            LOGGER.w(e, "legacy Shizuku binder compatibility");
            return false;
        } finally {
            data.setDataPosition(position);
        }
    }

    @Nullable private static Intent readBroadcastIntent(Parcel data, int stringArgumentCount) {
        data.readStrongBinder();
        for (int i = 0; i < stringArgumentCount; i++) {
            data.readString();
        }
        // AIDL writes Intent with a preceding presence marker, including on releases before
        // Parcel.readTypedObject was added to the public API.
        if (data.readInt() == 0) {
            return null;
        }
        return Intent.CREATOR.createFromParcel(data);
    }

    private static boolean isLegacyRequest(@Nullable Intent intent) {
        return intent != null
                && REQUEST_BINDER_ACTION.equals(intent.getAction())
                && SHIZUKU_PACKAGE.equals(intent.getPackage());
    }

    private static boolean isShizukuInstalled(int uid) {
        ApplicationInfo applicationInfo =
                PackageManagerApis.getApplicationInfoNoThrow(SHIZUKU_PACKAGE, 0, uid / 100000);
        return applicationInfo != null && applicationInfo.enabled;
    }

    private static boolean isEnabled() {
        IShizukuService service = BridgeService.get();
        if (service == null) {
            return false;
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(ShizukuApiConstants.BINDER_DESCRIPTOR);
            service.asBinder().transact(ServerConstants.BINDER_TRANSACTION_getGlobalSettings, data, reply, 0);
            reply.readException();
            return (reply.readInt() & FLAG_LEGACY_SHIZUKU_BINDER_COMPAT) != 0;
        } catch (Throwable e) {
            LOGGER.w(e, "read legacy Shizuku compatibility setting");
            return false;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }
}
