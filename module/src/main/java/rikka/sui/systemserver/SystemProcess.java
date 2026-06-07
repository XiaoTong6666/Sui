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
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import java.util.Arrays;
import rikka.sui.server.SuiConfig;
import rikka.sui.util.ParcelUtils;

public final class SystemProcess {

    private static final BridgeService SERVICE = new BridgeService();
    private static volatile int[] hiddenUids = new int[0];
    private static volatile int[] rootUids = new int[0];
    private static volatile int[] deniedUids = new int[0];
    private static volatile int[] shellUids = new int[0];
    private static volatile int defaultPermissionFlags = 0;

    private static boolean execActivityTransaction(
            @NonNull Binder binder, int code, Parcel data, Parcel reply, int flags) {
        return SERVICE.onTransact(code, data, reply, flags);
    }

    public static boolean execTransact(@NonNull Binder binder, int code, long dataObj, long replyObj, int flags) {
        if (!SERVICE.isServiceTransaction(code)) {
            return false;
        }

        Parcel data = ParcelUtils.fromNativePointer(dataObj);
        Parcel reply = ParcelUtils.fromNativePointer(replyObj);

        if (data == null) {
            return false;
        }

        boolean res;
        try {
            res = execActivityTransaction(binder, code, data, reply, flags);
        } catch (Exception e) {
            if ((flags & IBinder.FLAG_ONEWAY) != 0) {
                LOGGER.w(e, "Caught a Exception from the binder stub implementation.");
            } else {
                if (reply != null) {
                    reply.setDataPosition(0);
                    reply.writeException(e);
                }
            }
            res = false;
        } finally {
            data.setDataPosition(0);
            if (reply != null) reply.setDataPosition(0);
        }

        if (res) {
            data.recycle();
            if (reply != null) reply.recycle();
        }

        return res;
    }

    public static void main(String[] args) {
        LOGGER.d("main: %s", Arrays.toString(args));

        // Note: IShizukuService only provides getHiddenUids().
        // Root and shell UIDs will be pushed shortly by SuiService via ACTION_SYNC_UIDS.
        try {
            moe.shizuku.server.IShizukuService service = BridgeService.get();
            if (service != null) {
                int[] uids = service.getHiddenUids();
                LOGGER.d("syncing %d hidden uids to native and Java cache", uids.length);
                updateUids(uids, new int[0], new int[0], new int[0], 0);
            } else {
                LOGGER.w("IShizukuService is null in SystemProcess.main");
            }
        } catch (Throwable e) {
            LOGGER.w(e, "failed to sync hidden uids");
        }
    }

    public static void updateUids(int[] hidden, int[] root, int[] denied, int[] shell, int defaultFlags) {
        if (hidden == null) hidden = new int[0];
        if (root == null) root = new int[0];
        if (denied == null) denied = new int[0];
        if (shell == null) shell = new int[0];

        Arrays.sort(hidden);
        Arrays.sort(root);
        Arrays.sort(denied);
        Arrays.sort(shell);

        hiddenUids = hidden;
        rootUids = root;
        deniedUids = denied;
        shellUids = shell;
        defaultPermissionFlags = defaultFlags & SuiConfig.MASK_PERMISSION;

        LOGGER.d(
                "syncing %d hidden, %d root, %d denied, %d shell uids to native, defaultFlags=%d",
                hidden.length, root.length, denied.length, shell.length, defaultPermissionFlags);
        setHiddenUids(hidden);
    }

    public static boolean isHidden(int uid) {
        int[] uids = hiddenUids;
        return Arrays.binarySearch(uids, uid) >= 0;
    }

    public static int getEffectivePermissionFlags(int uid) {
        int flags = defaultPermissionFlags;
        if (isHidden(uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_HIDDEN;
        } else if (isDenied(uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_DENIED;
        } else if (isRootAllowed(uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_ALLOWED;
        } else if (isShellAllowed(uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_ALLOWED_SHELL;
        }
        return flags & SuiConfig.MASK_PERMISSION;
    }

    public static boolean isUidHiddenEffective(int uid) {
        return (getEffectivePermissionFlags(uid) & SuiConfig.FLAG_HIDDEN) != 0;
    }

    public static boolean isRootAllowed(int uid) {
        int[] uids = rootUids;
        return Arrays.binarySearch(uids, uid) >= 0;
    }

    public static boolean isShellAllowed(int uid) {
        int[] uids = shellUids;
        return Arrays.binarySearch(uids, uid) >= 0;
    }

    public static boolean isDenied(int uid) {
        int[] uids = deniedUids;
        return Arrays.binarySearch(uids, uid) >= 0;
    }

    public static int getDefaultPermissionFlags() {
        return defaultPermissionFlags;
    }

    @Keep
    @SuppressWarnings("JavaJniMissingFunction")
    private static native void setHiddenUids(int[] uids);
}
