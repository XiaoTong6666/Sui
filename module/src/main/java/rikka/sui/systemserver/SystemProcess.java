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

    private static final class PermissionSnapshot {
        final int[] hidden;
        final int[] root;
        final int[] denied;
        final int[] shell;
        final int defaultFlags;
        final boolean legacyCompatEnabled;

        PermissionSnapshot(
                int[] hidden, int[] root, int[] denied, int[] shell, int defaultFlags, boolean legacyCompatEnabled) {
            this.hidden = hidden;
            this.root = root;
            this.denied = denied;
            this.shell = shell;
            this.defaultFlags = defaultFlags;
            this.legacyCompatEnabled = legacyCompatEnabled;
        }
    }

    private static volatile PermissionSnapshot permissionSnapshot =
            new PermissionSnapshot(new int[0], new int[0], new int[0], new int[0], 0, false);

    private static boolean execActivityTransaction(
            @NonNull Binder binder, int code, Parcel data, Parcel reply, int flags) {
        return SERVICE.onTransact(code, data, reply, flags);
    }

    public static boolean execTransact(@NonNull Binder binder, int code, long dataObj, long replyObj, int flags) {
        Parcel data = ParcelUtils.fromNativePointer(dataObj);
        Parcel reply = ParcelUtils.fromNativePointer(replyObj);

        if (data == null) {
            return false;
        }

        boolean res;
        try {
            if (LegacyShizukuBinderCompat.handle(binder, code, data, reply)) {
                res = true;
            } else if (SERVICE.isServiceTransaction(code)) {
                res = execActivityTransaction(binder, code, data, reply, flags);
            } else {
                res = false;
            }
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
                updateUids(uids, new int[0], new int[0], new int[0], 0, false);
            } else {
                LOGGER.w("IShizukuService is null in SystemProcess.main");
            }
        } catch (Throwable e) {
            LOGGER.w(e, "failed to sync hidden uids");
        }
    }

    public static synchronized boolean updateUids(
            int[] hidden, int[] root, int[] denied, int[] shell, int defaultFlags, boolean legacyCompatEnabled) {
        int[] newHidden = sortedCopy(hidden);
        int[] newRoot = sortedCopy(root);
        int[] newDenied = sortedCopy(denied);
        int[] newShell = sortedCopy(shell);
        int newDefaultFlags = defaultFlags & SuiConfig.MASK_PERMISSION;

        // Only publish the Java snapshot if native accepted the complete update.
        if (!setPermissionSnapshot(
                newHidden,
                newRoot,
                newDenied,
                newShell,
                (newDefaultFlags & SuiConfig.FLAG_HIDDEN) != 0,
                legacyCompatEnabled)) {
            LOGGER.w("native permission snapshot update failed");
            return false;
        }
        permissionSnapshot =
                new PermissionSnapshot(newHidden, newRoot, newDenied, newShell, newDefaultFlags, legacyCompatEnabled);
        LOGGER.d(
                "synced %d hidden, %d root, %d denied, %d shell uids, defaultFlags=%d, legacy=%s",
                newHidden.length,
                newRoot.length,
                newDenied.length,
                newShell.length,
                newDefaultFlags,
                legacyCompatEnabled);
        return true;
    }

    private static int[] sortedCopy(int[] source) {
        int[] copy = source == null ? new int[0] : source.clone();
        Arrays.sort(copy);
        return copy;
    }

    private static boolean contains(int[] uids, int uid) {
        return Arrays.binarySearch(uids, uid) >= 0;
    }

    public static boolean isLegacyCompatEnabled() {
        return permissionSnapshot.legacyCompatEnabled;
    }

    public static boolean isHidden(int uid) {
        return contains(permissionSnapshot.hidden, uid);
    }

    public static int getEffectivePermissionFlags(int uid) {
        PermissionSnapshot snapshot = permissionSnapshot;
        int flags = snapshot.defaultFlags;
        if (contains(snapshot.hidden, uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_HIDDEN;
        } else if (contains(snapshot.denied, uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_DENIED;
        } else if (contains(snapshot.root, uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_ALLOWED;
        } else if (contains(snapshot.shell, uid)) {
            flags = (flags & ~SuiConfig.MASK_PERMISSION) | SuiConfig.FLAG_ALLOWED_SHELL;
        }
        return flags & SuiConfig.MASK_PERMISSION;
    }

    public static boolean isUidHiddenEffective(int uid) {
        return (getEffectivePermissionFlags(uid) & SuiConfig.FLAG_HIDDEN) != 0;
    }

    public static boolean isRootAllowed(int uid) {
        return contains(permissionSnapshot.root, uid);
    }

    public static boolean isShellAllowed(int uid) {
        return contains(permissionSnapshot.shell, uid);
    }

    public static boolean isDenied(int uid) {
        return contains(permissionSnapshot.denied, uid);
    }

    public static int getDefaultPermissionFlags() {
        return permissionSnapshot.defaultFlags;
    }

    @Keep
    @SuppressWarnings("JavaJniMissingFunction")
    private static native boolean setPermissionSnapshot(
            int[] hidden, int[] root, int[] denied, int[] shell, boolean defaultHidden, boolean legacyCompatEnabled);
}
