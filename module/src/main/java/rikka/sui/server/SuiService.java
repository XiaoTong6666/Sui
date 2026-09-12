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

package rikka.sui.server;

import static rikka.shizuku.ShizukuApiConstants.ATTACH_APPLICATION_API_VERSION;
import static rikka.shizuku.ShizukuApiConstants.ATTACH_APPLICATION_BINDER_GENERATION;
import static rikka.shizuku.ShizukuApiConstants.ATTACH_APPLICATION_PACKAGE_NAME;
import static rikka.shizuku.ShizukuApiConstants.ATTACH_APPLICATION_SUPPORTS_SERVER_BINDER_HANDOFF;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_BINDER_GENERATION;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_PERMISSION_GRANTED;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_PATCH_VERSION;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_SECONTEXT;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_UID;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_VERSION;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SHOULD_SHOW_REQUEST_PERMISSION_RATIONALE;
import static rikka.shizuku.ShizukuApiConstants.REQUEST_PERMISSION_REPLY_ALLOWED;
import static rikka.shizuku.ShizukuApiConstants.REQUEST_PERMISSION_REPLY_IS_ONETIME;

import android.app.ActivityThread;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.net.Uri;
import android.os.Binder;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.system.ErrnoException;
import android.system.Os;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.OptIn;
import java.io.File;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import moe.shizuku.server.IShizukuApplication;
import rikka.hidden.compat.ActivityManagerApis;
import rikka.hidden.compat.PackageManagerApis;
import rikka.parcelablelist.ParcelableListSlice;
import rikka.rish.RishConfig;
import rikka.shizuku.ShizukuApiConstants;
import rikka.shizuku.server.ClientRecord;
import rikka.shizuku.server.Service;
import rikka.shizuku.server.util.HandlerUtil;
import rikka.sui.model.AppInfo;
import rikka.sui.server.bridge.BridgeServiceClient;
import rikka.sui.util.AppLaunchUtils;
import rikka.sui.util.BridgeConstants;
import rikka.sui.util.Logger;
import rikka.sui.util.OsUtils;
import rikka.sui.util.SystemPackages;
import rikka.sui.util.SystemPackages.SystemPackage;
import rikka.sui.util.UserHandleCompat;

@OptIn(markerClass = androidx.core.os.BuildCompat.PrereleaseSdkCheck.class)
@SuppressWarnings("deprecation")
public class SuiService extends Service<SuiUserServiceManager, SuiClientManager, SuiConfigManager> {

    private static final long DELEGATED_PERMISSION_CALLBACK_TIMEOUT_MS = 5 * 60 * 1000L;

    private static SuiService instance;
    private static String filesPath;
    private static boolean shellMode = false;
    private final java.util.concurrent.ConcurrentHashMap<String, DelegatedPermissionCallback>
            delegatedPermissionCallbacks = new java.util.concurrent.ConcurrentHashMap<>();

    public static SuiService getInstance() {
        return instance;
    }

    private static IBinder requestBinderFromBridge(int serverUid) {
        IBinder bridgeService = android.os.ServiceManager.getService(BridgeConstants.SERVICE_NAME);
        if (bridgeService == null) {
            return null;
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(BridgeConstants.SERVICE_DESCRIPTOR);
            data.writeInt(BridgeConstants.ACTION_GET_BINDER);
            if (serverUid == BridgeConstants.SERVER_UID_ROOT || serverUid == BridgeConstants.SERVER_UID_SHELL) {
                data.writeInt(serverUid);
            }
            bridgeService.transact(BridgeConstants.TRANSACTION_CODE, data, reply, 0);
            reply.readException();
            return reply.readStrongBinder();
        } catch (Throwable e) {
            LOGGER.w(e, "requestBinderFromBridge");
            return null;
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private SuiConfigManager.ShellReloadResult reloadShellServerConfig(long expectedTransitionId) {
        java.util.List<ClientFallback> fallbacks = new java.util.ArrayList<>();
        IBinder shellBinder = requestBinderFromBridge(BridgeConstants.SERVER_UID_SHELL);
        if (shellBinder == null) {
            LOGGER.w("shell binder is null, skip synchronous shell config reload");
            return SuiConfigManager.ShellReloadResult.notApplied(expectedTransitionId);
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(ShizukuApiConstants.BINDER_DESCRIPTOR);
            data.writeLong(expectedTransitionId);
            if (!shellBinder.transact(ServerConstants.BINDER_TRANSACTION_reloadShellConfig, data, reply, 0)) {
                return SuiConfigManager.ShellReloadResult.notApplied(expectedTransitionId);
            }
            reply.readException();
            long appliedTransitionId = reply.readLong();
            boolean applied = reply.readInt() != 0;
            int count = reply.readInt();
            for (int i = 0; i < count; ++i) {
                fallbacks.add(new ClientFallback(reply.readInt(), reply.readInt(), reply.readString()));
            }
            return new SuiConfigManager.ShellReloadResult(appliedTransitionId, applied, fallbacks);
        } catch (Throwable e) {
            LOGGER.w(e, "reloadShellServerConfig");
            return SuiConfigManager.ShellReloadResult.notApplied(expectedTransitionId);
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    static boolean isPermissionAllowedForCurrentServer(int flags) {
        int mode = flags & SuiConfig.MASK_PERMISSION;
        return shellMode ? mode == SuiConfig.FLAG_ALLOWED_SHELL : mode == SuiConfig.FLAG_ALLOWED;
    }

    private static boolean isRootPermissionMode(int flags) {
        return (flags & SuiConfig.MASK_PERMISSION) == SuiConfig.FLAG_ALLOWED;
    }

    private static boolean requiresRootCapabilityReset(int oldFlags, int newFlags) {
        return isRootPermissionMode(oldFlags) && !isRootPermissionMode(newFlags);
    }

    private static boolean requiresCurrentServerCapabilityReset(int oldFlags, int newFlags) {
        return isPermissionAllowedForCurrentServer(oldFlags) && !isPermissionAllowedForCurrentServer(newFlags);
    }

    private void updateClientAllowedStateForUid(int uid, int effectiveFlags) {
        boolean allowed = isPermissionAllowedForCurrentServer(effectiveFlags);
        for (ClientRecord record : clientManager.findClients(uid)) {
            record.allowed = allowed;
            if (!allowed) {
                record.onetime = false;
            }
        }
    }

    private static int getServerUidForPermissionFlags(int flags) {
        int mode = flags & SuiConfig.MASK_PERMISSION;
        if (mode == SuiConfig.FLAG_ALLOWED) {
            return BridgeConstants.SERVER_UID_ROOT;
        }
        if (mode == SuiConfig.FLAG_ALLOWED_SHELL) {
            return BridgeConstants.SERVER_UID_SHELL;
        }
        return -1;
    }

    private static int readProcessGroupId(int pid) throws java.io.IOException {
        String stat;
        try (java.io.BufferedReader reader =
                new java.io.BufferedReader(new java.io.FileReader("/proc/" + pid + "/stat"))) {
            stat = reader.readLine();
        }
        if (stat == null) {
            throw new java.io.IOException("empty /proc stat for pid " + pid);
        }

        // /proc/<pid>/stat field 2 (comm) is parenthesized and may contain spaces or ')'.
        // Split after its final ')' so field indexes stay aligned: state, ppid, pgrp, ...
        int commEnd = stat.lastIndexOf(')');
        if (commEnd < 0 || commEnd + 2 >= stat.length()) {
            throw new java.io.IOException("malformed /proc stat for pid " + pid);
        }
        String[] fields = stat.substring(commEnd + 2).trim().split("\\s+");
        if (fields.length < 3) {
            throw new java.io.IOException("missing pgrp in /proc stat for pid " + pid);
        }
        try {
            return Integer.parseInt(fields[2]);
        } catch (NumberFormatException e) {
            throw new java.io.IOException("invalid pgrp in /proc stat for pid " + pid, e);
        }
    }

    static final class ClientFallback {
        final int uid;
        final int pid;
        final String packageName;

        ClientFallback(int uid, int pid, String packageName) {
            this.uid = uid;
            this.pid = pid;
            this.packageName = packageName;
        }
    }

    private java.util.List<ClientFallback> handoffClientsForUid(int uid, int effectiveFlags) {
        java.util.List<ClientFallback> fallbacks = new java.util.ArrayList<>();
        int targetServerUid = getServerUidForPermissionFlags(effectiveFlags);
        int currentServerUid = shellMode ? BridgeConstants.SERVER_UID_SHELL : BridgeConstants.SERVER_UID_ROOT;
        if (targetServerUid == -1 || targetServerUid == currentServerUid) {
            return fallbacks;
        }

        IBinder targetBinder = requestBinderFromBridge(targetServerUid);
        if (targetBinder == null) {
            LOGGER.w("cannot hand off uid %d: target server binder %d is unavailable", uid, targetServerUid);
            for (ClientRecord record : clientManager.findClients(uid)) {
                fallbacks.add(new ClientFallback(record.uid, record.pid, record.packageName));
            }
            return fallbacks;
        }

        // A main-Binder handoff cannot migrate capabilities already materialized in the
        // current server process. Force the lifecycle fallback whenever such capabilities
        // exist so their owner process and server-side registries are reset together.
        if (hasRemoteProcessesForUid(uid) || getUserServiceManager().hasUserServicesForUid(uid)) {
            for (ClientRecord record : clientManager.findClients(uid)) {
                fallbacks.add(new ClientFallback(record.uid, record.pid, record.packageName));
            }
            return fallbacks;
        }

        for (ClientRecord record : clientManager.findClients(uid)) {
            if (!record.supportsServerBinderHandoff || hasRishHostForClient(record.pid)) {
                fallbacks.add(new ClientFallback(record.uid, record.pid, record.packageName));
                continue;
            }
            try {
                long generation = android.os.SystemClock.elapsedRealtimeNanos();
                LOGGER.i(
                        "Handing off %s (uid %d, pid %d) to Sui server uid %d, generation=%d",
                        record.packageName, record.uid, record.pid, targetServerUid, generation);
                if (!record.client.dispatchServerBinder(targetBinder, record.packageName, generation)) {
                    fallbacks.add(new ClientFallback(record.uid, record.pid, record.packageName));
                }
            } catch (Throwable e) {
                LOGGER.w(e, "Failed to hand off client %s", record.packageName);
                fallbacks.add(new ClientFallback(record.uid, record.pid, record.packageName));
            }
        }
        return fallbacks;
    }

    private void invalidatePackages(int uid, @NonNull java.util.Collection<String> packageNames, String reason) {
        List<ClientRecord> records = clientManager.findClients(uid);

        for (ClientRecord record : records) {
            revokeRishHostForClient(record.pid);
        }
        revokeRemoteProcessesForUid(uid);
        getUserServiceManager().revokeUserServicesForUid(uid);

        long id = android.os.Binder.clearCallingIdentity();
        try {
            for (String packageName : packageNames) {
                try {
                    LOGGER.i("%s for %s (uid %d), force stopping to sever old binders...", reason, packageName, uid);
                    ActivityManagerApis.forceStopPackageNoThrow(packageName, UserHandleCompat.getUserId(uid));
                } catch (Throwable e) {
                    LOGGER.w(e, "Failed to invalidate package %s", packageName);
                }
            }

            // forceStopPackage() only covers AMS-managed application processes. Sui also accepts
            // clients such as rish/app_process, so explicitly terminate every attached client PID
            // before considering a privilege downgrade complete.
            for (ClientRecord record : records) {
                try {
                    android.system.Os.kill(record.pid, android.system.OsConstants.SIGKILL);
                } catch (android.system.ErrnoException e) {
                    if (e.errno != android.system.OsConstants.ESRCH) {
                        LOGGER.w(e, "Failed to kill stale Sui client pid %d", record.pid);
                    }
                }
            }

        } finally {
            android.os.Binder.restoreCallingIdentity(id);
        }
    }

    private void invalidateFallbacks(@NonNull java.util.Collection<ClientFallback> fallbacks, String reason) {
        java.util.Map<Integer, java.util.Set<String>> packagesByUid = new java.util.LinkedHashMap<>();
        for (ClientFallback fallback : fallbacks) {
            java.util.Set<String> packages = getOrCreateAffectedPackages(packagesByUid, fallback.uid);
            if (fallback.packageName != null) {
                packages.add(fallback.packageName);
            }
        }
        for (java.util.Map.Entry<Integer, java.util.Set<String>> entry : packagesByUid.entrySet()) {
            invalidatePackages(entry.getKey(), entry.getValue(), reason);
        }

        long id = android.os.Binder.clearCallingIdentity();
        try {
            for (ClientFallback fallback : fallbacks) {
                try {
                    android.system.Os.kill(fallback.pid, android.system.OsConstants.SIGKILL);
                } catch (android.system.ErrnoException e) {
                    if (e.errno != android.system.OsConstants.ESRCH) {
                        LOGGER.w(e, "Failed to kill fallback client pid %d", fallback.pid);
                    }
                }
            }
        } finally {
            android.os.Binder.restoreCallingIdentity(id);
        }
    }

    private void restartPermissionRequester(
            int requestUid,
            int requestPid,
            @NonNull java.util.Collection<ClientFallback> firstFallbacks,
            @NonNull java.util.Collection<ClientFallback> secondFallbacks) {
        ClientFallback requesterFallback = null;
        for (ClientFallback fallback : firstFallbacks) {
            if (fallback.uid == requestUid && fallback.pid == requestPid) {
                requesterFallback = fallback;
                break;
            }
        }
        if (requesterFallback == null) {
            for (ClientFallback fallback : secondFallbacks) {
                if (fallback.uid == requestUid && fallback.pid == requestPid) {
                    requesterFallback = fallback;
                    break;
                }
            }
        }
        if (requesterFallback == null || requesterFallback.packageName == null) {
            return;
        }

        long id = android.os.Binder.clearCallingIdentity();
        try {
            LOGGER.i("Restarting permission requester %s after legacy Binder fallback", requesterFallback.packageName);
            AppLaunchUtils.startAppAsUser(
                    requesterFallback.packageName, UserHandleCompat.getUserId(requesterFallback.uid));
        } finally {
            android.os.Binder.restoreCallingIdentity(id);
        }
    }

    private void invalidatePackagesForUid(int uid, String reason) {
        List<String> packages = PackageManagerApis.getPackagesForUidNoThrow(uid);
        invalidatePackages(uid, packages, reason);
    }

    private java.util.Map<Integer, java.util.Set<String>> collectUnconfiguredAffectedPackages() {
        java.util.Map<Integer, java.util.Set<String>> affectedPackagesByUid = new java.util.LinkedHashMap<>();
        for (ClientRecord record : clientManager.getClients()) {
            if (record.uid < 10000 || record.uid == systemUiUid || record.uid == settingsUid) {
                continue;
            }
            if (configManager.findExplicit(record.uid) != null) {
                continue;
            }
            if (record.packageName != null) {
                getOrCreateAffectedPackages(affectedPackagesByUid, record.uid).add(record.packageName);
            } else {
                getOrCreateAffectedPackages(affectedPackagesByUid, record.uid);
            }
        }

        // Capability owners can outlive their original client process (daemon user services,
        // remote process groups). Include their UIDs even when there is no current ClientRecord.
        for (int uid : capabilityEpochStates.keySet()) {
            if (uid < 10000 || uid == systemUiUid || uid == settingsUid || configManager.findExplicit(uid) != null) {
                continue;
            }
            java.util.Set<String> packages = getOrCreateAffectedPackages(affectedPackagesByUid, uid);
            packages.addAll(PackageManagerApis.getPackagesForUidNoThrow(uid));
        }
        return affectedPackagesByUid;
    }

    private void refreshUnconfiguredClientsForDefaultPermissionTransition(
            int oldDefaultMode,
            int newDefaultMode,
            java.util.Map<Integer, java.util.Set<String>> affectedPackagesByUid) {

        for (java.util.Map.Entry<Integer, java.util.Set<String>> entry : affectedPackagesByUid.entrySet()) {
            int uid = entry.getKey();
            updateClientAllowedStateForUid(uid, newDefaultMode);
            if (oldDefaultMode == newDefaultMode) {
                continue;
            }
            if (getServerUidForPermissionFlags(newDefaultMode) != -1) {
                java.util.List<ClientFallback> fallbacks = handoffClientsForUid(uid, newDefaultMode);
                if (!fallbacks.isEmpty()) {
                    invalidateFallbacks(fallbacks, "Binder handoff failed");
                }
            } else {
                invalidatePackages(uid, entry.getValue(), "Default permission changed");
            }
        }
    }

    public static boolean isShellMode() {
        return shellMode;
    }

    public static String getFilesPath() {
        return filesPath;
    }

    public static void main(String filesPath, boolean isShell) {
        LOGGER.i("starting server (isShell=%b)...", isShell);

        RishConfig.setLibraryPath(System.getProperty("sui.library.path"));

        SuiService.filesPath = filesPath;
        SuiService.shellMode = isShell;

        Looper.prepareMainLooper();
        // Frameworks without the SQLite isolated-process fix may query SettingsProvider through
        // systemMain's unregistered Application, so initialize SQLite first.
        if (!isShell && !SuiDatabase.initialize()) {
            throw new IllegalStateException("database unavailable");
        }
        Context context = ActivityThread.systemMain().getSystemContext();
        new SuiService(context);
        Looper.loop();

        LOGGER.i("server exited");
        System.exit(0);
    }

    private final SuiClientManager clientManager;
    private final SuiConfigManager configManager;
    private final SuiUserServiceManager userServiceManager;
    private final String systemUiPackageName;
    private final String settingsPackageName;
    private final int systemUiUid;
    private final int settingsUid;
    private IShizukuApplication systemUiApplication;

    private final Object managerBinderLock = new Object();
    private final Object pendingPermissionLock = new Object();
    private final Logger flog = new Logger("Sui", "/cache/sui.log");
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Map<String, Integer> pendingPermissionConfirmations = new HashMap<>();
    private final java.util.concurrent.ConcurrentHashMap<Integer, CapabilityEpochState> capabilityEpochStates =
            new java.util.concurrent.ConcurrentHashMap<>();

    private static final class CapabilityEpochState {
        long epoch = 1;
        int inFlight;
        boolean transitioning;
    }

    private CapabilityEpochState capabilityStateForUid(int uid) {
        CapabilityEpochState state = capabilityEpochStates.get(uid);
        if (state == null) {
            CapabilityEpochState newState = new CapabilityEpochState();
            state = capabilityEpochStates.putIfAbsent(uid, newState);
            if (state == null) {
                state = newState;
            }
        }
        return state;
    }

    @Override
    protected long beginCapabilityCreation(String kind, int uid, int pid) {
        CapabilityEpochState state = capabilityStateForUid(uid);
        synchronized (state) {
            ClientRecord record = clientManager.findClient(uid, pid);
            if (state.transitioning || record == null || !isClientAuthorized(record)) {
                throw new SecurityException("permission transition in progress while creating " + kind);
            }
            state.inFlight++;
            return state.epoch;
        }
    }

    @Override
    protected boolean finishCapabilityCreation(String kind, int uid, int pid, long epoch, Runnable publisher) {
        CapabilityEpochState state = capabilityStateForUid(uid);
        synchronized (state) {
            try {
                ClientRecord record = clientManager.findClient(uid, pid);
                if (state.transitioning || state.epoch != epoch || record == null || !isClientAuthorized(record)) {
                    return false;
                }
                publisher.run();
                return true;
            } finally {
                if (state.inFlight > 0) {
                    state.inFlight--;
                }
                state.notifyAll();
            }
        }
    }

    @Override
    protected void abortCapabilityCreation(String kind, int uid, int pid, long epoch) {
        CapabilityEpochState state = capabilityStateForUid(uid);
        synchronized (state) {
            if (state.inFlight > 0) {
                state.inFlight--;
            }
            state.notifyAll();
        }
    }

    private void beginPermissionTransition(int uid) {
        CapabilityEpochState state = capabilityStateForUid(uid);
        synchronized (state) {
            while (state.transitioning) {
                try {
                    state.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("interrupted while waiting for permission transition", e);
                }
            }
            state.transitioning = true;
            state.epoch++;
        }
    }

    private void finishPermissionTransition(int uid) {
        CapabilityEpochState state = capabilityStateForUid(uid);
        synchronized (state) {
            while (state.inFlight != 0) {
                try {
                    state.wait();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("interrupted while waiting for capability rollback", e);
                }
            }
            state.transitioning = false;
            state.notifyAll();
        }
    }

    private boolean hasCapabilityWorkForUid(int uid) {
        CapabilityEpochState state = capabilityEpochStates.get(uid);
        boolean inFlight = false;
        if (state != null) {
            synchronized (state) {
                inFlight = state.inFlight != 0;
            }
        }
        return inFlight
                || hasRemoteProcessesForUid(uid)
                || getUserServiceManager().hasUserServicesForUid(uid);
    }

    long beginUserServiceCapabilityCreation(int uid, int pid) {
        return beginCapabilityCreation("user-service", uid, pid);
    }

    boolean isUserServiceCapabilityCurrent(rikka.shizuku.server.UserServiceRecord record) {
        CapabilityEpochState state = capabilityStateForUid(record.ownerUid);
        synchronized (state) {
            ClientRecord client = clientManager.findClient(record.ownerUid, record.ownerPid);
            return !state.transitioning
                    && state.epoch == record.capabilityEpoch
                    && client != null
                    && isClientAuthorized(client);
        }
    }

    boolean finishUserServiceCapabilityCreation(rikka.shizuku.server.UserServiceRecord record, Runnable publisher) {
        return finishCapabilityCreation(
                "user-service", record.ownerUid, record.ownerPid, record.capabilityEpoch, publisher);
    }

    void abortUserServiceCapabilityCreation(rikka.shizuku.server.UserServiceRecord record) {
        abortCapabilityCreation("user-service", record.ownerUid, record.ownerPid, record.capabilityEpoch);
    }

    private static String buildPermissionRequestKey(int requestUid, int requestPid, int requestCode) {
        return requestUid + ":" + requestPid + ":" + requestCode;
    }

    private void markPendingPermissionConfirmation(int requestUid, int requestPid, int requestCode) {
        synchronized (pendingPermissionLock) {
            String key = buildPermissionRequestKey(requestUid, requestPid, requestCode);
            Integer count = pendingPermissionConfirmations.get(key);
            pendingPermissionConfirmations.put(key, count == null ? 1 : count + 1);
        }
    }

    private boolean consumePendingPermissionConfirmation(int requestUid, int requestPid, int requestCode) {
        synchronized (pendingPermissionLock) {
            String key = buildPermissionRequestKey(requestUid, requestPid, requestCode);
            Integer count = pendingPermissionConfirmations.get(key);
            if (count == null || count <= 0) {
                return false;
            }
            if (count == 1) {
                pendingPermissionConfirmations.remove(key);
            } else {
                pendingPermissionConfirmations.put(key, count - 1);
            }
            return true;
        }
    }

    private void removePendingPermissionConfirmationsForUid(int uid) {
        String prefix = uid + ":";
        synchronized (pendingPermissionLock) {
            java.util.List<String> toRemove = new java.util.ArrayList<>();
            for (String key : pendingPermissionConfirmations.keySet()) {
                if (key.startsWith(prefix)) {
                    toRemove.add(key);
                }
            }
            for (String key : toRemove) {
                pendingPermissionConfirmations.remove(key);
            }
        }
    }

    private void finishPermissionConfirmation(
            int requestUid,
            int requestPid,
            int requestCode,
            boolean allowed,
            boolean onetime,
            boolean isShell,
            boolean consumePending) {
        if (consumePending && !consumePendingPermissionConfirmation(requestUid, requestPid, requestCode)) {
            LOGGER.w(
                    "drop stale or forged permission result: uid=%d, pid=%d, requestCode=%d",
                    requestUid, requestPid, requestCode);
            return;
        }

        LOGGER.i(
                "dispatchPermissionConfirmationResult: uid=%d, pid=%d, requestCode=%d, allowed=%s, onetime=%s, isShell=%s",
                requestUid,
                requestPid,
                requestCode,
                Boolean.toString(allowed),
                Boolean.toString(onetime),
                Boolean.toString(isShell));

        List<ClientRecord> records = clientManager.findClients(requestUid);
        java.util.List<ClientFallback> shellFallbacks = java.util.Collections.emptyList();
        java.util.List<ClientFallback> handoffFallbacks = java.util.Collections.emptyList();

        if (!onetime) {
            int oldPermissionFlags = 0;
            SuiConfig.PackageEntry oldEntry = configManager.find(requestUid);
            if (oldEntry != null) {
                oldPermissionFlags = oldEntry.flags & SuiConfig.MASK_PERMISSION;
            }
            int permissionFlags =
                    allowed ? (isShell ? SuiConfig.FLAG_ALLOWED_SHELL : SuiConfig.FLAG_ALLOWED) : SuiConfig.FLAG_DENIED;
            boolean capabilityBarrier = requiresCurrentServerCapabilityReset(oldPermissionFlags, permissionFlags);
            if (capabilityBarrier) {
                beginPermissionTransition(requestUid);
            }
            try {
                configManager.update(requestUid, SuiConfig.MASK_PERMISSION, permissionFlags);

                if (!shellMode
                        && (oldPermissionFlags == SuiConfig.FLAG_ALLOWED_SHELL
                                || permissionFlags == SuiConfig.FLAG_ALLOWED_SHELL)) {
                    // Make the shell server observe the new routing before any client is told that
                    // the permission request succeeded.
                    shellFallbacks = flushShellRoutingState();
                }

                if (!shellMode) {
                    syncUidsToSystemServer();
                }

                updateClientAllowedStateForUid(requestUid, permissionFlags);

                int targetServerUid = getServerUidForPermissionFlags(permissionFlags);
                int currentServerUid = shellMode ? BridgeConstants.SERVER_UID_SHELL : BridgeConstants.SERVER_UID_ROOT;
                if (targetServerUid != -1 && targetServerUid != currentServerUid) {
                    handoffFallbacks = handoffClientsForUid(requestUid, permissionFlags);
                } else if (!shellMode && requiresRootCapabilityReset(oldPermissionFlags, permissionFlags)) {
                    invalidatePackagesForUid(requestUid, "Root permission revoked");
                }

                if (!shellFallbacks.isEmpty()) {
                    invalidateFallbacks(shellFallbacks, "Shell client migration failed");
                }
                if (!handoffFallbacks.isEmpty()) {
                    invalidateFallbacks(handoffFallbacks, "Binder handoff failed");
                }
                if (allowed) {
                    restartPermissionRequester(requestUid, requestPid, shellFallbacks, handoffFallbacks);
                }
            } finally {
                if (capabilityBarrier) {
                    finishPermissionTransition(requestUid);
                }
            }
        } else {
            for (ClientRecord record : records) {
                if (record.pid == requestPid) {
                    // One-time permission is root-only. Do not widen it to sibling processes
                    // sharing the same UID.
                    record.allowed = allowed && !shellMode;
                    record.onetime = allowed && !shellMode;
                }
            }
        }

        if (records.isEmpty()) {
            LOGGER.w("dispatchPermissionConfirmationResult: no client for uid %d was found", requestUid);
        } else {
            for (ClientRecord record : records) {
                if (record.pid == requestPid) {
                    record.dispatchRequestPermissionResult(requestCode, allowed);
                }
            }
        }

        String key = buildPermissionRequestKey(requestUid, requestPid, requestCode);
        DelegatedPermissionCallback callback = delegatedPermissionCallbacks.get(key);
        if (callback != null) {
            removeDelegatedPermissionCallback(key, callback);
            android.os.Parcel cbData = android.os.Parcel.obtain();
            try {
                cbData.writeInt(allowed ? 1 : 0);
                callback.binder.transact(1, cbData, null, android.os.IBinder.FLAG_ONEWAY);
            } catch (Throwable e) {
                LOGGER.w(e, "Failed to call delegated permission callback");
            } finally {
                cbData.recycle();
            }
        }
    }

    private boolean isTrustedPermissionDelegateCaller(int callingUid) {
        if (callingUid == 0 || callingUid == 2000) {
            return true;
        }
        return callingUid == systemUiUid;
    }

    private void syncUidsToSystemServer() {
        BridgeServiceClient.syncUids(
                configManager.getHiddenUids(),
                getRootUidsWithSystem(),
                configManager.getDeniedUids(),
                configManager.getShellUids(),
                configManager.getDefaultPermissionFlags());
    }

    private java.util.List<ClientFallback> flushShellRoutingState() {
        if (shellMode) {
            return java.util.Collections.emptyList();
        }
        long transitionId = configManager.syncUidsToShellFileNow();
        if (transitionId <= 0) {
            throw new IllegalStateException("failed to publish shell config transition");
        }
        SuiConfigManager.ShellReloadResult result = reloadShellServerConfig(transitionId);
        if (!result.applied || result.transitionId != transitionId) {
            // One retry is useful when the FileObserver applied the file first and the first
            // synchronous transaction raced with shell-server registration/reconnect.
            result = reloadShellServerConfig(transitionId);
        }
        if (!result.applied || result.transitionId != transitionId) {
            throw new IllegalStateException("shell server did not acknowledge config transition " + transitionId);
        }
        return result.fallbacks;
    }

    java.util.List<ClientFallback> onShellConfigReloaded() {
        java.util.List<ClientFallback> fallbacks = new java.util.ArrayList<>();
        if (!shellMode) {
            return fallbacks;
        }

        java.util.List<ClientRecord> records = clientManager.getClients();
        java.util.Map<Integer, Integer> effectiveFlagsByUid = new java.util.LinkedHashMap<>();
        java.util.Set<Integer> revokedUids = new java.util.LinkedHashSet<>();
        java.util.Set<Integer> rootTargetUids = new java.util.LinkedHashSet<>();
        java.util.Set<Integer> materializedCapabilityUids = new java.util.LinkedHashSet<>();

        for (ClientRecord record : records) {
            SuiConfig.PackageEntry entry = configManager.find(record.uid);
            int effectiveFlags = entry != null ? entry.flags & SuiConfig.MASK_PERMISSION : 0;
            effectiveFlagsByUid.put(record.uid, effectiveFlags);
            boolean wasAllowed = record.allowed || record.onetime;
            boolean nowAllowed = isPermissionAllowedForCurrentServer(effectiveFlags);
            if (wasAllowed && !nowAllowed) {
                revokedUids.add(record.uid);
            }
            if (getServerUidForPermissionFlags(effectiveFlags) == BridgeConstants.SERVER_UID_ROOT) {
                rootTargetUids.add(record.uid);
            }
            if (hasRishHostForClient(record.pid)) {
                materializedCapabilityUids.add(record.uid);
            }
        }
        for (int uid : capabilityEpochStates.keySet()) {
            Integer effectiveFlagsValue = effectiveFlagsByUid.get(uid);
            if (effectiveFlagsValue == null) {
                SuiConfig.PackageEntry entry = configManager.find(uid);
                effectiveFlagsValue = entry != null ? entry.flags & SuiConfig.MASK_PERMISSION : 0;
                effectiveFlagsByUid.put(uid, effectiveFlagsValue);
            }
            int effectiveFlags = effectiveFlagsValue;
            if (!isPermissionAllowedForCurrentServer(effectiveFlags) && hasCapabilityWorkForUid(uid)) {
                revokedUids.add(uid);
                if (getServerUidForPermissionFlags(effectiveFlags) == BridgeConstants.SERVER_UID_ROOT) {
                    rootTargetUids.add(uid);
                }
                materializedCapabilityUids.add(uid);
            }
        }
        for (int uid : revokedUids) {
            if (hasRemoteProcessesForUid(uid) || getUserServiceManager().hasUserServicesForUid(uid)) {
                materializedCapabilityUids.add(uid);
            }
            beginPermissionTransition(uid);
        }

        try {
            for (ClientRecord record : records) {
                Integer effectiveFlagsValue = effectiveFlagsByUid.get(record.uid);
                int effectiveFlags = effectiveFlagsValue != null ? effectiveFlagsValue : 0;
                record.allowed = isPermissionAllowedForCurrentServer(effectiveFlags);
                if (!record.allowed) {
                    record.onetime = false;
                }
            }

            for (int uid : revokedUids) {
                if (rootTargetUids.contains(uid) && !materializedCapabilityUids.contains(uid)) {
                    fallbacks.addAll(handoffClientsForUid(uid, SuiConfig.FLAG_ALLOWED));
                } else {
                    for (ClientRecord record : clientManager.findClients(uid)) {
                        fallbacks.add(new ClientFallback(record.uid, record.pid, record.packageName));
                    }
                }

                for (ClientRecord record : clientManager.findClients(uid)) {
                    revokeRishHostForClient(record.pid);
                }
                revokeRemoteProcessesForUid(uid);
                getUserServiceManager().revokeUserServicesForUid(uid);
            }
            return fallbacks;
        } finally {
            java.util.List<Integer> ids = new java.util.ArrayList<>(revokedUids);
            for (int i = ids.size() - 1; i >= 0; --i) {
                finishPermissionTransition(ids.get(i));
            }
        }
    }

    private final class DelegatedPermissionCallback implements IBinder.DeathRecipient, Runnable {

        private final String key;
        private final android.os.IBinder binder;

        private DelegatedPermissionCallback(String key, android.os.IBinder binder) {
            this.key = key;
            this.binder = binder;
        }

        @Override
        public void binderDied() {
            removeDelegatedPermissionCallback(key, this);
        }

        @Override
        public void run() {
            LOGGER.w("delegated permission callback timed out: %s", key);
            removeDelegatedPermissionCallback(key, this);
        }
    }

    private void removeDelegatedPermissionCallback(String key, DelegatedPermissionCallback callback) {
        if (callback == null) {
            return;
        }
        if (delegatedPermissionCallbacks.remove(key, callback)) {
            destroyDelegatedPermissionCallback(callback);
        }
    }

    private static java.util.Set<String> getOrCreateAffectedPackages(
            java.util.Map<Integer, java.util.Set<String>> affectedPackagesByUid, int uid) {
        java.util.Set<String> packages = affectedPackagesByUid.get(uid);
        if (packages == null) {
            packages = new java.util.LinkedHashSet<>();
            affectedPackagesByUid.put(uid, packages);
        }
        return packages;
    }

    private void destroyDelegatedPermissionCallback(DelegatedPermissionCallback callback) {
        if (callback == null) {
            return;
        }
        mainHandler.removeCallbacks(callback);
        callback.binder.unlinkToDeath(callback, 0);
    }

    private void putDelegatedPermissionCallback(String key, android.os.IBinder binder) {
        DelegatedPermissionCallback callback = new DelegatedPermissionCallback(key, binder);
        try {
            binder.linkToDeath(callback, 0);
        } catch (RemoteException e) {
            LOGGER.w(e, "delegated permission callback is already dead");
            return;
        }

        DelegatedPermissionCallback old = delegatedPermissionCallbacks.put(key, callback);
        destroyDelegatedPermissionCallback(old);
        mainHandler.postDelayed(callback, DELEGATED_PERMISSION_CALLBACK_TIMEOUT_MS);
    }

    private int waitForPackage(String packageName, boolean forever) {
        return waitForPackage(new String[] {packageName}, forever);
    }

    private interface PackageResolver {
        SystemPackage resolve();
    }

    private SystemPackage waitForPackage(String name, PackageResolver resolver) {
        while (true) {
            SystemPackage systemPackage = resolver.resolve();
            if (systemPackage != null) {
                LOGGER.i(
                        "%s package is %s (uid=%d, process=%s)",
                        name, systemPackage.packageName, systemPackage.uid, systemPackage.processName);
                return systemPackage;
            }

            LOGGER.w("can't resolve %s package, wait 1s", name);

            try {
                //noinspection BusyWait
                Thread.sleep(1000);
            } catch (InterruptedException ignored) {
            }
        }
    }

    private int waitForPackage(String[] packageNames, boolean forever) {
        while (true) {
            for (String packageName : packageNames) {
                ApplicationInfo ai = PackageManagerApis.getApplicationInfoNoThrow(packageName, 0, 0);
                if (ai != null) {
                    LOGGER.i("uid for %s is %d", packageName, ai.uid);
                    return ai.uid;
                }
            }

            LOGGER.w("can't find %s, wait 1s", java.util.Arrays.toString(packageNames));

            if (!forever) return -1;

            try {
                //noinspection BusyWait
                Thread.sleep(1000);
            } catch (InterruptedException ignored) {
            }
        }
    }

    private int[] getRootUidsWithSystem() {
        int[] rootUids = configManager.getRootUids();
        int[] result = new int[rootUids.length + 3];
        System.arraycopy(rootUids, 0, result, 0, rootUids.length);
        result[rootUids.length] = systemUiUid;
        result[rootUids.length + 1] = settingsUid;
        result[rootUids.length + 2] = 1000;
        return result;
    }

    private final Runnable registerTask = new Runnable() {
        @Override
        public void run() {
            BridgeServiceClient.send(new BridgeServiceClient.Listener() {
                @Override
                public void onSystemServerRestarted() {
                    LOGGER.w("system restarted, re-registering...");
                    mainHandler.post(registerTask);
                }

                @Override
                public void onResponseFromBridgeService(boolean response) {
                    if (response) {
                        LOGGER.i("SUCCESS: Service binder sent to bridge.");
                        // Only the root server manages UID lists.
                        // The shell server must NOT call syncUids, or it would overwrite
                        // the root server's rootUids/shellUids with its empty config.
                        if (!shellMode) {
                            syncUidsToSystemServer();
                        }
                    } else {
                        LOGGER.w("FAILURE: No response from bridge. Retrying in 1s...");
                        // dumpSuiProcess();
                        mainHandler.postDelayed(registerTask, 1000);
                    }
                }
            });
        }
    };

    public SuiService(Context context) {
        super();

        HandlerUtil.setMainHandler(mainHandler);

        SuiService.instance = this;

        configManager = getConfigManager();
        clientManager = getClientManager();
        userServiceManager = getUserServiceManager();

        SystemPackage systemUi = waitForPackage("SystemUI", () -> SystemPackages.resolveSystemUi(context));
        SystemPackage settings = waitForPackage("Settings", () -> SystemPackages.resolveSettings(context));
        systemUiPackageName = systemUi.packageName;
        systemUiUid = systemUi.uid;
        settingsPackageName = settings.packageName;
        settingsUid = settings.uid;

        // Skip root-only setup when running as shell server
        if (!shellMode) {
            int gmsUid = waitForPackage("com.google.android.gms", false);
            if (gmsUid > 0) {
                configManager.update(gmsUid, SuiConfig.MASK_PERMISSION, SuiConfig.FLAG_HIDDEN);
            }
        }

        mainHandler.postDelayed(registerTask, 2000);
    }

    @Override
    public SuiUserServiceManager onCreateUserServiceManager() {
        return new SuiUserServiceManager();
    }

    @Override
    public SuiClientManager onCreateClientManager() {
        return new SuiClientManager(getConfigManager());
    }

    @Override
    public SuiConfigManager onCreateConfigManager() {
        return new SuiConfigManager();
    }

    @Override
    public boolean checkCallerManagerPermission(String func, int callingUid, int callingPid) {
        return callingUid == settingsUid || callingUid == systemUiUid;
    }

    @Override
    public boolean checkCallerPermission(
            String func, int callingUid, int callingPid, @Nullable ClientRecord clientRecord) {
        // Temporary fix for https://github.com/RikkaApps/Sui/issues/35
        if ("transactRemote".equals(func) && clientRecord == null) {
            SuiConfig.PackageEntry packageEntry = configManager.find(callingUid);
            return packageEntry != null && isPermissionAllowedForCurrentServer(packageEntry.flags);
        }
        return false;
    }

    @Override
    protected boolean isClientAuthorized(ClientRecord clientRecord) {
        if (clientRecord.onetime) {
            return !shellMode && clientRecord.allowed;
        }
        SuiConfig.PackageEntry packageEntry = configManager.find(clientRecord.uid);
        return packageEntry != null && isPermissionAllowedForCurrentServer(packageEntry.flags);
    }

    @Override
    public void attachApplication(IShizukuApplication application, Bundle args) {
        if (application == null || args == null) {
            return;
        }

        String requestPackageName = args.getString(ATTACH_APPLICATION_PACKAGE_NAME);
        if (requestPackageName == null) {
            return;
        }
        int apiVersion = args.getInt(ATTACH_APPLICATION_API_VERSION, -1);
        boolean supportsServerBinderHandoff = args.getBoolean(ATTACH_APPLICATION_SUPPORTS_SERVER_BINDER_HANDOFF, false);
        long binderGeneration = args.getLong(ATTACH_APPLICATION_BINDER_GENERATION, 0);

        int callingPid = Binder.getCallingPid();
        int callingUid = Binder.getCallingUid();
        boolean isManager, isSettings;
        ClientRecord clientRecord = null;

        List<String> packages = PackageManagerApis.getPackagesForUidNoThrow(callingUid);
        if (!packages.contains(requestPackageName)) {
            throw new SecurityException(
                    "Request package " + requestPackageName + "does not belong to uid " + callingUid);
        }

        isManager = systemUiPackageName.equals(requestPackageName);
        isSettings = settingsPackageName.equals(requestPackageName);

        if (isManager) {
            IBinder binder = application.asBinder();
            try {
                binder.linkToDeath(
                        new IBinder.DeathRecipient() {

                            @Override
                            public void binderDied() {
                                flog.w("manager binder is dead, pid=%d", callingPid);

                                synchronized (managerBinderLock) {
                                    if (systemUiApplication.asBinder() == binder) {
                                        systemUiApplication = null;
                                    } else {
                                        flog.w("binderDied is called later than the arrival of the new binder ?!");
                                    }
                                }

                                binder.unlinkToDeath(this, 0);
                            }
                        },
                        0);
            } catch (RemoteException e) {
                LOGGER.w(e, "attachApplication");
            }

            synchronized (managerBinderLock) {
                systemUiApplication = application;
                flog.i("manager attached: pid=%d", callingPid);
            }
        }

        if (!isManager && !isSettings) {
            ClientRecord existing = clientManager.findClient(callingUid, callingPid);
            if (existing != null) {
                if (existing.client.asBinder() != application.asBinder()
                        || !requestPackageName.equals(existing.packageName)) {
                    throw new IllegalStateException(
                            "Client (uid=" + callingUid + ", pid=" + callingPid + ") has already attached");
                }
                clientRecord = existing;
                SuiConfig.PackageEntry packageEntry = configManager.find(callingUid);
                clientRecord.allowed = packageEntry != null && isPermissionAllowedForCurrentServer(packageEntry.flags);
                clientRecord.onetime = false;
            } else {
                synchronized (this) {
                    clientRecord = clientManager.addClient(
                            callingUid, callingPid, application, requestPackageName, apiVersion);
                }
                if (clientRecord == null) {
                    return;
                }
            }
            clientRecord.supportsServerBinderHandoff = supportsServerBinderHandoff;
        }

        int replyServerVersion = ShizukuApiConstants.SERVER_VERSION;
        if (!isManager && !isSettings && apiVersion == -1) {
            // ShizukuBinderWrapper has adapted API v13 in dev.rikka.shizuku:api 12.2.0, however
            // attachApplication in 12.2.0 is still old, so that server treat the client as pre 13.
            // This finally cause transactRemote fails.
            // So we can pass 12 here to pretend we are v12 server.
            replyServerVersion = 12;
        }

        Bundle reply = new Bundle();
        reply.putInt(BIND_APPLICATION_SERVER_UID, OsUtils.getUid());
        if (binderGeneration != 0) {
            reply.putLong(BIND_APPLICATION_BINDER_GENERATION, binderGeneration);
        }
        reply.putInt(BIND_APPLICATION_SERVER_VERSION, replyServerVersion);
        reply.putString(BIND_APPLICATION_SERVER_SECONTEXT, OsUtils.getSELinuxContext());
        reply.putInt(BIND_APPLICATION_SERVER_PATCH_VERSION, ShizukuApiConstants.SERVER_PATCH_VERSION);
        if (!isManager && !isSettings) {
            reply.putBoolean(BIND_APPLICATION_PERMISSION_GRANTED, isClientAuthorized(clientRecord));
            reply.putBoolean(
                    BIND_APPLICATION_SHOULD_SHOW_REQUEST_PERMISSION_RATIONALE,
                    shouldShowRequestPermissionRationale(clientRecord));
        }
        try {
            application.bindApplication(reply);
        } catch (Throwable e) {
            LOGGER.w(e, "attachApplication");
        }
    }

    @Override
    public void showPermissionConfirmation(
            int requestCode, @NonNull ClientRecord clientRecord, int callingUid, int callingPid, int userId) {
        if (systemUiApplication != null) {
            markPendingPermissionConfirmation(callingUid, callingPid, requestCode);
            try {
                systemUiApplication.showPermissionConfirmation(
                        callingUid, callingPid, clientRecord.packageName, requestCode);
            } catch (Throwable e) {
                LOGGER.w(e, "showPermissionConfirmation");
                finishPermissionConfirmation(callingUid, callingPid, requestCode, false, true, false, true);
            }
        } else if (shellMode) {
            LOGGER.i("Delegating showPermissionConfirmation to root server");
            RootBridgeDelegate.delegatePermissionConfirmationToRoot(
                    clientManager, requestCode, clientRecord.packageName, callingUid, callingPid);
        } else {
            LOGGER.e("manager is null");
            finishPermissionConfirmation(callingUid, callingPid, requestCode, false, true, false, false);
        }
    }

    private boolean shouldShowRequestPermissionRationale(ClientRecord record) {
        SuiConfig.PackageEntry entry = configManager.find(record.uid);
        return entry != null && entry.isDenied();
    }

    @Override
    public boolean isHidden(int uid) {
        if (Binder.getCallingUid() != 1000) {
            // only allow to be called by system server
            return false;
        }

        return uid != systemUiUid && uid != settingsUid && configManager.isHidden(uid);
    }

    @Override
    public void dispatchPermissionConfirmationResult(int requestUid, int requestPid, int requestCode, Bundle data) {
        int callingUid = Binder.getCallingUid();
        if (callingUid != systemUiUid) {
            LOGGER.w(
                    "dispatchPermissionConfirmationResult is allowed to be called only from the manager (callingUid=%d, systemUiUid=%d)",
                    callingUid, systemUiUid);
            return;
        }

        if (data == null) {
            return;
        }

        boolean allowed = data.getBoolean(REQUEST_PERMISSION_REPLY_ALLOWED);
        boolean onetime = data.getBoolean(REQUEST_PERMISSION_REPLY_IS_ONETIME);
        boolean isShell = data.getBoolean(ShizukuApiConstants.REQUEST_PERMISSION_REPLY_IS_SHELL);
        finishPermissionConfirmation(requestUid, requestPid, requestCode, allowed, onetime, isShell, true);
    }

    private int getFlagsForUidInternal(int uid, int mask) {
        SuiConfig.PackageEntry entry = configManager.findExplicit(uid);
        if (entry != null) {
            return entry.flags & mask;
        }
        return 0;
    }

    @Override
    public int getFlagsForUid(int uid, int mask) {
        int callingUid = Binder.getCallingUid();
        if (callingUid != uid && callingUid != systemUiUid && callingUid != settingsUid && callingUid != 1000) {
            return 0;
        }
        SuiConfig.PackageEntry entry = configManager.find(uid);
        if (entry != null) {
            return entry.flags & mask;
        }
        return 0;
    }

    @Override
    public void updateFlagsForUid(int uid, int mask, int value) {
        enforceManagerPermission("updateFlagsForUid");

        int oldEffectiveFlags = 0;
        SuiConfig.PackageEntry oldEffectiveEntry = configManager.find(uid);
        if (oldEffectiveEntry != null) {
            oldEffectiveFlags = oldEffectiveEntry.flags & SuiConfig.MASK_PERMISSION;
        }
        int permissionMask = mask & SuiConfig.MASK_PERMISSION;
        int anticipatedPermissionFlags = (oldEffectiveFlags & ~permissionMask) | (value & permissionMask);
        boolean capabilityBarrier = permissionMask != 0
                && requiresCurrentServerCapabilityReset(oldEffectiveFlags, anticipatedPermissionFlags);
        if (capabilityBarrier) {
            beginPermissionTransition(uid);
        }
        try {
            configManager.update(uid, mask, value);

            if (permissionMask == 0) {
                return;
            }

            int newEffectiveFlags = 0;
            SuiConfig.PackageEntry newEffectiveEntry = configManager.find(uid);
            if (newEffectiveEntry != null) {
                newEffectiveFlags = newEffectiveEntry.flags & SuiConfig.MASK_PERMISSION;
            }
            updateClientAllowedStateForUid(uid, newEffectiveFlags);

            java.util.List<ClientFallback> shellFallbacks = java.util.Collections.emptyList();
            if (!shellMode
                    && (oldEffectiveFlags == SuiConfig.FLAG_ALLOWED_SHELL
                            || newEffectiveFlags == SuiConfig.FLAG_ALLOWED_SHELL)) {
                shellFallbacks = flushShellRoutingState();
            }

            // Always sync UIDs to system_server when permission flags change
            syncUidsToSystemServer();

            if (newEffectiveFlags != oldEffectiveFlags) {
                if (getServerUidForPermissionFlags(newEffectiveFlags) != -1) {
                    java.util.List<ClientFallback> handoffFallbacks = handoffClientsForUid(uid, newEffectiveFlags);
                    if (!handoffFallbacks.isEmpty()) {
                        invalidateFallbacks(handoffFallbacks, "Binder handoff failed");
                    }
                } else {
                    invalidatePackagesForUid(uid, "Permission changed");
                }
            }

            if (!shellFallbacks.isEmpty()) {
                invalidateFallbacks(shellFallbacks, "Shell client migration failed");
            }
        } finally {
            if (capabilityBarrier) {
                finishPermissionTransition(uid);
            }
        }
    }

    @Override
    public void dispatchPackageChanged(Intent intent) {
        int callingUid = Binder.getCallingUid();
        if (callingUid != 1000 && callingUid != 0) {
            return;
        }
        if (intent == null) {
            return;
        }

        String action = intent.getAction();
        int uid = intent.getIntExtra(Intent.EXTRA_UID, -1);
        boolean replacing = intent.getBooleanExtra(Intent.EXTRA_REPLACING, false);
        if (Intent.ACTION_PACKAGE_REMOVED.equals(action) && uid > 0 && !replacing) {
            LOGGER.i("uid %d is removed", uid);
            configManager.remove(uid);
            removePendingPermissionConfirmationsForUid(uid);
            if (!shellMode) {
                flushShellRoutingState();
            }
            syncUidsToSystemServer();
        } else if (Intent.ACTION_PACKAGE_FULLY_REMOVED.equals(action) && !replacing) {
            Uri uri = intent.getData();
            String packageName = (uri != null) ? uri.getSchemeSpecificPart() : null;
            if (packageName != null) {
                userServiceManager.removeUserServicesForPackage(packageName);
            }
        }
    }

    private ParcelableListSlice<AppInfo> getApplications(int userId, boolean onlyShizuku) {
        enforceManagerPermission("getApplications");
        return AppListBuilder.build(configManager, systemUiUid, userId, onlyShizuku);
    }

    private void showManagement() {
        enforceManagerPermission("showManagement");

        if (systemUiApplication != null) {
            Parcel data = Parcel.obtain();
            data.writeInterfaceToken(ShizukuApiConstants.BINDER_DESCRIPTOR);
            try {
                systemUiApplication
                        .asBinder()
                        .transact(ServerConstants.BINDER_TRANSACTION_showManagement, data, null, IBinder.FLAG_ONEWAY);
            } catch (Throwable e) {
                LOGGER.w(e, "showPermissionConfirmation");
            } finally {
                data.recycle();
            }
        } else {
            LOGGER.e("manager is null");
        }
    }

    private ParcelFileDescriptor openApk() {
        if (!checkCallerManagerPermission("openApk", Binder.getCallingUid(), Binder.getCallingPid())) {
            LOGGER.w("openApk is allowed to be called only from settings and system ui");
            return null;
        }
        String pathname = filesPath + "/sui.apk";
        try {
            //noinspection OctalInteger
            Os.chmod(pathname, 0655);
        } catch (ErrnoException e) {
            LOGGER.e(e, "Cannot chmod %s", pathname);
        }

        try {
            return ParcelFileDescriptor.open(new File(pathname), ParcelFileDescriptor.MODE_READ_ONLY);
        } catch (FileNotFoundException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public boolean onTransact(int code, Parcel data, Parcel reply, int flags) throws RemoteException {
        // LOGGER.d("transact: code=%d, calling uid=%d", code, Binder.getCallingUid());
        if (code == ServerConstants.BINDER_TRANSACTION_getApplications) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            int userId = data.readInt();
            boolean onlyShizuku = data.readInt() != 0;

            try {
                ParcelableListSlice<AppInfo> result = getApplications(userId, onlyShizuku);

                reply.writeNoException();
                if (result != null) {
                    reply.writeInt(1);
                    result.writeToParcel(reply, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
                } else {
                    reply.writeInt(0);
                }
            } catch (Throwable e) {
                if (e instanceof Error) {
                    LOGGER.e(e, "Fatal error occurred, terminating.");
                    throw (Error) e;
                }
                LOGGER.e(e, "An exception occurred inside getApplications(). This is the root cause.");

                reply.writeException(new RuntimeException("Sui root service crashed while trying to get app list.", e));
            }

            return true;
        } else if (code == ServerConstants.BINDER_TRANSACTION_showManagement) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            showManagement();
            return true;
        } else if (code == ServerConstants.BINDER_TRANSACTION_openApk) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            ParcelFileDescriptor result = openApk();
            reply.writeNoException();
            if (result != null) {
                reply.writeInt(1);
                result.writeToParcel(reply, android.os.Parcelable.PARCELABLE_WRITE_RETURN_VALUE);
            } else {
                reply.writeInt(0);
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_REQUEST_PINNED_SHORTCUT_FROM_UI) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);

            try {
                enforceManagerPermission("requestPinnedShortcut");
                if (systemUiApplication != null) {
                    systemUiApplication
                            .asBinder()
                            .transact(
                                    ServerConstants.BINDER_TRANSACTION_SEND_SHORTCUT_BROADCAST,
                                    data,
                                    null,
                                    IBinder.FLAG_ONEWAY);
                    reply.writeNoException();
                } else {
                    reply.writeException(new IllegalStateException("SystemUI is not attached yet."));
                }
            } catch (Throwable e) {
                LOGGER.w(e, "Failed to relay request pinned shortcut to SystemUI");
                reply.writeException(new RuntimeException("Failed to relay request to SystemUI", e));
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_BATCH_UPDATE_UNCONFIGURED) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);

            int targetMode = data.readInt() & SuiConfig.MASK_PERMISSION;
            try {
                enforceManagerPermission("setDefaultPermissionFlags");
                if (targetMode != 0 && (targetMode & (targetMode - 1)) != 0) {
                    throw new IllegalArgumentException("Invalid targetMode: " + targetMode);
                }
                int oldDefaultMode = configManager.getDefaultPermissionFlags();
                java.util.Map<Integer, java.util.Set<String>> affectedPackagesByUid =
                        collectUnconfiguredAffectedPackages();
                java.util.List<Integer> barrierUids = new java.util.ArrayList<>();
                if (!shellMode && requiresCurrentServerCapabilityReset(oldDefaultMode, targetMode)) {
                    for (int uid : affectedPackagesByUid.keySet()) {
                        beginPermissionTransition(uid);
                        barrierUids.add(uid);
                    }
                }
                try {
                    configManager.setDefaultPermissionFlags(targetMode);
                    java.util.List<ClientFallback> shellFallbacks = java.util.Collections.emptyList();
                    if (!shellMode
                            && (oldDefaultMode == SuiConfig.FLAG_ALLOWED_SHELL
                                    || targetMode == SuiConfig.FLAG_ALLOWED_SHELL)) {
                        shellFallbacks = flushShellRoutingState();
                    }
                    if (!shellMode) {
                        syncUidsToSystemServer();
                        refreshUnconfiguredClientsForDefaultPermissionTransition(
                                oldDefaultMode, targetMode, affectedPackagesByUid);
                        if (!shellFallbacks.isEmpty()) {
                            invalidateFallbacks(shellFallbacks, "Shell client migration failed");
                        }
                    }
                } finally {
                    for (int i = barrierUids.size() - 1; i >= 0; --i) {
                        finishPermissionTransition(barrierUids.get(i));
                    }
                }
                reply.writeNoException();
            } catch (Throwable e) {
                LOGGER.w(e, "setDefaultPermissionFlags");
                reply.writeException(new RuntimeException("Failed to set default permission flags", e));
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_reloadShellConfig) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            long expectedTransitionId = data.readLong();
            try {
                if (!shellMode) {
                    throw new IllegalStateException("reloadShellConfig is only available in shell mode");
                }
                SuiConfigManager.ShellReloadResult result = configManager.reloadShellConfig(expectedTransitionId);
                reply.writeNoException();
                reply.writeLong(result.transitionId);
                reply.writeInt(result.applied ? 1 : 0);
                reply.writeInt(result.fallbacks.size());
                for (ClientFallback fallback : result.fallbacks) {
                    reply.writeInt(fallback.uid);
                    reply.writeInt(fallback.pid);
                    reply.writeString(fallback.packageName);
                }
            } catch (Throwable e) {
                LOGGER.w(e, "reloadShellConfig");
                reply.writeException(new RuntimeException("Failed to reload shell config", e));
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_registerUserServiceProcess) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            String token = data.readString();
            try {
                int callingUid = Binder.getCallingUid();
                int callingPid = Binder.getCallingPid();
                int expectedUid = OsUtils.getUid();
                if (callingUid != expectedUid) {
                    throw new SecurityException("user-service registration uid " + callingUid
                            + " does not match server uid " + expectedUid);
                }

                int pgid = readProcessGroupId(callingPid);
                if (pgid != callingPid) {
                    throw new SecurityException("user-service process " + callingPid
                            + " is not a process-group leader (pgid=" + pgid + ")");
                }

                boolean registered = userServiceManager.registerUserServiceProcess(token, callingPid, pgid);
                reply.writeNoException();
                reply.writeInt(registered ? 1 : 0);
            } catch (Throwable e) {
                LOGGER.w(e, "registerUserServiceProcess");
                reply.writeException(new RuntimeException("Failed to register user-service process", e));
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_getGlobalSettings) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            try {
                int settingFlags = configManager.getGlobalSettings();
                reply.writeNoException();
                reply.writeInt(settingFlags);
            } catch (Throwable e) {
                LOGGER.w(e, "getGlobalSettings");
                reply.writeException(new RuntimeException("Failed to get global settings", e));
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_setGlobalSettings) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            int settingFlags = data.readInt();
            try {
                enforceManagerPermission("setGlobalSettings");
                configManager.setGlobalSettings(settingFlags);
                reply.writeNoException();
            } catch (Throwable e) {
                LOGGER.w(e, "setGlobalSettings");
                reply.writeException(new RuntimeException("Failed to set global settings", e));
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_getShortcutToken) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            try {
                enforceManagerPermission("getShortcutToken");
                String token = configManager.getShortcutToken();
                reply.writeNoException();
                reply.writeString(token);
            } catch (Throwable e) {
                LOGGER.w(e, "getShortcutToken");
                reply.writeException(new RuntimeException("Failed to get shortcut token", e));
            }
            return true;
        }
        if (code == ServerConstants.BINDER_TRANSACTION_requestPermissionFromShell) {
            data.enforceInterface(ShizukuApiConstants.BINDER_DESCRIPTOR);
            int callingUid = Binder.getCallingUid();
            if (!isTrustedPermissionDelegateCaller(callingUid)) {
                LOGGER.w(
                        "requestPermissionFromShell is allowed only from trusted delegates (callingUid=%d)",
                        callingUid);
                return false;
            }
            int requestCode = data.readInt();
            String packageName = data.readString();
            int reqUid = data.readInt();
            int reqPid = data.readInt();
            android.os.IBinder callback = data.readStrongBinder();

            List<String> packages = PackageManagerApis.getPackagesForUidNoThrow(reqUid);
            if (packageName == null || !packages.contains(packageName)) {
                LOGGER.w(
                        "requestPermissionFromShell rejected: package %s does not belong to uid %d",
                        packageName, reqUid);
                return false;
            }

            if (reqPid <= 0) {
                LOGGER.w("requestPermissionFromShell rejected: invalid pid %d for uid %d", reqPid, reqUid);
                return false;
            }

            String key = buildPermissionRequestKey(reqUid, reqPid, requestCode);
            if (callback != null) {
                putDelegatedPermissionCallback(key, callback);
            }

            int userId = UserHandleCompat.getUserId(reqUid);
            ClientRecord dummy = new ClientRecord(reqUid, reqPid, null, packageName, -1);
            showPermissionConfirmation(requestCode, dummy, reqUid, reqPid, userId);
            return true;
        }
        return super.onTransact(code, data, reply, flags);
    }

    @Override
    public int[] getHiddenUids() {
        if (Binder.getCallingUid() != 1000) {
            throw new SecurityException();
        }
        return configManager.getHiddenUids();
    }

    @Override
    public void exit() {}
}
