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
import static rikka.shizuku.ShizukuApiConstants.ATTACH_APPLICATION_PACKAGE_NAME;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_PERMISSION_GRANTED;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_PATCH_VERSION;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_SECONTEXT;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_UID;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SERVER_VERSION;
import static rikka.shizuku.ShizukuApiConstants.BIND_APPLICATION_SHOULD_SHOW_REQUEST_PERMISSION_RATIONALE;
import static rikka.shizuku.ShizukuApiConstants.REQUEST_PERMISSION_REPLY_ALLOWED;
import static rikka.shizuku.ShizukuApiConstants.REQUEST_PERMISSION_REPLY_IS_ONETIME;

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
import rikka.sui.util.SettingsPackages;
import rikka.sui.util.UserHandleCompat;

@OptIn(markerClass = androidx.core.os.BuildCompat.PrereleaseSdkCheck.class)
@SuppressWarnings("deprecation")
public class SuiService extends Service<SuiUserServiceManager, SuiClientManager, SuiConfigManager> {

    private static final long DELEGATED_PERMISSION_CALLBACK_TIMEOUT_MS = 5 * 60 * 1000L;

    private static SuiService instance;
    private static String filesPath;
    private static boolean shellMode = false;
    private final Map<String, DelegatedPermissionCallback> delegatedPermissionCallbacks =
            new java.util.concurrent.ConcurrentHashMap<>();

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

    private void reloadShellServerConfig() {
        IBinder shellBinder = requestBinderFromBridge(BridgeConstants.SERVER_UID_SHELL);
        if (shellBinder == null) {
            LOGGER.w("shell binder is null, skip synchronous shell config reload");
            return;
        }

        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(ShizukuApiConstants.BINDER_DESCRIPTOR);
            shellBinder.transact(ServerConstants.BINDER_TRANSACTION_reloadShellConfig, data, reply, 0);
            reply.readException();
        } catch (Throwable e) {
            LOGGER.w(e, "reloadShellServerConfig");
        } finally {
            data.recycle();
            reply.recycle();
        }
    }

    private static boolean isAllowedByFlags(int flags) {
        return (flags & (SuiConfig.FLAG_ALLOWED | SuiConfig.FLAG_ALLOWED_SHELL)) != 0;
    }

    private static boolean shouldAutoRestartAfterPermissionTransition(int oldFlags, int newFlags) {
        return (oldFlags & SuiConfig.FLAG_ALLOWED_SHELL) != 0 || (newFlags & SuiConfig.FLAG_ALLOWED_SHELL) != 0;
    }

    private void updateClientAllowedStateForUid(int uid, int effectiveFlags) {
        boolean allowed = isAllowedByFlags(effectiveFlags);
        for (ClientRecord record : clientManager.findClients(uid)) {
            record.allowed = allowed;
        }
    }

    private void invalidatePackages(
            int uid, @NonNull java.util.Collection<String> packageNames, boolean autoRestart, String reason) {
        if (packageNames.isEmpty()) {
            return;
        }

        long id = android.os.Binder.clearCallingIdentity();
        try {
            for (String packageName : packageNames) {
                try {
                    LOGGER.i("%s for %s (uid %d), force stopping to sever old binders...", reason, packageName, uid);
                    ActivityManagerApis.forceStopPackageNoThrow(packageName, UserHandleCompat.getUserId(uid));
                    getUserServiceManager().removeUserServicesForPackage(packageName);
                    if (autoRestart) {
                        LOGGER.i("Auto-restarting %s dynamically after %s", packageName, reason);
                        AppLaunchUtils.startAppAsUser(packageName, UserHandleCompat.getUserId(uid));
                    }
                } catch (Throwable e) {
                    LOGGER.w(e, "Failed to invalidate package %s", packageName);
                }
            }
        } finally {
            android.os.Binder.restoreCallingIdentity(id);
        }
    }

    private void invalidatePackagesForUid(int uid, boolean autoRestart, String reason) {
        List<String> packages = PackageManagerApis.getPackagesForUidNoThrow(uid);
        invalidatePackages(uid, packages, autoRestart, reason);
    }

    private void refreshUnconfiguredClientsForDefaultPermissionTransition(int oldDefaultMode, int newDefaultMode) {
        java.util.Map<Integer, java.util.Set<String>> affectedPackagesByUid = new java.util.LinkedHashMap<>();
        for (ClientRecord record : clientManager.getClients()) {
            if (record.uid < 10000 || record.uid == systemUiUid || record.uid == settingsUid) {
                continue;
            }
            if (configManager.findExplicit(record.uid) != null) {
                continue;
            }
            if (record.packageName != null) {
                affectedPackagesByUid
                        .computeIfAbsent(record.uid, ignored -> new java.util.LinkedHashSet<>())
                        .add(record.packageName);
            } else {
                affectedPackagesByUid.computeIfAbsent(record.uid, ignored -> new java.util.LinkedHashSet<>());
            }
        }

        for (java.util.Map.Entry<Integer, java.util.Set<String>> entry : affectedPackagesByUid.entrySet()) {
            int uid = entry.getKey();
            updateClientAllowedStateForUid(uid, newDefaultMode);
            if (oldDefaultMode == newDefaultMode) {
                continue;
            }
            invalidatePackages(
                    uid,
                    entry.getValue(),
                    shouldAutoRestartAfterPermissionTransition(oldDefaultMode, newDefaultMode),
                    "Default permission changed");
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
        new SuiService();
        Looper.loop();

        LOGGER.i("server exited");
        System.exit(0);
    }

    private static final String MANAGER_APPLICATION_ID = "com.android.systemui";

    private final SuiClientManager clientManager;
    private final SuiConfigManager configManager;
    private final SuiUserServiceManager userServiceManager;
    private final int systemUiUid;
    private final int settingsUid;
    private IShizukuApplication systemUiApplication;

    private final Object managerBinderLock = new Object();
    private final Object pendingPermissionLock = new Object();
    private final Logger flog = new Logger("Sui", "/cache/sui.log");
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final Map<String, Integer> pendingPermissionConfirmations = new HashMap<>();

    private static String buildPermissionRequestKey(int requestUid, int requestPid, int requestCode) {
        return requestUid + ":" + requestPid + ":" + requestCode;
    }

    private void markPendingPermissionConfirmation(int requestUid, int requestPid, int requestCode) {
        synchronized (pendingPermissionLock) {
            String key = buildPermissionRequestKey(requestUid, requestPid, requestCode);
            pendingPermissionConfirmations.merge(key, 1, Integer::sum);
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
        if (records.isEmpty()) {
            LOGGER.w("dispatchPermissionConfirmationResult: no client for uid %d was found", requestUid);
        } else {
            for (ClientRecord record : records) {
                record.allowed = allowed;
                if (record.pid == requestPid) {
                    record.dispatchRequestPermissionResult(requestCode, allowed);
                }
            }
        }

        String key = requestUid + ":" + requestPid;
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

        if (!onetime) {
            int flag =
                    allowed ? (isShell ? SuiConfig.FLAG_ALLOWED_SHELL : SuiConfig.FLAG_ALLOWED) : SuiConfig.FLAG_DENIED;
            configManager.update(requestUid, SuiConfig.MASK_PERMISSION, flag);

            if (!shellMode && isShell) {
                flushShellRoutingState();
            }

            if (!shellMode) {
                syncUidsToSystemServer();
            }

            if (isShell) {
                for (ClientRecord record : records) {
                    if (record.packageName != null) {
                        try {
                            LOGGER.i("Force stopping and restarting %s to re-acquire shell binder", record.packageName);
                            long id = android.os.Binder.clearCallingIdentity();
                            try {
                                ActivityManagerApis.forceStopPackageNoThrow(
                                        record.packageName, UserHandleCompat.getUserId(requestUid));
                                LOGGER.i("Auto-restarting %s dynamically", record.packageName);
                                AppLaunchUtils.startAppAsUser(
                                        record.packageName, UserHandleCompat.getUserId(requestUid));
                            } finally {
                                android.os.Binder.restoreCallingIdentity(id);
                            }
                        } catch (Throwable e) {
                            LOGGER.w(e, "Failed to force stop/restart package %s", record.packageName);
                        }
                    }
                }
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

    private void flushShellRoutingState() {
        if (shellMode) {
            return;
        }
        configManager.syncUidsToShellFileNow();
        reloadShellServerConfig();
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

    private static boolean isSettingsPackageName(String packageName) {
        for (String candidate : SettingsPackages.SETTINGS_CANDIDATES) {
            if (candidate.equals(packageName)) {
                return true;
            }
        }
        return false;
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

    public SuiService() {
        super();

        HandlerUtil.setMainHandler(mainHandler);

        SuiService.instance = this;

        configManager = getConfigManager();
        clientManager = getClientManager();
        userServiceManager = getUserServiceManager();

        systemUiUid = waitForPackage(MANAGER_APPLICATION_ID, true);
        settingsUid = waitForPackage(SettingsPackages.SETTINGS_CANDIDATES, true);

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
        if ("transactRemote".equals(func)) {
            SuiConfig.PackageEntry packageEntry = configManager.find(callingUid);
            return packageEntry != null && (packageEntry.isAllowed() || packageEntry.isAllowedShell());
        }
        return false;
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

        int callingPid = Binder.getCallingPid();
        int callingUid = Binder.getCallingUid();
        boolean isManager, isSettings;
        ClientRecord clientRecord = null;

        List<String> packages = PackageManagerApis.getPackagesForUidNoThrow(callingUid);
        if (!packages.contains(requestPackageName)) {
            throw new SecurityException(
                    "Request package " + requestPackageName + "does not belong to uid " + callingUid);
        }

        isManager = MANAGER_APPLICATION_ID.equals(requestPackageName);
        isSettings = isSettingsPackageName(requestPackageName);

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
            if (clientManager.findClient(callingUid, callingPid) != null) {
                throw new IllegalStateException(
                        "Client (uid=" + callingUid + ", pid=" + callingPid + ") has already attached");
            }
            synchronized (this) {
                clientRecord =
                        clientManager.addClient(callingUid, callingPid, application, requestPackageName, apiVersion);
            }
            if (clientRecord == null) {
                return;
            }
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
        reply.putInt(BIND_APPLICATION_SERVER_VERSION, replyServerVersion);
        reply.putString(BIND_APPLICATION_SERVER_SECONTEXT, OsUtils.getSELinuxContext());
        reply.putInt(BIND_APPLICATION_SERVER_PATCH_VERSION, ShizukuApiConstants.SERVER_PATCH_VERSION);
        if (!isManager && !isSettings) {
            reply.putBoolean(BIND_APPLICATION_PERMISSION_GRANTED, clientRecord.allowed);
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
        configManager.update(uid, mask, value);

        if ((mask & SuiConfig.MASK_PERMISSION) != 0) {
            int newEffectiveFlags = 0;
            SuiConfig.PackageEntry newEffectiveEntry = configManager.find(uid);
            if (newEffectiveEntry != null) {
                newEffectiveFlags = newEffectiveEntry.flags & SuiConfig.MASK_PERMISSION;
            }
            boolean allowed = (newEffectiveFlags & (SuiConfig.FLAG_ALLOWED | SuiConfig.FLAG_ALLOWED_SHELL)) != 0;
            for (ClientRecord record : clientManager.findClients(uid)) {
                record.allowed = allowed;
            }

            if (newEffectiveFlags != oldEffectiveFlags) {
                invalidatePackagesForUid(uid, false, "Permission changed");
            }

            if (!shellMode
                    && ((oldEffectiveFlags & SuiConfig.FLAG_ALLOWED_SHELL) != 0
                            || (newEffectiveFlags & SuiConfig.FLAG_ALLOWED_SHELL) != 0)) {
                flushShellRoutingState();
            }

            // Always sync UIDs to system_server when permission flags change
            syncUidsToSystemServer();
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
                configManager.setDefaultPermissionFlags(targetMode);
                if (!shellMode
                        && (oldDefaultMode == SuiConfig.FLAG_ALLOWED_SHELL
                                || targetMode == SuiConfig.FLAG_ALLOWED_SHELL)) {
                    flushShellRoutingState();
                }
                if (!shellMode) {
                    syncUidsToSystemServer();
                    refreshUnconfiguredClientsForDefaultPermissionTransition(oldDefaultMode, targetMode);
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
            try {
                if (!shellMode) {
                    throw new IllegalStateException("reloadShellConfig is only available in shell mode");
                }
                configManager.reloadShellConfig();
                reply.writeNoException();
            } catch (Throwable e) {
                LOGGER.w(e, "reloadShellConfig");
                reply.writeException(new RuntimeException("Failed to reload shell config", e));
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

            String key = reqUid + ":" + reqPid;
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
