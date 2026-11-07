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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
package rikka.sui.systemserver;

import static rikka.sui.systemserver.SystemServerConstants.LOGGER;

import android.app.ActivityManager;
import android.app.ActivityThread;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.Process;
import android.util.SparseArray;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;

/**
 * Shizuku-compatible receiver hosted in system_server. SYSTEM_UID may use Shizuku's
 * callerPackage when registering with AMS, without changing AMS or JNI code.
 */
final class ShizukuBinderReceiver {
    private static final String REQUEST_BINDER_ACTION = "rikka.shizuku.intent.action.REQUEST_BINDER";
    private static final String SHIZUKU_PACKAGE = "moe.shizuku.privileged.api";
    // android.os.Process.INVALID_UID was added after Android 6.
    private static final int INVALID_UID = -1;
    private static volatile boolean registered;
    private static IBinder receiverBinder;
    private static Object activityManager;

    private static final BroadcastReceiver RECEIVER = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!REQUEST_BINDER_ACTION.equals(intent.getAction())
                    || !SHIZUKU_PACKAGE.equals(intent.getPackage())) return;

            // Android 14+ provides an authenticated sending UID only when the sender
            // explicitly shares its identity. Older releases keep it inside AMS.
            int uid = Build.VERSION.SDK_INT >= 34 ? getSentFromUid() : INVALID_UID;
            if (uid == INVALID_UID && isOrderedBroadcast()) {
                uid = getOrderedBroadcastUid();
            }
            LOGGER.i(
                    "shizuku alias: received package=%s ordered=%s uid=%d",
                    intent.getPackage(), isOrderedBroadcast(), uid);
            // Receiver registration and sender identification only. Binder delivery
            // remains the responsibility of the original AMS Hook.
        }
    };

    /** Read the real sending UID from AMS's active ordered-broadcast record.
     * Android 6-13 keeps it in ReceiverList.curBroadcast. Modern broadcast
     * queues instead use BroadcastProcessQueue.mActive/mActiveIndex.
     * Fail closed if any part of the active receiver identity cannot be verified.
     */
    private static int getOrderedBroadcastUid() {
        if (activityManager == null || receiverBinder == null) return INVALID_UID;
        try {
            Object owner = activityManager;
            Field mapField = findField(owner.getClass(), "mRegisteredReceivers");
            if (mapField == null) {
                // Newer Android versions have moved broadcast state out of AMS.
                Field controllerField = findField(owner.getClass(), "mBroadcastController");
                if (controllerField == null) return INVALID_UID;
                owner = controllerField.get(owner);
                if (owner == null) return INVALID_UID;
                mapField = findField(owner.getClass(), "mRegisteredReceivers");
                if (mapField == null) return INVALID_UID;
            }
            // In modern AOSP the map is in BroadcastController, but @GuardedBy(mService).
            Object lock = owner == activityManager
                    ? owner
                    : requireField(owner, "mService").get(owner);
            synchronized (lock) {
                Object records = mapField.get(owner);
                if (!(records instanceof Map)) return INVALID_UID;
                Object list = ((Map<?, ?>) records).get(receiverBinder);
                if (list == null) return INVALID_UID;
                Object record = requireField(list, "curBroadcast").get(list);
                if (record == null && owner != activityManager) {
                    // Modern BroadcastQueue no longer populates ReceiverList.curBroadcast.
                    Object modernQueue = requireField(owner, "mBroadcastQueue").get(owner);
                    Field processQueuesField = findField(modernQueue.getClass(), "mProcessQueues");
                    if (processQueuesField != null) {
                        Object allQueues = processQueuesField.get(modernQueue);
                        if (allQueues instanceof SparseArray) {
                            Object processQueue = ((SparseArray<?>) allQueues).get(Process.myUid());
                            while (processQueue != null) {
                                Object active =
                                        requireField(processQueue, "mActive").get(processQueue);
                                if (active != null) {
                                    int index = requireField(processQueue, "mActiveIndex")
                                            .getInt(processQueue);
                                    Object receivers =
                                            requireField(active, "receivers").get(active);
                                    if (receivers instanceof List
                                            && index >= 0
                                            && index < ((List<?>) receivers).size()) {
                                        Object target = ((List<?>) receivers).get(index);
                                        Field receiverListField = findField(target.getClass(), "receiverList");
                                        if (receiverListField != null && receiverListField.get(target) == list) {
                                            record = active;
                                            break;
                                        }
                                    }
                                }
                                processQueue = requireField(processQueue, "processNameNext")
                                        .get(processQueue);
                            }
                        }
                    }
                }
                if (record == null) return INVALID_UID;
                // Legacy queue: verify the current Binder target. Modern queue was
                // already verified via the active receiver's ReceiverList identity.
                Field currentReceiverField = findField(record.getClass(), "receiver");
                if (currentReceiverField != null && currentReceiverField.get(record) != receiverBinder) {
                    return INVALID_UID;
                }
                Intent original = (Intent) requireField(record, "intent").get(record);
                if (original == null
                        || !REQUEST_BINDER_ACTION.equals(original.getAction())
                        || !SHIZUKU_PACKAGE.equals(original.getPackage())
                        || !requireField(record, "ordered").getBoolean(record)) {
                    return INVALID_UID;
                }
                int uid = requireField(record, "callingUid").getInt(record);
                LOGGER.i("shizuku alias: AMS broadcast sender uid=%d", uid);
                return uid;
            }
        } catch (Throwable e) {
            LOGGER.w(e, "shizuku alias: cannot resolve ordered-broadcast sender from AMS");
            return INVALID_UID;
        }
    }

    private static Field findField(Class<?> type, String name) {
        for (Class<?> cls = type; cls != null; cls = cls.getSuperclass()) {
            try {
                Field field = cls.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            } catch (NoSuchFieldException ignored) {
            }
        }
        return null;
    }

    private static Field requireField(Object target, String name) throws NoSuchFieldException {
        Field field = findField(target.getClass(), name);
        if (field == null) throw new NoSuchFieldException(target.getClass().getName() + "." + name);
        return field;
    }

    static synchronized void register(Context systemContext, Handler handler) {
        if (registered) return;
        try {
            ActivityThread thread = ActivityThread.currentActivityThread();
            if (thread == null) return;

            // Use the real framework ReceiverDispatcher: ActivityThread only preserves
            // ordered-broadcast finish and sender UID for its InnerReceiver type.
            Field packageInfoField = requireField(systemContext, "mPackageInfo");
            Object packageInfo = packageInfoField.get(systemContext);
            if (packageInfo == null) throw new IllegalStateException("system LoadedApk missing");
            Method dispatcherMethod = packageInfo
                    .getClass()
                    .getMethod(
                            "getReceiverDispatcher",
                            BroadcastReceiver.class,
                            Context.class,
                            Handler.class,
                            Class.forName("android.app.Instrumentation"),
                            boolean.class);
            Object dispatcher = dispatcherMethod.invoke(packageInfo, RECEIVER, systemContext, handler, null, true);

            Method getApplicationThread = ActivityThread.class.getDeclaredMethod("getApplicationThread");
            getApplicationThread.setAccessible(true);
            Object applicationThread = getApplicationThread.invoke(thread);
            Object am = getActivityManager();
            if (am == null) throw new IllegalStateException("ActivityManager missing");
            Method register = null;
            for (Method candidate : am.getClass().getMethods()) {
                Class<?>[] types = candidate.getParameterTypes();
                if ("registerReceiverWithFeature".equals(candidate.getName())
                        && types.length == 9
                        && "android.content.IIntentReceiver".equals(types[4].getName())) {
                    register = candidate;
                    break;
                }
            }
            if (register == null) {
                for (Method candidate : am.getClass().getMethods()) {
                    Class<?>[] types = candidate.getParameterTypes();
                    if ("registerReceiver".equals(candidate.getName())
                            && (types.length == 6 || types.length == 7)
                            && "android.content.IIntentReceiver".equals(types[2].getName())) {
                        register = candidate;
                        break;
                    }
                }
            }
            if (register == null) throw new NoSuchMethodException("registerReceiver");

            IntentFilter filter = new IntentFilter(REQUEST_BINDER_ACTION);
            filter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
            // Match PackageReceiver: the SYSTEM_UID receiver must be visible to every user.
            int userId = -1; // UserHandle.USER_ALL
            int flags = Build.VERSION.SDK_INT >= 33 ? Context.RECEIVER_EXPORTED : 0;
            int parameterCount = register.getParameterTypes().length;
            if (parameterCount == 9) {
                register.invoke(
                        am,
                        applicationThread,
                        SHIZUKU_PACKAGE,
                        null,
                        null,
                        dispatcher,
                        filter,
                        null,
                        userId,
                        flags);
            } else if (parameterCount == 7) {
                register.invoke(
                        am,
                        applicationThread,
                        SHIZUKU_PACKAGE,
                        dispatcher,
                        filter,
                        null,
                        userId,
                        flags);
            } else {
                register.invoke(
                        am, applicationThread, SHIZUKU_PACKAGE, dispatcher, filter, null, userId);
            }
            receiverBinder = (IBinder) dispatcher;
            activityManager = am;
            registered = true;
            LOGGER.i(
                    "shizuku alias: registered package=%s uid=%d method=%s(%d) am=%s",
                    SHIZUKU_PACKAGE,
                    Process.myUid(),
                    register.getName(),
                    parameterCount,
                    am.getClass().getName());
        } catch (Throwable e) {
            LOGGER.w(e, "shizuku alias: register failed");
        }
    }

    private static Object getActivityManager() throws Exception {
        try {
            Method getService = ActivityManager.class.getDeclaredMethod("getService");
            getService.setAccessible(true);
            return getService.invoke(null);
        } catch (NoSuchMethodException ignored) {
            Class<?> legacy = Class.forName("android.app.ActivityManagerNative");
            Method getDefault = legacy.getDeclaredMethod("getDefault");
            getDefault.setAccessible(true);
            return getDefault.invoke(null);
        }
    }

    private ShizukuBinderReceiver() {}
}
