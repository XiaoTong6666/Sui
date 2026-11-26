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

package rikka.sui.resource;

import static rikka.sui.settings.SettingsConstants.LOGGER;

import android.annotation.SuppressLint;
import android.app.ActivityThread;
import android.app.Application;
import android.content.ComponentName;
import android.content.pm.ApplicationInfo;
import android.content.res.AssetManager;
import android.content.res.Resources;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import dalvik.system.BaseDexClassLoader;
import dalvik.system.DexFile;
import dalvik.system.PathClassLoader;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import rikka.sui.util.BridgeServiceClient;
import rikka.sui.util.Log;

@SuppressLint({"DiscouragedPrivateApi", "BlockedPrivateApi"})
@SuppressWarnings("JavaReflectionMemberAccess")
public class SuiApk implements AutoCloseable {

    @SuppressWarnings("FieldCanBeLocal")
    private final ClassLoader classLoader;

    private int apkFd = -1;
    private volatile Resources resources;
    private String apkPath;
    private volatile Class<?> suiActivityClass;
    private volatile Class<?> suiRequestPermissionDialogClass;
    private volatile Constructor<?> suiActivityConstructor;
    private volatile Constructor<?> suiRequestPermissionDialogConstructor;

    public static SuiApk createForSettings() {
        SuiApk apk = null;
        try {
            apk = new SuiApk();
            apk.loadSuiActivity();
            if (apk.getSuiActivityClass() == null || apk.getSuiActivityConstructor() == null) {
                LOGGER.e("Cannot initialize SuiActivity from %s", apk.apkPath);
                apk.close();
                return null;
            }
            return apk;
        } catch (Throwable e) {
            if (apk != null) apk.close();
            Log.e("SuiApk", Log.getStackTraceString(e));
            return null;
        }
    }

    public static SuiApk createForSystemUI() {
        SuiApk apk = null;
        try {
            apk = new SuiApk();
            apk.loadSuiRequestPermissionDialog();
            if (apk.getSuiRequestPermissionDialogClass() == null
                    || apk.getSuiRequestPermissionDialogConstructor() == null) {
                LOGGER.e("Cannot initialize SuiRequestPermissionDialog from %s", apk.apkPath);
                apk.close();
                return null;
            }
            return apk;
        } catch (Throwable e) {
            if (apk != null) apk.close();
            Log.e("SuiApk", Log.getStackTraceString(e));
            return null;
        }
    }

    private SuiApk() throws Exception {
        // The APK now requires a Binder FD; let Settings retry off the main thread.
        if (BridgeServiceClient.getService() == null) {
            throw new IllegalStateException("Sui server binder is not ready");
        }

        // Keep the detached APK FD alive for class and resource reopens.
        // https://android.googlesource.com/platform/frameworks/base/+/android-5.0.0_r6/core/java/android/os/ParcelFileDescriptor.java#570
        try {
            try (ParcelFileDescriptor pfd = Objects.requireNonNull(BridgeServiceClient.openApk())) {
                apkFd = pfd.detachFd();
            }
            apkPath = "/proc/self/fd/" + apkFd;
            LOGGER.i("SuiApk: Using FD path: %s", apkPath);
            if (Build.VERSION.SDK_INT == Build.VERSION_CODES.O || Build.VERSION.SDK_INT == Build.VERSION_CODES.O_MR1) {
                // Oreo's OatFileAssistant calls realpath(): the Binder FD alias
                // may fail to resolve or resolve to an inaccessible module path.
                // https://android.googlesource.com/platform/art/+/android-8.0.0_r1/runtime/oat_file_assistant.cc#91
                // A failed checksum lookup marks the original DEX as missing,
                // so ART skips the fallback and reports "No original dex files found".
                // https://android.googlesource.com/platform/art/+/android-8.0.0_r1/runtime/oat_file_assistant.cc#808
                // https://android.googlesource.com/platform/art/+/android-8.0.0_r1/runtime/oat_file_manager.cc#765
                classLoader = createOreoClassLoader();
            } else {
                // Nougat preserves the supplied path; Pie restores that behavior.
                // https://android.googlesource.com/platform/art/+/android-7.1.1_r1/runtime/oat_file_assistant.cc#79
                // https://android.googlesource.com/platform/art/+/android-9.0.0_r1/runtime/oat_file_assistant.cc#110
                classLoader = new PathClassLoader(apkPath, ClassLoader.getSystemClassLoader());
            }
            reloadResources();
        } catch (Exception | Error e) {
            close();
            throw e;
        }
    }

    private ClassLoader createOreoClassLoader() throws Exception {
        List<ByteBuffer> buffers = new ArrayList<>();
        try (ZipFile zip = new ZipFile(apkPath)) {
            // Preserve APK multidex order and use a single defining class loader.
            for (int i = 1; ; i++) {
                String name = i == 1 ? "classes.dex" : "classes" + i + ".dex";
                ZipEntry entry = zip.getEntry(name);
                if (entry == null) break;
                long size = entry.getSize();
                if (size <= 0 || size > Integer.MAX_VALUE) {
                    throw new IOException("Invalid DEX entry size: " + name);
                }
                byte[] bytes = new byte[(int) size];
                try (DataInputStream input = new DataInputStream(zip.getInputStream(entry))) {
                    input.readFully(bytes);
                    if (input.read() != -1) {
                        throw new IOException("Unexpected DEX entry size: " + name);
                    }
                }
                buffers.add(ByteBuffer.wrap(bytes));
            }
        }
        if (buffers.isEmpty()) {
            throw new IOException("Sui APK contains no DEX files");
        }
        // Both Oreo releases implement the array constructor; API 26 hides it.
        // https://android.googlesource.com/platform/libcore/+/android-8.0.0_r1/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java#35
        Constructor<?> constructor = Class.forName("dalvik.system.InMemoryDexClassLoader")
                .getConstructor(ByteBuffer[].class, ClassLoader.class);
        LOGGER.i("SuiApk: Loading %d DEX files in memory on Oreo", buffers.size());
        // ART copies the heap buffers into its own mappings during construction.
        // https://android.googlesource.com/platform/art/+/android-8.0.0_r1/runtime/native/dalvik_system_DexFile.cc#241
        return (ClassLoader)
                constructor.newInstance(buffers.toArray(new ByteBuffer[0]), ClassLoader.getSystemClassLoader());
    }

    @Override
    public synchronized void close() {
        if (apkFd < 0) return;
        int fd = apkFd;
        apkFd = -1;
        Resources failedResources = resources;
        resources = null;
        try {
            if (failedResources != null) {
                try {
                    failedResources.getAssets().close();
                } catch (RuntimeException e) {
                    LOGGER.w(e, "Cannot close failed Sui APK assets");
                }
            }
            closeFailedClassLoader();
        } finally {
            // detachFd transfers ownership to us; close only on failed initialization.
            // https://android.googlesource.com/platform/frameworks/base/+/android-5.0.0_r6/core/java/android/os/ParcelFileDescriptor.java#307
            try {
                ParcelFileDescriptor.adoptFd(fd).close();
            } catch (IOException e) {
                LOGGER.w(e, "Cannot close failed Sui APK FD");
            }
        }
    }

    private void closeFailedClassLoader() {
        if (!(classLoader instanceof BaseDexClassLoader)) return;
        try {
            Field pathList = BaseDexClassLoader.class.getDeclaredField("pathList");
            pathList.setAccessible(true);
            Object list = pathList.get(classLoader);
            Field dexElements = list.getClass().getDeclaredField("dexElements");
            dexElements.setAccessible(true);
            // DexPathList holds both DEX and lazy ZIP handles, even if no class is found.
            // https://android.googlesource.com/platform/libcore/+/android-6.0.1_r11/dalvik/src/main/java/dalvik/system/DexPathList.java#413
            for (Object element : (Object[]) dexElements.get(list)) {
                for (String name : new String[] {"dexFile", "zipFile"}) {
                    try {
                        Field field = element.getClass().getDeclaredField(name);
                        field.setAccessible(true);
                        Object resource = field.get(element);
                        if (resource instanceof DexFile) {
                            ((DexFile) resource).close();
                        } else if (resource instanceof ZipFile) {
                            ((ZipFile) resource).close();
                        }
                    } catch (NoSuchFieldException ignored) {
                        // Newer ART versions no longer retain a Java ZipFile.
                    } catch (ReflectiveOperationException | IOException | RuntimeException e) {
                        LOGGER.w(e, "Cannot close failed Sui class loader element");
                    }
                }
            }
        } catch (ReflectiveOperationException | RuntimeException e) {
            LOGGER.w(e, "Cannot close failed Sui class loader resources");
        }
    }

    @SuppressWarnings("deprecation")
    public void reloadResources() throws Exception {
        AssetManager am = AssetManager.class.getConstructor().newInstance();
        try {
            loadResources(am);
        } catch (Exception | Error e) {
            am.close();
            throw e;
        }
    }

    private void loadResources(AssetManager am) throws Exception {
        Method addAssetPath = AssetManager.class.getDeclaredMethod("addAssetPath", String.class);
        // AssetManager still needs the APK FD for resources, even when Oreo loads
        // DEX from memory. FD aliases were verified on Android 6 and 8.0.
        // https://android.googlesource.com/platform/frameworks/base/+/android-6.0.1_r11/core/java/android/content/res/AssetManager.java#608
        addAssetPath.setAccessible(true);
        int cookie = (Integer) addAssetPath.invoke(am, apkPath);
        if (cookie == 0) {
            throw new IOException("Cannot load Sui APK resources: " + apkPath);
        }

        Application application = ActivityThread.currentActivityThread().getApplication();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            Method addOverlayPath = AssetManager.class.getDeclaredMethod("addOverlayPath", String.class);
            addOverlayPath.setAccessible(true);

            ApplicationInfo ai = application.getApplicationInfo();
            Field field = ApplicationInfo.class.getDeclaredField("overlayPaths");
            String[] overlayPaths = (String[]) field.get(ai);

            if (overlayPaths != null) {
                for (String overlayPath : overlayPaths) {
                    addOverlayPath.invoke(am, overlayPath);
                }
            }
        }

        Resources newResources = new Resources(
                am,
                application.getResources().getDisplayMetrics(),
                application.getResources().getConfiguration());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            Field classLoaderField = Resources.class.getDeclaredField("mClassLoader");
            classLoaderField.setAccessible(true);
            classLoaderField.set(newResources, classLoader);
        }

        this.resources = newResources;
    }

    @SuppressWarnings("deprecation")
    public void updateConfiguration(android.content.res.Configuration newConfig) throws Exception {
        Resources res = this.resources;
        if (res != null) {
            res.updateConfiguration(newConfig, res.getDisplayMetrics());
        }
    }

    private void loadSuiActivity() {
        try {
            suiActivityClass = classLoader.loadClass("rikka.sui.SuiActivity");
            suiActivityConstructor =
                    suiActivityClass.getDeclaredConstructor(Application.class, Resources.class, ComponentName.class);
        } catch (Throwable e) {
            LOGGER.e(e, "Cannot load SuiActivity class");
        }
    }

    private void loadSuiRequestPermissionDialog() {
        try {
            suiRequestPermissionDialogClass = classLoader.loadClass("rikka.sui.SuiRequestPermissionDialog");
            suiRequestPermissionDialogConstructor = suiRequestPermissionDialogClass.getDeclaredConstructor(
                    Application.class, Resources.class, int.class, int.class, String.class, int.class);
        } catch (Throwable e) {
            LOGGER.e(e, "Cannot load SuiRequestPermissionDialog class");
        }
    }

    public ClassLoader getClassLoader() {
        return classLoader;
    }

    public Class<?> getSuiActivityClass() {
        return suiActivityClass;
    }

    public Constructor<?> getSuiActivityConstructor() {
        return suiActivityConstructor;
    }

    public Class<?> getSuiRequestPermissionDialogClass() {
        return suiRequestPermissionDialogClass;
    }

    public Constructor<?> getSuiRequestPermissionDialogConstructor() {
        return suiRequestPermissionDialogConstructor;
    }

    public Resources getResources() {
        return resources;
    }
}
