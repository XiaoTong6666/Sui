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

#include <cstdio>
#include <cstring>
#include <chrono>
#include <fcntl.h>
#include <unistd.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <dirent.h>
#include <jni.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <mntent.h>
#include <sys/mount.h>
#include <sys/sendfile.h>
#include <dlfcn.h>
#include <cinttypes>
#include <string>
#include <vector>
#include <atomic>
#include <unordered_set>
#include <shared_mutex>

#include "android.h"
#include "logging.h"
#include "misc.h"
#include "dex_file.h"
#include "bridge_service.h"
#include "binder_hook.h"
#include "config.h"

typedef uid_t (*AIBinder_getCallingUid_t)();
typedef pid_t (*AIBinder_getCallingPid_t)();

namespace SystemServer {

static jclass mainClass = nullptr;
static jmethodID my_execTransactMethodID;
static jmethodID isUidHiddenEffectiveMethodID;

static jclass javaBinderClass = nullptr;
static jmethodID getCallingUidMethodID = nullptr;

static jint startShortcutTransactionCode = -1;
static jint broadcastIntentTransactionCode = -1;
static jint broadcastIntentWithFeatureTransactionCode = -1;

static std::unordered_set<uid_t> hiddenUids;
static std::unordered_set<uid_t> rootUids;
static std::unordered_set<uid_t> deniedUids;
static std::unordered_set<uid_t> shellUids;
static bool defaultHidden = false;
static std::shared_mutex hiddenUidsMutex;
static bool legacyCompatEnabled = false;
static std::atomic_bool legacyCompatFastEnabled{false};

static bool readUids(JNIEnv* env, jintArray uids, std::unordered_set<uid_t>& result) {
    if (!uids) return true;
    jsize len = env->GetArrayLength(uids);
    if (len == 0) return true;
    jint* body = env->GetIntArrayElements(uids, nullptr);
    if (body == nullptr) {
        return false;
    }
    for (jsize i = 0; i < len; i++) {
        result.insert((uid_t)body[i]);
    }
    env->ReleaseIntArrayElements(uids, body, JNI_ABORT);
    return true;
}

static jboolean setPermissionSnapshot(JNIEnv* env, jclass, jintArray hidden, jintArray root,
                                      jintArray denied, jintArray shell, jboolean isDefaultHidden,
                                      jboolean enabled) {
    std::unordered_set<uid_t> newHidden, newRoot, newDenied, newShell;
    if (!readUids(env, hidden, newHidden) || !readUids(env, root, newRoot) ||
        !readUids(env, denied, newDenied) || !readUids(env, shell, newShell)) {
        return JNI_FALSE;
    }

    std::unique_lock lock(hiddenUidsMutex);
    hiddenUids.swap(newHidden);
    rootUids.swap(newRoot);
    deniedUids.swap(newDenied);
    shellUids.swap(newShell);
    defaultHidden = isDefaultHidden == JNI_TRUE;
    legacyCompatEnabled = enabled == JNI_TRUE;
    legacyCompatFastEnabled.store(legacyCompatEnabled, std::memory_order_release);
    LOGD("updated %zu hidden uids", hiddenUids.size());
    return JNI_TRUE;
}

static bool isUidHiddenLocked(uid_t uid) {
    if (hiddenUids.find(uid) != hiddenUids.end()) return true;
    if (deniedUids.find(uid) != deniedUids.end() || rootUids.find(uid) != rootUids.end() ||
        shellUids.find(uid) != shellUids.end()) return false;
    return defaultHidden;
}

static bool isUidHidden(uid_t uid) {
    std::shared_lock lock(hiddenUidsMutex);
    return isUidHiddenLocked(uid);
}

static bool shouldSkipLegacy(uid_t uid) {
    std::shared_lock lock(hiddenUidsMutex);
    return !legacyCompatEnabled || isUidHiddenLocked(uid);
}

static uid_t getCallingUid(JNIEnv* env) {
    static AIBinder_getCallingUid_t get_uid_ndk = []() -> AIBinder_getCallingUid_t {
        void* libbinder_ndk = dlopen("libbinder_ndk.so", RTLD_NOW);
        return libbinder_ndk ? (AIBinder_getCallingUid_t)dlsym(libbinder_ndk, "AIBinder_getCallingUid")
                             : nullptr;
    }();

    if (get_uid_ndk) return get_uid_ndk();
    if (!getCallingUidMethodID) return (uid_t)-1;
    jint uid = env->CallStaticIntMethod(javaBinderClass, getCallingUidMethodID);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        return (uid_t)-1;
    }
    return (uid_t)uid;
}

static jint getIActivityManagerTransactionCode(JNIEnv* env, jclass stubClass, const char* name) {
    jfieldID field = env->GetStaticFieldID(stubClass, name, "I");
    if (!field) {
        env->ExceptionClear();
        return -1;
    }
    return env->GetStaticIntField(stubClass, field);
}

static void resolveIActivityManagerTransactionCodes(JNIEnv* env) {
    jclass stubClass = env->FindClass("android/app/IActivityManager$Stub");
    if (!stubClass) {
        LOGW("unable to find IActivityManager$Stub for legacy Shizuku compatibility");
        env->ExceptionClear();
        return;
    }

    broadcastIntentTransactionCode =
        getIActivityManagerTransactionCode(env, stubClass, "TRANSACTION_broadcastIntent");
    broadcastIntentWithFeatureTransactionCode = getIActivityManagerTransactionCode(
        env, stubClass, "TRANSACTION_broadcastIntentWithFeature");
    env->DeleteLocalRef(stubClass);

    LOGI(
        "legacy Shizuku broadcast transaction codes: broadcastIntent=%d "
        "broadcastIntentWithFeature=%d",
        broadcastIntentTransactionCode, broadcastIntentWithFeatureTransactionCode);
}

static bool installDex(JNIEnv* env, Dex* dexFile) {
    bool success = false;
    jclass localMainClass = nullptr;
    jclass loadedMainClass = nullptr;
    jclass binderCls = nullptr;
    jclass loadedBinderClass = nullptr;
    jclass stringClass = nullptr;
    jobjectArray args = nullptr;
    jmethodID mainMethod = nullptr;
    JNINativeMethod methods[] = {
        {"setPermissionSnapshot", "([I[I[I[IZZ)Z", (void*)setPermissionSnapshot},
    };

    if (android_get_device_api_level() < 27) {
        dexFile->setPre26Paths("/data/system/sui/" DEX_NAME, "/data/system/sui/oat");
    }
    dexFile->createClassLoader(env);

    localMainClass = dexFile->findClass(env, SYSTEM_PROCESS_CLASSNAME);
    if (!localMainClass) {
        LOGE("unable to find main class");
        goto cleanup;
    }
    loadedMainClass = (jclass)env->NewGlobalRef(localMainClass);
    env->DeleteLocalRef(localMainClass);
    if (!loadedMainClass) {
        LOGE("unable to create main class global ref");
        goto cleanup;
    }

    if (env->RegisterNatives(loadedMainClass, methods, sizeof(methods) / sizeof(methods[0])) < 0) {
        LOGE("unable to register natives");
        goto cleanup;
    }

    mainMethod = env->GetStaticMethodID(loadedMainClass, "main", "([Ljava/lang/String;)V");
    if (!mainMethod) {
        LOGE("unable to find main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    my_execTransactMethodID =
        env->GetStaticMethodID(loadedMainClass, "execTransact", "(Landroid/os/Binder;IJJI)Z");
    if (!my_execTransactMethodID) {
        LOGE("unable to find execTransact");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    isUidHiddenEffectiveMethodID =
        env->GetStaticMethodID(loadedMainClass, "isUidHiddenEffective", "(I)Z");
    if (!isUidHiddenEffectiveMethodID) {
        LOGE("unable to find isUidHiddenEffective");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    binderCls = env->FindClass("android/os/Binder");
    if (binderCls) {
        loadedBinderClass = (jclass)env->NewGlobalRef(binderCls);
        if (!loadedBinderClass) {
            env->DeleteLocalRef(binderCls);
            LOGE("unable to create Binder class global ref");
            goto cleanup;
        }
        if (!getCallingUidMethodID) {
            getCallingUidMethodID =
                env->GetStaticMethodID(loadedBinderClass, "getCallingUid", "()I");
        }
        if (!getCallingUidMethodID) {
            env->ExceptionClear();
            LOGE("unable to find Binder.getCallingUid");
        }
        env->DeleteLocalRef(binderCls);
    } else {
        env->ExceptionClear();
        LOGE("unable to find android.os.Binder class");
    }

    stringClass = env->FindClass("java/lang/String");
    if (!stringClass) {
        LOGE("unable to find java/lang/String");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    args = env->NewObjectArray(0, stringClass, nullptr);
    if (!args) {
        LOGE("unable to allocate argument array");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        goto cleanup;
    }

    env->CallStaticVoidMethod(loadedMainClass, mainMethod, args);
    if (env->ExceptionCheck()) {
        LOGE("unable to call main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    mainClass = loadedMainClass;
    loadedMainClass = nullptr;
    javaBinderClass = loadedBinderClass;
    loadedBinderClass = nullptr;
    resolveIActivityManagerTransactionCodes(env);
    success = true;

cleanup:
    if (args)
        env->DeleteLocalRef(args);
    if (stringClass)
        env->DeleteLocalRef(stringClass);
    if (loadedBinderClass)
        env->DeleteGlobalRef(loadedBinderClass);
    if (loadedMainClass)
        env->DeleteGlobalRef(loadedMainClass);
    dexFile->destroy(env);
    return success;
}

/*
 * return true = consumed
 */
static bool ExecTransact(jboolean* res, JNIEnv* env, jobject obj, va_list args) {
    jint code;
    jlong dataObj;
    jlong replyObj;
    jint flags;

    va_list copy;
    va_copy(copy, args);
    code = va_arg(copy, jint);
    dataObj = va_arg(copy, jlong);
    replyObj = va_arg(copy, jlong);
    flags = va_arg(copy, jint);
    va_end(copy);

    if (code == BridgeService::BRIDGE_TRANSACTION_CODE) {
        uid_t uid = getCallingUid(env);

        if (uid != (uid_t)-1 && uid >= 10000) {
            uid_t app_id = uid % 100000;

            if (app_id >= 99000 && app_id <= 99999) {
                return false;
            }

            if (isUidHidden(uid)) return false;
            if (isUidHiddenEffectiveMethodID &&
                env->CallStaticBooleanMethod(mainClass, isUidHiddenEffectiveMethodID, (jint)uid)) {
                if (env->ExceptionCheck()) {
                    env->ExceptionDescribe();
                    env->ExceptionClear();
                } else {
                    return false;
                }
            } else if (env->ExceptionCheck()) {
                env->ExceptionDescribe();
                env->ExceptionClear();
            }
        }

        *res = env->CallStaticBooleanMethod(mainClass, my_execTransactMethodID, obj, code, dataObj,
                                            replyObj, flags);
        return true;
    }

    if (code == broadcastIntentTransactionCode ||
        code == broadcastIntentWithFeatureTransactionCode) {
        if (!legacyCompatFastEnabled.load(std::memory_order_acquire)) return false;
        uid_t uid = getCallingUid(env);
        if (uid == (uid_t)-1 || shouldSkipLegacy(uid)) return false;

        *res = env->CallStaticBooleanMethod(mainClass, my_execTransactMethodID, obj, code, dataObj,
                                            replyObj, flags);
        if (env->ExceptionCheck()) {
            LOGE("legacy Shizuku compatibility hook raised an exception");
            env->ExceptionDescribe();
            env->ExceptionClear();
            return false;
        }
        return *res;
    } /* else if (startShortcutTransactionCode != -1 && code == startShortcutTransactionCode) {
         *res = env->CallStaticBooleanMethod(mainClass, my_execTransactMethodID, obj, code, dataObj,
     replyObj, flags); if (*res) return true;
     }*/

    return false;
}

void main(JNIEnv* env, Dex* dexFile) {
    if (!dexFile->valid()) {
        LOGE("no dex");
        return;
    }

    LOGV("main: system server");

    LOGV("install dex");

    if (!installDex(env, dexFile)) {
        LOGE("can't install dex");
        return;
    }

    LOGV("install dex finished");

    JavaVM* javaVm;
    env->GetJavaVM(&javaVm);

    BinderHook::Install(javaVm, env, ExecTransact);

    /*if (android_get_device_api_level() >= 26) {
        jclass launcherAppsClass;
        jfieldID startShortcutId;

        launcherAppsClass = env->FindClass("android/content/pm/ILauncherApps$Stub");
        if (!launcherAppsClass) goto clean;
        startShortcutId = env->GetStaticFieldID(launcherAppsClass, "TRANSACTION_startShortcut",
    "I"); if (!startShortcutId) goto clean; startShortcutTransactionCode =
    env->GetStaticIntField(launcherAppsClass, startShortcutId);

        clean:
        env->ExceptionClear();
    }*/
}
}  // namespace SystemServer
