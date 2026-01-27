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

static jint startShortcutTransactionCode = -1;

static std::string get_process_name(pid_t pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return "";

    char buf[256] = {0};
    ssize_t len = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (len > 0) {
        return std::string(buf);
    }
    return "";
}

static bool is_blacklisted_app(pid_t pid) {
    std::string process_name = get_process_name(pid);
    if (process_name.empty())
        return false;
    if (process_name.find("icu.nullptr.nativetest") != std::string::npos)
        return true;
    if (process_name.find("com.android.nativetest") != std::string::npos)
        return true;
    // if (process_name.find("com.example.suidetect") != std::string::npos) return true;
    return false;
}

static bool installDex(JNIEnv* env, Dex* dexFile) {
    if (android_get_device_api_level() < 27) {
        dexFile->setPre26Paths("/data/system/sui/" DEX_NAME, "/data/system/sui/oat");
    }
    dexFile->createClassLoader(env);

    mainClass = dexFile->findClass(env, SYSTEM_PROCESS_CLASSNAME);
    if (!mainClass) {
        LOGE("unable to find main class");
        return false;
    }
    mainClass = (jclass)env->NewGlobalRef(mainClass);

    auto mainMethod = env->GetStaticMethodID(mainClass, "main", "([Ljava/lang/String;)V");
    if (!mainMethod) {
        LOGE("unable to find main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    my_execTransactMethodID =
        env->GetStaticMethodID(mainClass, "execTransact", "(Landroid/os/Binder;IJJI)Z");
    if (!my_execTransactMethodID) {
        LOGE("unable to find execTransact");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    auto args = env->NewObjectArray(0, env->FindClass("java/lang/String"), nullptr);

    env->CallStaticVoidMethod(mainClass, mainMethod, args);
    if (env->ExceptionCheck()) {
        LOGE("unable to call main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    return true;
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
        static void* libbinder_ndk = dlopen("libbinder_ndk.so", RTLD_NOW);
        static AIBinder_getCallingUid_t get_uid = nullptr;
        static AIBinder_getCallingPid_t get_pid = nullptr;

        if (libbinder_ndk) {
            if (!get_uid)
                get_uid = (AIBinder_getCallingUid_t)dlsym(libbinder_ndk, "AIBinder_getCallingUid");
            if (!get_pid)
                get_pid = (AIBinder_getCallingPid_t)dlsym(libbinder_ndk, "AIBinder_getCallingPid");
        }

        if (get_uid && get_pid) {
            uid_t uid = get_uid();
            if (uid < 10000) {
            } else {
                pid_t pid = get_pid();
                if (is_blacklisted_app(pid)) {
                    return false;
                }
            }
        }

        *res = env->CallStaticBooleanMethod(mainClass, my_execTransactMethodID, obj, code, dataObj,
                                            replyObj, flags);
        return true;
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
