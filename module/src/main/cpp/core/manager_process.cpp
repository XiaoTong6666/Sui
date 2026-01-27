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
#include <vector>

#include "android.h"
#include "logging.h"
#include "misc.h"
#include "dex_file.h"
#include "bridge_service.h"
#include "binder_hook.h"
#include "config.h"
#include <pthread.h>

namespace Manager {

static jclass mainClass = nullptr;

static bool installDex(JNIEnv* env, const char* appDataDir, Dex* dexFile) {
    int api = android_get_device_api_level();
    if (api <= 25) {
        char dexPath[PATH_MAX], oatDir[PATH_MAX];
        snprintf(dexPath, PATH_MAX, "%s/sui.dex", appDataDir);
        snprintf(oatDir, PATH_MAX, "%s/code_cache", appDataDir);

        LOGI("installDex (Below 7.1): using private paths: dex=%s, oat=%s", dexPath, oatDir);
        dexFile->setPre26Paths(dexPath, oatDir);
    } else if (api == 26 || api == 27) {
        const char* dexPath = "/data/system/sui/sui.dex";
        const char* oatDir = "/data/system/sui/oat";

        LOGI("installDex (8.0/8.1): using global system paths: dex=%s, oat=%s", dexPath, oatDir);
        dexFile->setPre26Paths(dexPath, oatDir);
    }
    dexFile->createClassLoader(env);

    mainClass = dexFile->findClass(env, MANAGER_PROCESS_CLASSNAME);
    if (!mainClass) {
        LOGE("installDex: unable to find main class: %s", MANAGER_PROCESS_CLASSNAME);
        return false;
    }
    mainClass = (jclass)env->NewGlobalRef(mainClass);

    auto mainMethod = env->GetStaticMethodID(mainClass, "main", "([Ljava/lang/String;)V");
    if (!mainMethod) {
        LOGE("installDex: unable to find main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    auto args = env->NewObjectArray(0, env->FindClass("java/lang/String"), nullptr);

    env->CallStaticVoidMethod(mainClass, mainMethod, args);
    if (env->ExceptionCheck()) {
        LOGE("installDex: exception in main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        return false;
    }

    return true;
}

struct InjectArgs {
    JavaVM* vm;
    char* appDataDir;
    Dex* dexFile;
};

static void* InjectRoutine(void* data) {
    auto args = (InjectArgs*)data;
    JNIEnv* env;
    if (args->vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
        LOGI("Async injection started");
        if (installDex(env, args->appDataDir, args->dexFile)) {
            LOGI("Async injection success");
        } else {
            LOGE("Async injection failed");
        }
        args->vm->DetachCurrentThread();
    }
    if (args->appDataDir)
        free(args->appDataDir);
    delete args;
    return nullptr;
}

void main(JNIEnv* env, const char* appDataDir, Dex* dexFile) {
    if (!dexFile->valid()) {
        LOGE("no dex");
        return;
    }

    LOGV("main: manager");

    JavaVM* vm;
    env->GetJavaVM(&vm);

    auto args = new InjectArgs();
    args->vm = vm;
    args->appDataDir = appDataDir ? strdup(appDataDir) : nullptr;
    args->dexFile = dexFile;

    pthread_t t;
    pthread_create(&t, nullptr, InjectRoutine, args);

    LOGV("install dex (async) scheduled");
}
}  // namespace Manager
