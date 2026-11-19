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
#define SUI_LOG_COMPONENT "Manager"
#include "logging.h"
#include "misc.h"
#include "dex_file.h"
#include "bridge_service.h"
#include "binder_hook.h"
#include "config.h"
#include <pthread.h>

namespace Manager {

static bool installDex(JNIEnv* env, const char* appDataDir, Dex* dexFile) {
    bool success = false;
    jclass mainClass = nullptr;
    jclass stringClass = nullptr;
    jobjectArray args = nullptr;
    jmethodID mainMethod = nullptr;

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
        goto cleanup;
    }

    mainMethod = env->GetStaticMethodID(mainClass, "main", "([Ljava/lang/String;)V");
    if (!mainMethod) {
        LOGE("installDex: unable to find main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    stringClass = env->FindClass("java/lang/String");
    if (!stringClass) {
        LOGE("installDex: unable to find java/lang/String");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    args = env->NewObjectArray(0, stringClass, nullptr);
    if (!args) {
        LOGE("installDex: unable to allocate argument array");
        if (env->ExceptionCheck()) {
            env->ExceptionDescribe();
            env->ExceptionClear();
        }
        goto cleanup;
    }

    env->CallStaticVoidMethod(mainClass, mainMethod, args);
    if (env->ExceptionCheck()) {
        LOGE("installDex: exception in main method");
        env->ExceptionDescribe();
        env->ExceptionClear();
        goto cleanup;
    }

    success = true;

cleanup:
    if (args)
        env->DeleteLocalRef(args);
    if (stringClass)
        env->DeleteLocalRef(stringClass);
    if (mainClass)
        env->DeleteLocalRef(mainClass);
    dexFile->destroy(env);
    return success;
}

struct InjectArgs {
    JavaVM* vm;
    char* appDataDir;
    Dex* dexFile;
};

static void DestroyInjectArgs(InjectArgs* args) {
    if (!args)
        return;
    if (args->appDataDir)
        free(args->appDataDir);
    delete args;
}

static void* InjectRoutine(void* data) {
    auto args = (InjectArgs*)data;
    JNIEnv* env = nullptr;
    if (args->vm->AttachCurrentThread(&env, nullptr) == JNI_OK) {
        LOGI("Async injection started");
        if (installDex(env, args->appDataDir, args->dexFile)) {
            LOGI("Async injection success");
        } else {
            LOGE("Async injection failed");
        }
        args->vm->DetachCurrentThread();
    }
    DestroyInjectArgs(args);
    return nullptr;
}

void main(JNIEnv* env, const char* appDataDir, Dex* dexFile) {
    if (!dexFile->valid()) {
        LOGE("no dex");
        return;
    }

    LOGV("main: manager");

    JavaVM* vm = nullptr;
    if (env->GetJavaVM(&vm) != JNI_OK || !vm) {
        LOGE("main: unable to get JavaVM");
        return;
    }

    auto args = new InjectArgs();
    args->vm = vm;
    args->appDataDir = appDataDir ? strdup(appDataDir) : nullptr;
    args->dexFile = dexFile;

    pthread_attr_t attr;
    int rc = pthread_attr_init(&attr);
    if (rc != 0) {
        LOGE("main: pthread_attr_init failed: %s", strerror(rc));
        DestroyInjectArgs(args);
        return;
    }

    rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (rc != 0) {
        LOGE("main: pthread_attr_setdetachstate failed: %s", strerror(rc));
        pthread_attr_destroy(&attr);
        DestroyInjectArgs(args);
        return;
    }

    pthread_t t;
    rc = pthread_create(&t, &attr, InjectRoutine, args);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        LOGE("main: pthread_create failed: %s", strerror(rc));
        DestroyInjectArgs(args);
        return;
    }

    LOGV("install dex (async) scheduled");
}
}  // namespace Manager
