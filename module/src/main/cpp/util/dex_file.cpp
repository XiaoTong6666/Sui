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

#include <fcntl.h>
#include <zconf.h>
#include <malloc.h>
#include <jni.h>
#include <android.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <libgen.h>
#include "dex_file.h"
#include "misc.h"
#include "logging.h"

Buffer::Buffer(int fd, size_t size) {
    uint8_t* addr;
    if ((addr = (uint8_t*)mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0)) != MAP_FAILED) {
        bytes_ = addr;
        size_ = size;
        is_mmap_ = true;
    } else {
        PLOGE("mmap");
    }
}

Buffer::Buffer(const char* path) {
    if (!path)
        return;

    LOGD("Attempt to read %s", path);

    bytes_ = nullptr;
    size_ = 0;

    auto fd = open(path, O_RDONLY);
    if (fd == -1) {
        PLOGE("open %s", path);
        close(fd);
        return;
    }
    size_ = lseek(fd, 0, SEEK_END);
    if (size_ == -1) {
        PLOGE("lseek %s", path);
        close(fd);
        return;
    }
    lseek(fd, 0, SEEK_SET);

    bytes_ = static_cast<uint8_t*>(malloc(size_));
    if (read_full(fd, bytes_, size_) == -1) {
        size_ = 0;
        free(bytes_);
        bytes_ = nullptr;
    }
    close(fd);
}

Buffer::~Buffer() {
    LOGD("~Buffer %p", bytes_);
    if (!bytes_)
        return;
    if (is_mmap_)
        munmap(bytes_, size_);
    else
        free(bytes_);
}

uint8_t* Buffer::data() const {
    return bytes_;
}

size_t Buffer::size() const {
    return size_;
}

int Buffer::writeToFile(const char* path, mode_t mode) {
    if (!bytes_)
        return -1;

    char* path_copy = strdup(path);
    auto dir = dirname(path_copy);
    mkdirs(dir, mode);
    free(path_copy);

    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd == -1) {
        PLOGE("open %s", path);
        return -1;
    }

    if (write_full(fd, bytes_, size_) == -1) {
        close(fd);
        PLOGE("write");
        return -1;
    }
    return fd;
}

void Dex::destroy(JNIEnv* env) {
    if (dexClassLoaderClass)
        env->DeleteGlobalRef(dexClassLoaderClass);
    if (dexClassLoader)
        env->DeleteGlobalRef(dexClassLoader);
}

Dex::Dex(const char* path) : buffer_(path) {
}

Dex::Dex(int fd, size_t size) : buffer_(fd, size) {
}

Dex::~Dex() {
    LOGD("~Dex");
    if (pre26DexPath_)
        free(pre26DexPath_);
    if (pre26OptDir_)
        free(pre26OptDir_);
}

void Dex::createClassLoader(JNIEnv* env) {
    if (android_get_device_api_level() >= 27) {
        createInMemoryDexClassLoader(env);
    } else {
        copyDexToFile(pre26DexPath_);
        createDexClassLoader(env, pre26DexPath_, pre26OptDir_);
    }
}

void Dex::createInMemoryDexClassLoader(JNIEnv* env) {
    if (!buffer_.data())
        return;

    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    jmethodID getSystemClassLoaderMethod = env->GetStaticMethodID(
        classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject systemClassLoader =
        env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoaderMethod);

    dexClassLoaderClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    findClassMethod =
        env->GetMethodID(dexClassLoaderClass, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    dexClassLoaderClass = (jclass)env->NewGlobalRef(dexClassLoaderClass);

    jmethodID initDexClassLoaderMethod = env->GetMethodID(
        dexClassLoaderClass, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject buffer = env->NewDirectByteBuffer(buffer_.data(), buffer_.size());
    dexClassLoader =
        env->NewObject(dexClassLoaderClass, initDexClassLoaderMethod, buffer, systemClassLoader);
    if (!dexClassLoader)
        goto clean;
    dexClassLoader = env->NewGlobalRef(dexClassLoader);

clean:
    if (env->ExceptionCheck())
        env->ExceptionClear();
    env->DeleteLocalRef(systemClassLoader);
    env->DeleteLocalRef(classLoaderClass);
}

void Dex::createDexClassLoader(JNIEnv* env, const char* path, const char* optDir) {
    /*
        if (optDir) {
            mkdirs(optDir, 0700);
        }
    */

    jstring jDexPath = env->NewStringUTF(path);
    jstring jOptDir = optDir ? env->NewStringUTF(optDir) : nullptr;

    jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
    jmethodID getSystemClassLoaderMethod = env->GetStaticMethodID(
        classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
    jobject systemClassLoader =
        env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoaderMethod);

    dexClassLoaderClass = env->FindClass("dalvik/system/DexClassLoader");
    findClassMethod =
        env->GetMethodID(dexClassLoaderClass, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    dexClassLoaderClass = (jclass)env->NewGlobalRef(dexClassLoaderClass);

    jmethodID initDexClassLoaderMethod = env->GetMethodID(
        dexClassLoaderClass, "<init>",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V");
    dexClassLoader = env->NewObject(dexClassLoaderClass, initDexClassLoaderMethod, jDexPath,
                                    jOptDir, nullptr, systemClassLoader);
    if (!dexClassLoader)
        goto clean;
    dexClassLoader = env->NewGlobalRef(dexClassLoader);

clean:
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
    env->DeleteLocalRef(classLoaderClass);
    if (jOptDir)
        env->DeleteLocalRef(jOptDir);
    env->DeleteLocalRef(jDexPath);
}

void Dex::copyDexToFile(const char* dexPath) {
    if (!buffer_.data())
        return;

    size_t len = strlen(dexPath);
    if (len > 4 && strcmp(dexPath + len - 4, ".apk") == 0) {
        LOGI("copyDexToFile: skip writing to APK %s", dexPath);
        return;
    }

    // Even if this fails (e.g. due to permissions/SELinux), we proceed because
    int fd = buffer_.writeToFile(dexPath, 0644);
    if (fd != -1) {
        fchmod(fd, 0644);
        close(fd);
    } else {
        PLOGE("copyDexToFile: write failed, but proceeding to try loading");
    }
}

jclass Dex::findClass(JNIEnv* env, const char* name) {
    if (!dexClassLoader)
        return nullptr;

    jstring jName = env->NewStringUTF(name);
    auto cls = (jclass)env->CallObjectMethod(dexClassLoader, findClassMethod, jName);
    if (env->ExceptionCheck())
        env->ExceptionClear();
    return cls;
}

void Dex::setPre26Paths(const char* dexPath, const char* optDir) {
    if (pre26DexPath_)
        free(pre26DexPath_);
    if (pre26OptDir_)
        free(pre26OptDir_);
    pre26DexPath_ = dexPath ? strdup(dexPath) : nullptr;
    pre26OptDir_ = optDir ? strdup(optDir) : nullptr;
}

bool Dex::valid() {
    return buffer_.data();
}
