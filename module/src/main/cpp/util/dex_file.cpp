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
#include <cerrno>
#include <cstring>
#include <string>
#include <unistd.h>
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

bool Buffer::writeToFile(const char* path, mode_t mode) {
    if (!bytes_ || !size_ || !path)
        return false;
    const char* slash = strrchr(path, '/');
    if (!slash || slash == path || !slash[1])
        return false;
    const std::string parent(path, slash - path);
    const char* name = slash + 1;
    int dir = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dir < 0) {
        PLOGE("open DEX directory");
        return false;
    }
    struct stat st{};
    bool safe = fstat(dir, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
                !(st.st_mode & S_IWOTH);
    if (safe && fstatat(dir, name, &st, AT_SYMLINK_NOFOLLOW) == 0)
        safe = S_ISREG(st.st_mode) && st.st_uid == geteuid();
    else if (safe)
        safe = errno == ENOENT;
    if (!safe) {
        LOGE("unsafe DEX destination: %s", path);
        close(dir);
        return false;
    }

    std::string temporary = parent + "/.sui.dex.XXXXXX";
    int fd = mkstemp(temporary.data());
    if (fd < 0) {
        PLOGE("mkstemp DEX");
        close(dir);
        return false;
    }
    const char* tmp_name = strrchr(temporary.c_str(), '/') + 1;
    bool ok = write_full(fd, bytes_, size_) == 0 && fchmod(fd, mode) == 0 && fsync(fd) == 0;
    if (close(fd) != 0)
        ok = false;
    if (ok)
        ok = renameat(dir, tmp_name, dir, name) == 0;
    if (!ok) {
        PLOGE("atomic DEX write %s", path);
        unlinkat(dir, tmp_name, 0);
    }
    close(dir);
    return ok;
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

bool Dex::createClassLoader(JNIEnv* env) {
    // Oreo supports direct ByteBuffer DEX loading, so no optimized disk path is needed.
    // https://android.googlesource.com/platform/libcore/+/android-8.0.0_r1/dalvik/src/main/java/dalvik/system/InMemoryDexClassLoader.java#46
    if (android_get_device_api_level() >= 26) {
        createInMemoryDexClassLoader(env);
    } else {
        // Pre-Oreo ART loads the source DEX with a separate optimized OAT path.
        // https://android.googlesource.com/platform/libcore/+/android-6.0.1_r11/dalvik/src/main/java/dalvik/system/DexPathList.java#282
        if (!pre26DexPath_ || !pre26OptDir_ || !copyDexToFile(pre26DexPath_))
            return false;
        createDexClassLoader(env, pre26DexPath_, pre26OptDir_);
    }
    return dexClassLoader != nullptr;
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
    env->DeleteLocalRef(systemClassLoader);
    env->DeleteLocalRef(classLoaderClass);
    if (jOptDir)
        env->DeleteLocalRef(jOptDir);
    env->DeleteLocalRef(jDexPath);
}

bool Dex::copyDexToFile(const char* dexPath) {
    if (!buffer_.data())
        return false;

    size_t len = strlen(dexPath);
    if (len > 4 && strcmp(dexPath + len - 4, ".apk") == 0)
        return true;
    return buffer_.writeToFile(dexPath, 0644);
}

jclass Dex::findClass(JNIEnv* env, const char* name) {
    if (!dexClassLoader)
        return nullptr;

    jstring jName = env->NewStringUTF(name);
    auto cls = (jclass)env->CallObjectMethod(dexClassLoader, findClassMethod, jName);
    if (env->ExceptionCheck())
        env->ExceptionClear();
    env->DeleteLocalRef(jName);
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

bool Dex::setPre26AppPaths(const char* appDataDir) {
    if (!appDataDir || appDataDir[0] != '/' || strlen(appDataDir) >= PATH_MAX - 16)
        return false;
    int app = open(appDataDir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (app < 0) {
        PLOGE("open app data directory");
        return false;
    }
    struct stat st{};
    bool valid = fstat(app, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
                 !(st.st_mode & S_IWOTH) &&
                 (st.st_mode & (S_IWUSR | S_IXUSR)) == (S_IWUSR | S_IXUSR);
    if (valid && mkdirat(app, "code_cache", 0700) != 0 && errno != EEXIST)
        valid = false;
    int cache =
        valid ? openat(app, "code_cache", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW) : -1;
    if (cache < 0)
        valid = false;
    if (valid)
        valid = fstat(cache, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == geteuid() &&
                !(st.st_mode & S_IWOTH) &&
                (st.st_mode & (S_IRUSR | S_IWUSR | S_IXUSR)) == (S_IRUSR | S_IWUSR | S_IXUSR);
    if (cache >= 0)
        close(cache);
    close(app);
    if (!valid) {
        LOGE("private code_cache is unavailable: %s", appDataDir);
        return false;
    }
    const std::string base(appDataDir);
    setPre26Paths((base + "/sui.dex").c_str(), (base + "/code_cache").c_str());
    return true;
}

bool Dex::valid() {
    return buffer_.data();
}
