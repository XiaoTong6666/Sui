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

#include <sys/mount.h>
#include <private/ScopedFd.h>
#include <sys/mman.h>
#include <cinttypes>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <selinux.h>
#include <logging.h>
#include <misc.h>
#include <elf.h>
#include <link.h>
#include <private/ScopedReaddir.h>
#include <string_view>
#include <android/api-level.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <android.h>
#include <cstdarg>

using namespace std::literals::string_view_literals;

#define ERR_SELINUX 10
#define ERR_NO_ADBD 11
#define ERR_ADBD_IS_STATIC 12
#define ERR_OTHER 13

struct attrs {
    uid_t uid{};
    gid_t gid{};
    mode_t mode{};
    char* context{nullptr};
    bool is_malloced{false};

    ~attrs() {
        if (context) {
            if (is_malloced) {
                free(context);
            } else {
                freecon(context);
            }
        }
    }
};

inline bool build_path(char* buffer, size_t buffer_size, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buffer, buffer_size, fmt, args);
    va_end(args);
    if (written < 0 || static_cast<size_t>(written) >= buffer_size) {
        errno = ENAMETOOLONG;
        return false;
    }
    return true;
}

inline int getattrs(const char* file, attrs* attrs) {
    struct stat statbuf{};
    if (stat(file, &statbuf) != 0) {
        PLOGE("stat %s", file);
        return 1;
    }

    if (attrs->context) {
        if (attrs->is_malloced) {
            free(attrs->context);
        } else {
            freecon(attrs->context);
        }
        attrs->context = nullptr;
        attrs->is_malloced = false;
    }

    if (getfilecon_raw(file, &attrs->context) < 0) {
        PLOGE("getfilecon %s", file);
        return 1;
    }

    attrs->uid = statbuf.st_uid;
    attrs->gid = statbuf.st_gid;
    attrs->mode = statbuf.st_mode;
    attrs->is_malloced = false;
    return 0;
}

inline int setattrs(const char* file, const attrs* attrs) {
    uid_t uid = attrs->uid;
    gid_t gid = attrs->gid;
    mode_t mode = attrs->mode;
    const char* secontext = attrs->context;

    if (chmod(file, mode) != 0) {
        PLOGE("chmod %s", file);
        return 1;
    }
    if (chown(file, uid, gid) != 0) {
        PLOGE("chown %s", file);
        return 1;
    }
    if (setfilecon_raw(file, secontext) != 0) {
        PLOGE("setfilecon %s", file);
        return 1;
    }
    return 0;
}

inline int setup_file(const char* source, const char* target, const attrs* attrs) {
    if (attrs && setattrs(source, attrs) != 0) {
        return 1;
    }
    if (int fd = open(target, O_RDWR | O_CREAT, 0700); fd == -1) {
        PLOGE("open %s", target);
        return 1;
    } else {
        close(fd);
    }
    if (mount(source, target, nullptr, MS_BIND, nullptr)) {
        PLOGE("mount %s -> %s", source, target);
        return 1;
    }
    return 0;
}

inline bool is_dynamically_linked(const char* path) {
    struct stat st;
    ScopedFd fd(open(path, O_RDONLY));

    if (fd.get() == -1) {
        PLOGE("open %s", path);
        return false;
    }
    if (fstat(fd.get(), &st) < 0) {
        PLOGE("fstat");
        return false;
    }

    auto data =
        static_cast<uint8_t*>(mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd.get(), 0));
    if (data == MAP_FAILED) {
        PLOGE("mmap");
        return false;
    }

    auto ehdr = (ElfW(Ehdr)*)data;
#ifdef __LP64__
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        LOGE("Not elf64");
        munmap(data, st.st_size);
        return false;
    }
#else
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
        LOGE("Not elf32");
        munmap(data, st.st_size);
        return false;
    }
#endif

    bool is_dynamically_linked = false;

    auto phdr = (ElfW(Phdr)*)(data + ehdr->e_phoff);
    int phnum = ehdr->e_phnum;

    for (int i = 0; i < phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            is_dynamically_linked = true;
            break;
        }
    }

    munmap(data, st.st_size);
    return is_dynamically_linked;
}

inline int setup_adb_root_apex(const char* root_path, const char* adbd_wrapper,
                               const char* adbd_preload) {
    char versioned_adbd[PATH_MAX]{0};
    char path[PATH_MAX]{0};
    char source[PATH_MAX]{0};
    char target[PATH_MAX]{0};
    const char *adbd, *adbd_real, *bin_folder, *lib_folder, *data_adb_folder;
    attrs file_attr{}, folder_attr{}, lib_attr{}, data_adb_attr{};

    adbd = "/apex/com.android.adbd/bin/adbd";
    adbd_real = "/apex/com.android.adbd/bin/adbd_real";
    bin_folder = "/apex/com.android.adbd/bin";
#ifdef __LP64__
    lib_folder = "/apex/com.android.adbd/lib64";
#else
    lib_folder = "/apex/com.android.adbd/lib";
#endif
    data_adb_folder = "/data/adb";

    if (!is_dynamically_linked(adbd)) {
        LOGE("%s is not dynamically linked (or 32 bit elf on 64 bit machine)", adbd);
        return ERR_ADBD_IS_STATIC;
    } else {
        LOGI("%s is dynamically linked", adbd);
    }

    if (getattrs(adbd, &file_attr) != 0 || getattrs(bin_folder, &folder_attr) != 0 ||
        getattrs(data_adb_folder, &data_adb_attr) != 0) {
        return ERR_OTHER;
    } else {
        LOGV("%s: uid=%d, gid=%d, mode=%3o, context=%s", adbd, file_attr.uid, file_attr.gid,
             file_attr.mode, file_attr.context);
        LOGV("%s: uid=%d, gid=%d, mode=%3o, context=%s", bin_folder, folder_attr.uid,
             folder_attr.gid, folder_attr.mode, folder_attr.context);
    }

    // Path of real of adbd in module folder
    char my_backup[PATH_MAX]{0};
    if (!build_path(my_backup, sizeof(my_backup), "%s/bin/adbd_real", root_path)) {
        PLOGE("build_path %s/bin/adbd_real", root_path);
        return ERR_OTHER;
    }

    if (copyfile(adbd, my_backup) != 0) {
        PLOGE("copyfile %s -> %s", adbd, my_backup);
        return ERR_OTHER;
    }

    // Find /apex/com.android.adbd@version
    ScopedReaddir dir("/apex");
    if (dir.IsBad()) {
        PLOGE("opendir %s", "/apex");
        return ERR_OTHER;
    }

    auto apex = "/apex/"sv;
    strncpy(versioned_adbd, apex.data(), apex.length());

    bool found = false;
    uint64_t version = 0;
    auto adbd_prefix = "com.android.adbd@"sv;
    while (dirent* entry = dir.ReadEntry()) {
        std::string_view d_name{entry->d_name};

        if (d_name.length() <= adbd_prefix.length() ||
            d_name.substr(0, adbd_prefix.length()) != adbd_prefix)
            continue;

        const char* version_string = entry->d_name + adbd_prefix.length();
        uint64_t new_version = strtoull(version_string, nullptr, 10);
        if (new_version >= version) {
            version = new_version;
            strncpy(versioned_adbd + apex.length(), d_name.data(), d_name.length());
            LOGI("Found versioned apex %s", versioned_adbd);
            found = true;
        }
    }

    if (!found) {
        LOGE("Cannot find versioned apex");
        return ERR_OTHER;
    }

    if (!build_path(path, sizeof(path),
#ifdef __LP64__
                    "%s/lib64",
#else
                    "%s/lib",
#endif
                    versioned_adbd)) {
        PLOGE("build_path %s/lib", versioned_adbd);
        return ERR_OTHER;
    }

    ScopedReaddir lib(path);
    if (lib.IsBad()) {
        PLOGE("opendir %s", path);
        return ERR_OTHER;
    }

    bool bin_mounted = false, lib_mounted = false;

    LOGI("Mount %s tmpfs", bin_folder);

    {
        if (mount("tmpfs", bin_folder, "tmpfs", 0, "mode=755") != 0) {
            PLOGE("mount tmpfs -> %s", bin_folder);
            goto failed;
        }

        bin_mounted = true;

        if (setattrs(bin_folder, &folder_attr) != 0) {
            goto failed;
        }

        // $MODDIR/bin/adbd_wrapper -> /apex/com.android.adbd/bin/adbd
        if (setup_file(adbd_wrapper, adbd, &file_attr) != 0) {
            LOGE("Failed to %s -> %s", adbd_wrapper, adbd);
            goto failed;
        }

        if (file_attr.context) {
            if (file_attr.is_malloced) {
                free(file_attr.context);
            } else {
                freecon(file_attr.context);
            }
        }
        file_attr.context = strdup(data_adb_attr.context);
        file_attr.is_malloced = true;

        // $MODDIR/bin/adbd_real -> /apex/com.android.adbd/bin/adbd_real
        if (setup_file(my_backup, adbd_real, &file_attr) != 0) {
            LOGE("Failed to %s -> %s", my_backup, adbd_real);
            goto failed;
        }
    }

    LOGI("Mount %s tmpfs", lib_folder);

    {
        if (mount("tmpfs", lib_folder, "tmpfs", 0, "mode=755") != 0) {
            PLOGE("mount tmpfs -> %s", lib_folder);
            goto failed;
        }

        lib_mounted = true;

        if (lib.IsBad()) {
            goto failed;
        }

        while (dirent* entry = lib.ReadEntry()) {
            if (entry->d_name[0] == '.')
                continue;

            if (!build_path(source, sizeof(source),
#ifdef __LP64__
                            "%s/lib64/%s",
#else
                            "%s/lib/%s",
#endif
                            versioned_adbd, entry->d_name)) {
                PLOGE("build_path source %s", entry->d_name);
                goto failed;
            }

            if (getattrs(source, &lib_attr) != 0) {
                goto failed;
            }

            if (!build_path(target, sizeof(target), "%s/%s", lib_folder, entry->d_name)) {
                PLOGE("build_path target %s", entry->d_name);
                goto failed;
            }

            if (setup_file(source, target, nullptr) != 0) {
                LOGE("Failed to %s -> %s", source, target);
                goto failed;
            }
        }

        if (!build_path(target, sizeof(target), "%s/libsui_adbd_preload.so", lib_folder)) {
            PLOGE("build_path %s/libsui_adbd_preload.so", lib_folder);
            goto failed;
        }

        if (setup_file(adbd_preload, target, &lib_attr) != 0) {
            LOGE("Failed to %s -> %s", adbd_preload, target);
            goto failed;
        }
    }

    LOGI("Finished");
    return EXIT_SUCCESS;

failed:
    if (bin_mounted) {
        if (umount2(bin_folder, MNT_DETACH) != 0) {
            PLOGE("umount2 %s", bin_folder);
        } else {
            LOGW("Unmount %s", bin_folder);
        }
    }
    if (lib_mounted) {
        if (umount2(lib_folder, MNT_DETACH) != 0) {
            PLOGE("umount2 %s", lib_folder);
        } else {
            LOGW("Unmount %s", lib_folder);
        }
    }
    return ERR_OTHER;
}

inline int setup_adb_root_non_apex(const char* root_path, const char* adbd_wrapper,
                                   const char* adbd_preload) {
    const char *file, *folder, *data_adb_folder;
    attrs file_attr{}, folder_attr{}, data_adb_attr{};

    file = "/system/bin/adbd";
    folder = "/system/bin";
    data_adb_folder = "/data/adb";

    if (!is_dynamically_linked(file)) {
        LOGE("%s is not dynamically linked", file);
        return ERR_ADBD_IS_STATIC;
    } else {
        LOGI("%s is dynamically linked", file);
    }

    if (getattrs(file, &file_attr) != 0 || getattrs(folder, &folder_attr) != 0 ||
        getattrs(data_adb_folder, &data_adb_attr) != 0) {
        return ERR_OTHER;
    } else {
        LOGV("%s: uid=%d, gid=%d, mode=%3o, context=%s", file, file_attr.uid, file_attr.gid,
             file_attr.mode, file_attr.context);
        LOGV("%s: uid=%d, gid=%d, mode=%3o, context=%s", folder, folder_attr.uid, folder_attr.gid,
             folder_attr.mode, folder_attr.context);
    }

    LOGI("Copy files to MODDIR/system");

    char module_folder[PATH_MAX]{0};
    char target[PATH_MAX]{0};

    // mkdir $MODDIR/system/bin
    if (!build_path(module_folder, sizeof(module_folder), "%s/system/bin", root_path)) {
        PLOGE("build_path %s/system/bin", root_path);
        return ERR_OTHER;
    }
    if (mkdir(module_folder, folder_attr.mode) == -1 && errno != EEXIST) {
        PLOGE("mkdir %s", module_folder);
        return ERR_OTHER;
    }

    // $MODDIR/system/bin/adbd_wrapper -> $MODDIR/system/bin/adbd
    if (!build_path(target, sizeof(target), "%s/adbd", module_folder)) {
        PLOGE("build_path %s/adbd", module_folder);
        return ERR_OTHER;
    }
    if (copyfile(adbd_wrapper, target) != 0) {
        PLOGE("copyfile %s -> %s", adbd_wrapper, target);
        return ERR_OTHER;
    }
    if (setattrs(target, &file_attr) != 0) {
        unlink(target);
        return ERR_OTHER;
    }

    // /system/bin/adbd -> $MODDIR/system/bin/adbd_real
    if (!build_path(target, sizeof(target), "%s/adbd_real", module_folder)) {
        PLOGE("build_path %s/adbd_real", module_folder);
        return ERR_OTHER;
    }
    if (copyfile(file, target) != 0) {
        PLOGE("copyfile %s -> %s", file, target);
        return ERR_OTHER;
    }
    if (file_attr.context) {
        if (file_attr.is_malloced) {
            free(file_attr.context);
        } else {
            freecon(file_attr.context);
        }
    }
    file_attr.context = strdup(data_adb_attr.context);
    file_attr.is_malloced = true;
    if (setattrs(target, &file_attr) != 0) {
        unlink(target);
        return ERR_OTHER;
    }

    // mkdir $MODDIR/system/lib(64)
    if (!build_path(module_folder, sizeof(module_folder),
#ifdef __LP64__
                    "%s/system/lib64",
#else
                    "%s/system/lib",
#endif
                    root_path)) {
        PLOGE("build_path %s/system/lib", root_path);
        return ERR_OTHER;
    }
    if (mkdir(module_folder, folder_attr.mode) == -1 && errno != EEXIST) {
        PLOGE("mkdir %s", module_folder);
        return ERR_OTHER;
    }

    // $MODDIR/lib/libadbd_preload.so -> $MODDIR/system/lib(64)/libsui_adbd_preload.so
    if (!build_path(target, sizeof(target), "%s/libsui_adbd_preload.so", module_folder)) {
        PLOGE("build_path %s/libsui_adbd_preload.so", module_folder);
        return ERR_OTHER;
    }
    if (copyfile(adbd_preload, target) != 0) {
        PLOGE("copyfile %s -> %s", adbd_preload, target);
        return ERR_OTHER;
    }
    if (setattrs(target, &file_attr) != 0) {
        unlink(target);
        return ERR_OTHER;
    }

    LOGI("Finished");
    return EXIT_SUCCESS;
}

static int setup_adb_root(const char* root_path, bool inject_mode) {
    if (selinux_check_access("u:r:adbd:s0", "u:r:adbd:s0", "process", "setcurrent", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 u:r:adbd:s0 process setcurrent not allowed");
        return ERR_SELINUX;
    }

    char* curr_con = nullptr;
    attrs data_adb_attr{};
    if (getcon(&curr_con) != 0) {
        PLOGE("getcon");
        return ERR_SELINUX;
    }

    if (getattrs("/data/adb", &data_adb_attr) != 0) {
        freecon(curr_con);
        return ERR_OTHER;
    }

    if (selinux_check_access("u:r:adbd:s0", curr_con, "process", "dyntransition", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s process dyntransition not allowed", curr_con);
        freecon(curr_con);
        return ERR_SELINUX;
    }

    if (selinux_check_access(curr_con, curr_con, "process", "setsockcreate", nullptr) != 0) {
        PLOGE("%s %s process setsockcreate not allowed", curr_con, curr_con);
        freecon(curr_con);
        return ERR_SELINUX;
    }

    constexpr const char* sui_dir = "/data/adb/sui";
    if (mkdir(sui_dir, data_adb_attr.mode) == -1 && errno != EEXIST) {
        PLOGE("mkdir %s", sui_dir);
        freecon(curr_con);
        return ERR_OTHER;
    }
    if (setattrs(sui_dir, &data_adb_attr) != 0) {
        freecon(curr_con);
        return ERR_OTHER;
    }

    attrs seclabel_attr = data_adb_attr;
    seclabel_attr.context = strdup(data_adb_attr.context);
    seclabel_attr.is_malloced = true;
    seclabel_attr.mode = 0600;
    if (!seclabel_attr.context) {
        PLOGE("strdup /data/adb context");
        freecon(curr_con);
        return ERR_OTHER;
    }

    if (FILE* fp = fopen("/data/adb/sui/seclabel.tmp", "we")) {
        int fd = fileno(fp);
        bool ok = true;
        if (fputs(curr_con, fp) == EOF) {
            PLOGE("fputs /data/adb/sui/seclabel.tmp");
            ok = false;
        }
        if (ok && fchmod(fd, 0600) != 0) {
            PLOGE("fchmod /data/adb/sui/seclabel.tmp");
            ok = false;
        }
        if (fclose(fp) != 0) {
            PLOGE("fclose /data/adb/sui/seclabel.tmp");
            ok = false;
        }
        if (ok && setattrs("/data/adb/sui/seclabel.tmp", &seclabel_attr) != 0) {
            ok = false;
        }
        if (!ok) {
            unlink("/data/adb/sui/seclabel.tmp");
            freecon(curr_con);
            return ERR_OTHER;
        }
        if (rename("/data/adb/sui/seclabel.tmp", "/data/adb/sui/seclabel") != 0) {
            PLOGE("rename /data/adb/sui/seclabel.tmp");
            unlink("/data/adb/sui/seclabel.tmp");
            freecon(curr_con);
            return ERR_OTHER;
        }
    } else {
        PLOGE("fopen /data/adb/sui/seclabel");
        freecon(curr_con);
        return ERR_OTHER;
    }

    freecon(curr_con);

    if (inject_mode) {
        // Prepare ZN injection without wrapper mounts.
        const char* adbd = access("/apex/com.android.adbd/bin/adbd", F_OK) == 0
                               ? "/apex/com.android.adbd/bin/adbd"
                               : "/system/bin/adbd";
        if (!is_dynamically_linked(adbd)) {
            LOGE("adbd injection requires a dynamically linked executable: %s", adbd);
            return ERR_ADBD_IS_STATIC;
        }

        constexpr const char* marker = "/data/adb/sui/adbd_inject_prepared";
        attrs marker_attr{};
        if (getattrs("/data/adb/sui/seclabel", &marker_attr) != 0) {
            return ERR_OTHER;
        }
        marker_attr.mode = 0600;
        ScopedFd marker_fd(open(marker, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
        if (marker_fd.get() < 0 || setattrs(marker, &marker_attr) != 0 ||
            write(marker_fd.get(), "v4\n", 3) != 3) {
            PLOGE("prepare %s", marker);
            unlink(marker);
            return ERR_OTHER;
        }
        LOGI("Prepared adbd injection without Bind Mount");
        return EXIT_SUCCESS;
    }

    char adbd_wrapper[PATH_MAX]{0};
    if (!build_path(adbd_wrapper, sizeof(adbd_wrapper), "%s/bin/adbd_wrapper", root_path)) {
        PLOGE("build_path %s/bin/adbd_wrapper", root_path);
        return ERR_OTHER;
    }

    char adbd_preload[PATH_MAX]{0};
    if (!build_path(adbd_preload, sizeof(adbd_preload), "%s/lib/libadbd_preload.so", root_path)) {
        PLOGE("build_path %s/lib/libadbd_preload.so", root_path);
        return ERR_OTHER;
    }

    if (android_get_device_api_level() >= __ANDROID_API_R__) {
        if (access("/apex/com.android.adbd/bin/adbd", F_OK) != 0) {
            PLOGE("access /apex/com.android.adbd/bin/adbd");
            LOGW("Apex not exists on API 31+ device");
        } else {
            LOGI("Use adbd from /apex");
            return setup_adb_root_apex(root_path, adbd_wrapper, adbd_preload);
        }
    }

    if (access("/system/bin/adbd", F_OK) != 0) {
        PLOGE("access /system/bin/adbd");
        LOGW("No adbd");
        return ERR_NO_ADBD;
    }

    LOGI("Use adbd from /system");
    return setup_adb_root_non_apex(root_path, adbd_wrapper, adbd_preload);
}

inline int adb_root_main(int argc, char** argv) {
    if (argc < 2)
        return ERR_OTHER;
    LOGI("Setup adb root support: %s", argv[1]);

    const bool inject_mode = argc > 2 && strcmp(argv[2], "--inject") == 0;

    if (init_selinux()) {
        auto root_path = argv[1];
        return setup_adb_root(root_path, inject_mode);
    } else {
        LOGW("Cannot load libselinux");
        return 1;
    }
}
