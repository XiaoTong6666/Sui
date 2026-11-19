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

#include <cstdlib>
#include <cstring>
#include <sched.h>
#include <unistd.h>
#include <sys/mount.h>
#define SUI_LOG_COMPONENT "Adbd"
#include <logging.h>
#include <string_view>

using namespace std::literals::string_view_literals;

static constexpr char kSuiAdbdRootSeclabelEnv[] = "SUI_ADBD_ROOT_SECLABEL";
static constexpr auto kRootSeclabelArgPrefix = "--root_seclabel="sv;

int main(int argc, char** argv) {
    const char* adbd_ld_preload;
    const char* adbd_real;

    char root_seclabel_value[128] = "u:r:su:s0";
    if (FILE* fp = fopen("/data/adb/sui/seclabel", "re")) {
        if (fgets(root_seclabel_value, sizeof(root_seclabel_value), fp)) {
            root_seclabel_value[strcspn(root_seclabel_value, "\r\n")] = '\0';
        }
        fclose(fp);
    } else {
        PLOGE("fopen /data/adb/sui/seclabel");
    }

    auto apex = "/apex/"sv;
    std::string_view argv0{argv[0]};
    if (argv0.length() > apex.length() && argv0.substr(0, apex.length()) == apex) {
        adbd_real = "/apex/com.android.adbd/bin/adbd_real";
#ifdef __LP64__
        adbd_ld_preload = "/apex/com.android.adbd/lib64/libsui_adbd_preload.so";
#else
        adbd_ld_preload = "/apex/com.android.adbd/lib/libsui_adbd_preload.so";
#endif
    } else {
        adbd_real = "/system/bin/adbd_real";
#ifdef __LP64__
        adbd_ld_preload = "/system/lib64/libsui_adbd_preload.so";
#else
        adbd_ld_preload = "/system/lib/libsui_adbd_preload.so";
#endif
    }

    LOGI("adbd_main");
    LOGD("adbd_real=%s", adbd_real);
    LOGD("adbd_ld_preload=%s", adbd_ld_preload);

    auto ld_preload = getenv("LD_PRELOAD");
    char new_ld_preload[PATH_MAX]{};
    if (ld_preload) {
        setenv("SUI_LD_PRELOAD_BACKUP", ld_preload, 1);
        snprintf(new_ld_preload, PATH_MAX, "%s:%s", adbd_ld_preload, ld_preload);
    } else {
        strcpy(new_ld_preload, adbd_ld_preload);
    }
    setenv("LD_PRELOAD", new_ld_preload, 1);
    LOGD("LD_PRELOAD=%s", new_ld_preload);

    bool root_seclabel_rewritten = false;
    for (int i = 1; i < argc; ++i) {
        std::string_view argv_i{argv[i]};
        if (argv_i.length() > kRootSeclabelArgPrefix.length() &&
            argv_i.substr(0, kRootSeclabelArgPrefix.length()) == kRootSeclabelArgPrefix) {
            char seclabel_arg[128];
            size_t real_len =
                strnlen(root_seclabel_value, sizeof(seclabel_arg) - strlen("--root_seclabel=") - 1);
            snprintf(seclabel_arg, sizeof(seclabel_arg), "--root_seclabel=%.*s", (int)real_len,
                     root_seclabel_value);
            char* replaced = strdup(seclabel_arg);
            if (!replaced) {
                PLOGE("strdup %s", seclabel_arg);
                return EXIT_FAILURE;
            }
            argv[i] = replaced;
            root_seclabel_rewritten = true;
            LOGD("root_seclabel -> %.*s", (int)real_len, root_seclabel_value);
        }
    }

    if (root_seclabel_rewritten && setenv(kSuiAdbdRootSeclabelEnv, root_seclabel_value, 1) != 0) {
        PLOGE("setenv %s", kSuiAdbdRootSeclabelEnv);
        return EXIT_FAILURE;
    }

    execv(adbd_real, argv);
    PLOGE("execv %s", adbd_real);
    return EXIT_FAILURE;
}
