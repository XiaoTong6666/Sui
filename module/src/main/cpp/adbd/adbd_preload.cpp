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

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#define SUI_LOG_COMPONENT "Adbd"
#include <logging.h>
#include <sys/system_properties.h>
#include <unistd.h>

extern "C" {
[[gnu::constructor]] void constructor() {
    LOGD("preload constructor");

    auto ld_preload = getenv("SUI_LD_PRELOAD_BACKUP");
    if (ld_preload) {
        setenv("LD_PRELOAD", ld_preload, 1);
    } else {
        unsetenv("LD_PRELOAD");
    }
}

[[gnu::visibility("default")]] [[maybe_unused]] int
__android_log_is_debuggable() {  // NOLINT(bugprone-reserved-identifier)
    return 1;
}

using property_get_t = int(const char*, char*, const char*);
using setcon_hook_t = int(const char*);
using setsockcreatecon_raw_t = int(const char*);

static constexpr char kAdbdSockcreateLabel[] = "u:r:adbd:s0";
static constexpr char kSuiAdbdRootSeclabelEnv[] = "SUI_ADBD_ROOT_SECLABEL";

static bool ShouldResetSockcreateToAdbd(const char* target) {
    if (!target || strcmp(target, kAdbdSockcreateLabel) == 0) {
        return false;
    }

    const char* requested = getenv(kSuiAdbdRootSeclabelEnv);
    return requested && strcmp(target, requested) == 0;
}

static int SetSockcreateLabel(const char* label) {
    static setsockcreatecon_raw_t* original = nullptr;
    if (!original) {
        original = (setsockcreatecon_raw_t*)dlsym(RTLD_DEFAULT, "setsockcreatecon_raw");
        if (!original) {
            original = (setsockcreatecon_raw_t*)dlsym(RTLD_DEFAULT, "setsockcreatecon");
        }
    }
    if (!original) {
        LOGE("setsockcreatecon(_raw): original symbol not found");
        errno = ENOSYS;
        return -1;
    }

    return original(label);
}

static int HandleSetcon(const char* symbol_name, setcon_hook_t*& original, const char* con) {
    if (!original) {
        original = (setcon_hook_t*)dlsym(RTLD_NEXT, symbol_name);
    }
    if (!original) {
        LOGE("%s: original symbol not found", symbol_name);
        errno = ENOSYS;
        return -1;
    }

    int rc = original(con);
    int saved_errno = errno;

    if (rc == 0 && ShouldResetSockcreateToAdbd(con)) {
        if (SetSockcreateLabel(kAdbdSockcreateLabel) != 0) {
            int sockcreate_errno = errno;
            errno = sockcreate_errno;
            PLOGE("set sockcreate %s", kAdbdSockcreateLabel);
            return -1;
        }

        if (unsetenv(kSuiAdbdRootSeclabelEnv) != 0) {
            int unset_errno = errno;
            errno = unset_errno;
            PLOGE("unsetenv %s", kSuiAdbdRootSeclabelEnv);
            errno = saved_errno;
        }
    }

    errno = saved_errno;
    return rc;
}

[[gnu::visibility("default")]] [[maybe_unused]] int property_get(
    const char* key, char* value,
    const char* default_value) {  // NOLINT(bugprone-reserved-identifier)
    if (key && value && strcmp("ro.debuggable", key) == 0) {
        value[0] = '1';
        value[1] = '\0';
        return 1;
    }

    static property_get_t* original = nullptr;
    if (!original) {
        original = (property_get_t*)dlsym(RTLD_NEXT, "property_get");
    }
    if (original) {
        return original(key, value, default_value);
    }
    return -1;
}

[[gnu::visibility("default")]] [[maybe_unused]] int selinux_android_setcon(
    const char* con) {  // NOLINT(bugprone-reserved-identifier)
    static setcon_hook_t* original = nullptr;
    return HandleSetcon("selinux_android_setcon", original, con);
}

[[gnu::visibility("default")]] [[maybe_unused]] int setcon(
    const char* con) {  // NOLINT(bugprone-reserved-identifier)
    static setcon_hook_t* original = nullptr;
    return HandleSetcon("setcon", original, con);
}
}
