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
#include <dlfcn.h>
#include <logging.h>
#include <cstring>
#include <sys/system_properties.h>

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
}
