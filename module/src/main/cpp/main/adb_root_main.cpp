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

#define SUI_LOG_COMPONENT "AdbRoot"
#include "adb_root.hpp"

int run_adb_root_main(int argc, char** argv) {
    return adb_root_main(argc, argv);
}

int prepare_adb_root_main(int argc, char** argv, bool* already_prepared) {
    return adb_root_main(argc, argv, already_prepared);
}

bool adbd_apex_running_from_backup() {
    char value[PROP_VALUE_MAX]{};
    if (__system_property_get("init.svc_debug_pid.adbd", value) <= 0)
        return false;
    char* end = nullptr;
    long pid = strtol(value, &end, 10);
    if (!end || *end || pid <= 0)
        return false;
    char executable[64];
    return build_path(executable, sizeof(executable), "/proc/%ld/exe", pid) &&
           same_file_identity(executable, "/apex/com.android.adbd/bin/adbd_real");
}
