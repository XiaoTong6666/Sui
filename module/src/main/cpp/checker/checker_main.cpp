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

#include <selinux.h>
#include <android/api-level.h>
#include <logging.h>
#include <cstring>
#include <unistd.h>

bool check() {
    bool success = false;
    const int api = android_get_device_api_level();
    char *curr_con = nullptr, *data_adb_con = nullptr;
    char *sui_dir_con = nullptr, *seclabel_con = nullptr;

    if (selinux_check_access("u:r:adbd:s0", "u:r:adbd:s0", "process", "setcurrent", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 u:r:adbd:s0 process setcurrent not allowed");
        goto cleanup;
    }

    if (getcon(&curr_con) != 0) {
        PLOGE("getcon");
        goto cleanup;
    }

    if (selinux_check_access(curr_con, curr_con, "process", "setcurrent", nullptr) != 0) {
        PLOGE("%s %s process setcurrent not allowed", curr_con, curr_con);
        goto cleanup;
    }

    if (selinux_check_access(curr_con, "u:r:shell:s0", "process", "dyntransition", nullptr) != 0) {
        PLOGE("%s u:r:shell:s0 process dyntransition not allowed", curr_con);
        goto cleanup;
    }

    if (getfilecon_raw("/data/adb", &data_adb_con) < 0) {
        PLOGE("getfilecon_raw");
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", curr_con, "process", "dyntransition", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s process dyntransition not allowed", curr_con);
        goto cleanup;
    }

    if (selinux_check_access(curr_con, curr_con, "process", "setsockcreate", nullptr) != 0) {
        PLOGE("%s %s process setsockcreate not allowed", curr_con, curr_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "getopt",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket getopt not allowed", curr_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "getattr",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket getattr not allowed", curr_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "read",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket read not allowed", curr_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "write",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket write not allowed", curr_con);
        goto cleanup;
    }

    if (api >= 29 && selinux_check_access("u:r:init:s0", "u:r:adbd:s0", "process2",
                                          "nosuid_transition", nullptr) != 0) {
        PLOGE("u:r:init:s0 u:r:adbd:s0 process2 nosuid_transition not allowed");
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "dir", "search", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s dir search not allowed", data_adb_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "dir", "getattr", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s dir getattr not allowed", data_adb_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "getattr", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s file getattr not allowed", data_adb_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "open", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s file open not allowed", data_adb_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "read", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s file read not allowed", data_adb_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "execute", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s file execute not allowed", data_adb_con);
        goto cleanup;
    }

    if (api >= 27 &&
        selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "map", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s file map not allowed", data_adb_con);
        goto cleanup;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "execute_no_trans", nullptr) !=
        0) {
        PLOGE("u:r:adbd:s0 %s file execute_no_trans not allowed", data_adb_con);
        goto cleanup;
    }

    if (access("/data/adb/sui", F_OK) == 0) {
        if (getfilecon_raw("/data/adb/sui", &sui_dir_con) < 0) {
            PLOGE("getfilecon_raw /data/adb/sui");
            goto cleanup;
        }

        if (selinux_check_access("u:r:adbd:s0", sui_dir_con, "dir", "search", nullptr) != 0) {
            PLOGE("u:r:adbd:s0 %s dir search not allowed", sui_dir_con);
            goto cleanup;
        }

        if (selinux_check_access("u:r:adbd:s0", sui_dir_con, "dir", "getattr", nullptr) != 0) {
            PLOGE("u:r:adbd:s0 %s dir getattr not allowed", sui_dir_con);
            goto cleanup;
        }
    }

    if (access("/data/adb/sui/seclabel", F_OK) == 0) {
        if (getfilecon_raw("/data/adb/sui/seclabel", &seclabel_con) < 0) {
            PLOGE("getfilecon_raw /data/adb/sui/seclabel");
            goto cleanup;
        }

        if (selinux_check_access("u:r:adbd:s0", seclabel_con, "file", "getattr", nullptr) != 0) {
            PLOGE("u:r:adbd:s0 %s file getattr not allowed", seclabel_con);
            goto cleanup;
        }

        if (selinux_check_access("u:r:adbd:s0", seclabel_con, "file", "open", nullptr) != 0) {
            PLOGE("u:r:adbd:s0 %s file open not allowed", seclabel_con);
            goto cleanup;
        }

        if (selinux_check_access("u:r:adbd:s0", seclabel_con, "file", "read", nullptr) != 0) {
            PLOGE("u:r:adbd:s0 %s file read not allowed", seclabel_con);
            goto cleanup;
        }
    }

    success = true;

cleanup:
    freecon(seclabel_con);
    freecon(sui_dir_con);
    freecon(data_adb_con);
    freecon(curr_con);
    return success;
}

int main(int argc, char* argv[]) {
    if (!init_selinux()) {
        LOGE("init_selinux failed");
        return 1;
    }
    return check() ? 0 : 1;
}
