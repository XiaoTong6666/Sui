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
#include <logging.h>
#include <cstring>

bool check() {
    if (selinux_check_access("u:r:adbd:s0", "u:r:adbd:s0", "process", "setcurrent", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 u:r:adbd:s0 process setcurrent not allowed");
        return false;
    }

    char *curr_con = nullptr, *data_adb_con = nullptr;
    if (getcon(&curr_con) != 0) {
        PLOGE("getcon");
        return false;
    }

    if (getfilecon_raw("/data/adb", &data_adb_con) != 0) {
        PLOGE("getfilecon_raw");
        return false;
    }

    if (selinux_check_access("u:r:adbd:s0", curr_con, "process", "dyntransition", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s process dyntransition not allowed", curr_con);
        return false;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "getopt",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket getopt not allowed", curr_con);
        return false;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "getattr",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket getattr not allowed", curr_con);
        return false;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "read",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket read not allowed", curr_con);
        return false;
    }

    if (selinux_check_access("u:r:system_server:s0", curr_con, "unix_stream_socket", "write",
                             nullptr) != 0) {
        PLOGE("u:r:system_server:s0 %s unix_stream_socket write not allowed", curr_con);
        return false;
    }

    if (selinux_check_access("u:r:init:s0", "u:r:adbd:s0", "process2", "nosuid_transition",
                             nullptr) != 0) {
        PLOGE("u:r:init:s0 u:r:adbd:s0 process2 nosuid_transition not allowed");
        return false;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "execute", nullptr) != 0) {
        PLOGE("u:r:adbd:s0 %s file execute not allowed", curr_con);
        return false;
    }

    if (selinux_check_access("u:r:adbd:s0", data_adb_con, "file", "execute_no_trans", nullptr) !=
        0) {
        PLOGE("u:r:adbd:s0 %s file execute_no_trans not allowed", data_adb_con);
        return false;
    }
    return true;
}

int main(int argc, char* argv[]) {
    return check() ? 0 : 1;
}