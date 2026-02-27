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
#include <logging.h>
#include <unistd.h>
#include <sched.h>
#include <app_process.h>
#include <misc.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * argv[1]: path of the module, such as /data/adb/modules/zygisk-sui
 */
static int sui_main(int argc, char** argv) {
    LOGI("Sui starter begin: %s", argv[1]);

    if (daemon(false, false) != 0) {
        PLOGE("daemon");
        return EXIT_FAILURE;
    }

    {
        int fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
        if (fd >= 0) {
            const char value[] = "-1000";
            if (write_full(fd, value, sizeof(value) - 1) != 0) {
                LOGW("write /proc/self/oom_score_adj failed with %d: %s", errno, strerror(errno));
            }
            close(fd);
        } else {
            LOGW("open /proc/self/oom_score_adj failed with %d: %s", errno, strerror(errno));
        }
    }

    wait_for_zygote();

    if (access("/data/adb/sui", F_OK) != 0) {
        mkdir("/data/adb/sui", 0700);
    }
    chmod("/data/adb/sui", 0700);
    chown("/data/adb/sui", 0, 0);

    auto root_path = argv[1];

    char dex_path[PATH_MAX]{0};
    strcpy(dex_path, root_path);
    strcat(dex_path, "/sui.dex");

    app_process(dex_path, root_path, "rikka.sui.server.Starter", "sui");

    return EXIT_SUCCESS;
}
