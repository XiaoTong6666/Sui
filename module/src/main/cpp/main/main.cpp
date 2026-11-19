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
#include <unistd.h>

using main_func = int (*)(int, char**);
int run_sui_main(int argc, char** argv);
int run_adb_root_main(int argc, char** argv);
int run_uninstall_main(int argc, char** argv);
int sui_logcat_main(int argc, char** argv);

struct Applet {
    const char* name;
    main_func run;
};

static constexpr Applet kApplets[] = {
    {"sui", run_sui_main},
    {"sui_logcat", sui_logcat_main},
    {"adb_root", run_adb_root_main},
    {"uninstall", run_uninstall_main},
};

int main(int argc, char** argv) {
    if (getuid() != 0) {
        exit(EXIT_FAILURE);
    }

    auto base = basename(argv[0]);
    for (const auto& applet : kApplets) {
        if (strcmp(base, applet.name) == 0) {
            return applet.run(argc, argv);
        }
    }
    return 1;
}
