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

#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include "sui_main.hpp"
#include "adb_root.hpp"
#include "uninstall_main.hpp"

using main_func = int (*)(int, char**);

static main_func applet_func[] = {sui_main, adb_root_main, uninstall_main, nullptr};

static const char* applet_names[] = {"sui", "adb_root", "uninstall", nullptr};

int main(int argc, char** argv) {
    auto uid = getuid();
    if (uid != 0) {
        exit(EXIT_FAILURE);
    }

    auto base = basename(argv[0]);
    for (int i = 0; applet_names[i]; ++i) {
        if (strcmp(base, applet_names[i]) == 0) {
            return applet_func[i](argc, argv);
        }
    }
    return 1;
}
