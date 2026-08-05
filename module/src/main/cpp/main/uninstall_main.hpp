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
#include <cstdio>
#include <cctype>
#include <cerrno>
#include <logging.h>
#include <sys/system_properties.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sched.h>
#include <app_process.h>

static bool is_valid_package_name(const char* package_name) {
    bool segment_start = true;
    for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(package_name);
         *cursor != '\0'; ++cursor) {
        if (*cursor == '.') {
            if (segment_start) {
                return false;
            }
            segment_start = true;
        } else if (segment_start) {
            if (!isalpha(*cursor)) {
                return false;
            }
            segment_start = false;
        } else if (isalnum(*cursor) || *cursor == '_') {
            segment_start = false;
        } else {
            return false;
        }
    }
    return !segment_start;
}

static bool read_installed_settings_package(const char* root_path, char* package_name,
                                            size_t package_name_size) {
    if (package_name_size == 0) {
        return false;
    }
    package_name[0] = '\0';

    char path[PATH_MAX]{0};
    int written = snprintf(path, sizeof(path), "%s/settings", root_path);
    if (written < 0 || static_cast<size_t>(written) >= sizeof(path)) {
        return false;
    }

    FILE* file = fopen(path, "r");
    if (file == nullptr) {
        return false;
    }
    bool result = fgets(package_name, package_name_size, file) != nullptr &&
                  strpbrk(package_name, "\r\n") != nullptr;
    fclose(file);
    if (!result) {
        package_name[0] = '\0';
        return false;
    }

    package_name[strcspn(package_name, "\r\n")] = '\0';
    if (!is_valid_package_name(package_name)) {
        package_name[0] = '\0';
        return false;
    }
    return true;
}

/*
 * argv[1]: path of the module, such as /data/adb/modules/zygisk-sui
 */
static int uninstall_main(int argc, char** argv) {
    if (argc < 2) {
        LOGE("Sui uninstaller requires the module path");
        return EXIT_FAILURE;
    }
    LOGI("Sui uninstaller begin: %s", argv[1]);

    char sdk_version[PROP_VALUE_MAX]{0};
    if (__system_property_get("ro.build.version.sdk", sdk_version) > 0 && atoi(sdk_version) < 26) {
        LOGI("Shortcut cleanup is not required before Android 8");
        return EXIT_SUCCESS;
    }

    auto root_path = argv[1];
    char settings_package[PATH_MAX]{0};
    bool has_settings_package =
        read_installed_settings_package(root_path, settings_package, sizeof(settings_package));
    if (!has_settings_package) {
        LOGW("Cannot read the installed Settings package");
    }

    char dex_path[PATH_MAX]{0};
    int written = snprintf(dex_path, sizeof(dex_path), "%s/sui.dex", root_path);
    if (written < 0 || static_cast<size_t>(written) >= sizeof(dex_path)) {
        errno = ENAMETOOLONG;
        PLOGE("snprintf %s/sui.dex", root_path);
        return EXIT_FAILURE;
    }

    char dex_copy_path[] = "/dev/sui.dex.XXXXXX";
    int dex_copy_fd = mkstemp(dex_copy_path);
    if (dex_copy_fd == -1) {
        PLOGE("mkstemp %s", dex_copy_path);
        return EXIT_FAILURE;
    }
    close(dex_copy_fd);

    if (copyfile(dex_path, dex_copy_path) != 0) {
        PLOGE("copyfile");
        unlink(dex_copy_path);
        return EXIT_FAILURE;
    }

    if (daemon(false, false) != 0) {
        PLOGE("daemon");
        unlink(dex_copy_path);
        return EXIT_FAILURE;
    }

    wait_for_zygote();

    pid_t child = fork();
    if (child == -1) {
        PLOGE("fork");
        unlink(dex_copy_path);
        return EXIT_FAILURE;
    }
    if (child == 0) {
        app_process(dex_copy_path, "/dev", "rikka.sui.installer.Uninstaller", "sui_uninstaller",
                    has_settings_package ? settings_package : nullptr);
        _exit(EXIT_FAILURE);
    }

    int status = -1;
    while (waitpid(child, &status, 0) == -1) {
        if (errno != EINTR) {
            PLOGE("waitpid");
            status = -1;
            break;
        }
    }
    if (unlink(dex_copy_path) != 0) {
        PLOGE("unlink %s", dex_copy_path);
    }

    return status != -1 && WIFEXITED(status) ? WEXITSTATUS(status) : EXIT_FAILURE;
}
