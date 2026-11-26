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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * Copyright (c) 2021-2026 Sui Contributors
 */

#pragma once

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

namespace sui::adbd {

// Unlike a persistent 'ready' file, the kernel boot ID prevents an adbd that
// starts before service.sh from trusting the previous boot's injection state.
inline bool CurrentBootMarker(char* buffer, size_t size) {
    char uuid[40]{};
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    ssize_t bytes;
    do {
        bytes = read(fd, uuid, sizeof(uuid) - 1);
    } while (bytes < 0 && errno == EINTR);
    close(fd);
    if (bytes <= 0)
        return false;
    uuid[bytes] = '\0';
    uuid[strcspn(uuid, "\r\n")] = '\0';
    if (strlen(uuid) != 36)
        return false;
    int length = snprintf(buffer, size, "v5:%s\n", uuid);
    return length > 0 && static_cast<size_t>(length) < size;
}

}  // namespace sui::adbd
