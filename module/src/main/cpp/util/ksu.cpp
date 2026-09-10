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
 * Copyright (c) 2026 Sui Contributors
 */

#include <ksu.h>

#include <cerrno>
#include <cstdint>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {

// Keep this tiny compatibility shim in sync with KernelSU's public UAPI.
// KernelSU installs an anonymous driver fd when reboot(2) is invoked with
// these private magic values. Unsupported kernels simply reject the syscall.
constexpr std::uint32_t KSU_INSTALL_MAGIC1 = 0xDEADBEEF;
constexpr std::uint32_t KSU_INSTALL_MAGIC2 = 0xCAFEBABE;
constexpr unsigned long KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT = _IO('K', 21);

int get_ksu_driver_fd() {
    int fd = -1;
    errno = 0;
    // This mirrors ksud::ksucalls::init_driver_fd(). KernelSU intercepts this
    // otherwise-invalid reboot(2) invocation and installs anon_inode:[ksu_driver]
    // into the current process. Non-KernelSU kernels leave fd untouched.
    (void)syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd);
    return fd;
}

}  // namespace

KsuNoEscapeResult ksu_disable_escape_to_root() {
    if (getuid() != 0) {
        errno = EPERM;
        return KsuNoEscapeResult::Failed;
    }

    int fd = get_ksu_driver_fd();
    if (fd < 0) {
        // No KernelSU supercall hook (or a KernelSU generation without the
        // anonymous driver fd UAPI) is an unsupported environment, not a Sui
        // startup failure.
        errno = ENOTSUP;
        return KsuNoEscapeResult::Unsupported;
    }

    errno = 0;
    int rc = ioctl(fd, KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT, nullptr);
    int saved_errno = errno;
    close(fd);

    if (rc == 0) {
        return KsuNoEscapeResult::Enabled;
    }

    errno = saved_errno;
    if (saved_errno == ENOTTY) {
        return KsuNoEscapeResult::Unsupported;
    }
    return KsuNoEscapeResult::Failed;
}
