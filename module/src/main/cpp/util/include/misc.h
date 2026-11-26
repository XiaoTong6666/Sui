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
 * Copyright (c) 2021 Sui Contributors
 */

#ifndef _MISC_H
#define _MISC_H

#include <functional>
#include <string>
#include <sys/types.h>

int mkdirs(const char* pathname, mode_t mode);
int ensure_dir(const char* path, mode_t mode);
int copyfileat(int src_path_fd, const char* src_path, int dst_path_fd, const char* dst_path);
int copyfile(const char* src_path, const char* dst_path);
ssize_t read_eintr(int fd, void* out, size_t len);
int read_full(int fd, void* buf, size_t count);
int write_full(int fd, const void* buf, size_t count);

// Return false when /proc cannot be scanned, including readdir errors.
bool foreach_proc(const std::function<bool(pid_t)>& func);

#endif  // _MISC_H
