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

#ifndef _LOGGING_H
#define _LOGGING_H

#include <errno.h>
#include <string.h>
#include "android/log.h"

#ifndef SUI_LOG_COMPONENT
#define SUI_LOG_COMPONENT "Native"
#endif

// One Android log tag; preserve the emitting component in the message.
#define SUI_LOG_PRINT(priority, fmt, args...) \
    __android_log_print(priority, "Sui", "[" SUI_LOG_COMPONENT "] " fmt, ##args)

#ifdef DEBUG
#define LOGD(...) SUI_LOG_PRINT(ANDROID_LOG_DEBUG, __VA_ARGS__)
#define LOGV(...) SUI_LOG_PRINT(ANDROID_LOG_VERBOSE, __VA_ARGS__)
#define LOGI(...) SUI_LOG_PRINT(ANDROID_LOG_INFO, __VA_ARGS__)
#define LOGW(...) SUI_LOG_PRINT(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGE(...) SUI_LOG_PRINT(ANDROID_LOG_ERROR, __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#else
#define LOGD(...)
#define LOGV(...)
#define LOGI(...)
#define LOGW(...) SUI_LOG_PRINT(ANDROID_LOG_WARN, __VA_ARGS__)
#define LOGE(...) SUI_LOG_PRINT(ANDROID_LOG_ERROR, __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))
#endif

#endif  // _LOGGING_H
