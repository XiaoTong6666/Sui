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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <link.h>
#include <sys/auxv.h>
#include <unistd.h>
#include <logging.h>
#include <time.h>
#include <initializer_list>
#include <adbd_inject_protocol.hpp>

#include <zygisk_next_api.h>

namespace {

constexpr char kReadyMarker[] = "/data/adb/sui/adbd_inject_prepared";
constexpr char kRootLabelFile[] = "/data/adb/sui/seclabel";
constexpr char kDefaultRootLabel[] = "u:r:su:s0";
constexpr char kAdbdLabel[] = "u:r:adbd:s0";

using Setcon = int (*)(const char*);
using Debuggable = int (*)();
using PropertyGet = int (*)(const char*, char*, const char*);

Setcon original_selinux_android_setcon = nullptr;
Setcon original_setcon = nullptr;
Debuggable original_debuggable = nullptr;
PropertyGet original_property_get = nullptr;
char root_label[128]{};
sui::adbd::Protocol protocol;

uint64_t StartToken() {
    timespec ts{};
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + ts.tv_nsec;
}

const uint64_t attempt_token = StartToken();

void Report(const char* event) {
    const uint64_t snapshot = protocol.Snapshot();
    LOGI("adbd injection: pid=%d token=%llu event=%s state=%u reason=%u", getpid(),
         static_cast<unsigned long long>(attempt_token), event,
         static_cast<unsigned>(snapshot & 0xffffffffU), static_cast<unsigned>(snapshot >> 32));
}

int SetSocketLabel(const char* label) {
    using SetSockcreate = int (*)(const char*);
    auto* original = reinterpret_cast<SetSockcreate>(dlsym(RTLD_DEFAULT, "setsockcreatecon_raw"));
    if (!original) {
        original = reinterpret_cast<SetSockcreate>(dlsym(RTLD_DEFAULT, "setsockcreatecon"));
    }
    if (!original) {
        errno = ENOSYS;
        return -1;
    }
    return original(label);
}

int CallSetcon(Setcon original, const char* context) {
    if (!original) {
        errno = ENOSYS;
        return -1;
    }
    // Preserve unrelated transitions, including trade-in mode.
    const bool root_transition =
        protocol.Active() && context &&
        (strcmp(context, kDefaultRootLabel) == 0 || strcmp(context, root_label) == 0);
    const bool redirect = root_transition && strcmp(context, root_label) != 0;
    int result = original(redirect ? root_label : context);
    int saved_errno = errno;
    if (result == 0 && root_transition && strcmp(context, kAdbdLabel) != 0 &&
        SetSocketLabel(kAdbdLabel) != 0) {
        PLOGE("adbd injection: restore socket label");
        return -1;
    }
    errno = saved_errno;
    return result;
}

int HookSelinuxAndroidSetcon(const char* context) {
    return CallSetcon(original_selinux_android_setcon, context);
}

int HookSetcon(const char* context) {
    return CallSetcon(original_setcon, context);
}

int HookDebuggable() {
    return protocol.Active() ? 1 : (original_debuggable ? original_debuggable() : 0);
}

int HookPropertyGet(const char* key, char* value, const char* default_value) {
    if (protocol.Active() && key && value && strcmp(key, "ro.debuggable") == 0) {
        strcpy(value, "1");
        return 1;
    }
    return original_property_get ? original_property_get(key, value, default_value) : -1;
}

struct MainImage {
    const void* program_headers;
    void* base = nullptr;
};

int LocateMainExecutable(dl_phdr_info* info, size_t, void* opaque) {
    auto* main = static_cast<MainImage*>(opaque);
    // Match the main ELF using AT_PHDR.
    if (info->dlpi_phdr == main->program_headers ||
        (info->dlpi_name && info->dlpi_name[0] == '\0')) {
        main->base = reinterpret_cast<void*>(info->dlpi_addr);
        return 1;
    }
    return 0;
}

bool ReadRootLabel() {
    int marker = open(kReadyMarker, O_RDONLY | O_CLOEXEC);
    if (marker < 0)
        return false;
    close(marker);

    FILE* file = fopen(kRootLabelFile, "re");
    if (!file)
        return false;
    const bool read_ok = fgets(root_label, sizeof(root_label), file) != nullptr;
    fclose(file);
    if (!read_ok)
        return false;

    root_label[strcspn(root_label, "\r\n")] = '\0';
    const size_t length = strlen(root_label);
    return length > 7 && strncmp(root_label, "u:r:", 4) == 0 &&
           strcmp(root_label + length - 3, ":s0") == 0;
}

struct HookRegistration {
    const char* symbol = nullptr;
    void* original = nullptr;
};

void OnModuleLoaded(void*, const ZygiskNextAPI* api) {
    if (!protocol.AcceptApi(zn_module.target_api_version, true)) {
        Report("rejected-api-or-duplicate");
        return;
    }
    if (!protocol.Loaded(api != nullptr && api->pltHook != nullptr)) {
        Report("missing-required-interface");
        return;
    }
    Report("api-compatible-and-module-loaded");
    if (!protocol.Begin()) {
        Report("duplicate-initialization");
        return;
    }
    Report("initializing");
    if (!ReadRootLabel()) {
        protocol.Fail(sui::adbd::Failure::MissingConfiguration);
        Report("missing-prepared-configuration");
        return;
    }

    MainImage main{reinterpret_cast<void*>(getauxval(AT_PHDR))};
    dl_iterate_phdr(LocateMainExecutable, &main);
    if (!main.base) {
        protocol.Fail(sui::adbd::Failure::MissingExecutable);
        Report("missing-executable");
        return;
    }

    HookRegistration context{}, debug{};
    auto install = [&](const char* symbol, void* handler, void** original,
                       HookRegistration& record) -> bool {
        *original = nullptr;
        if (api->pltHook(main.base, symbol, handler, original) != ZN_SUCCESS || !*original)
            return false;
        record = {symbol, *original};
        return true;
    };

    const bool context_ok =
        install("selinux_android_setcon", reinterpret_cast<void*>(HookSelinuxAndroidSetcon),
                reinterpret_cast<void**>(&original_selinux_android_setcon), context) ||
        install("setcon", reinterpret_cast<void*>(HookSetcon),
                reinterpret_cast<void**>(&original_setcon), context);
    const bool debug_ok =
        install("__android_log_is_debuggable", reinterpret_cast<void*>(HookDebuggable),
                reinterpret_cast<void**>(&original_debuggable), debug) ||
        install("property_get", reinterpret_cast<void*>(HookPropertyGet),
                reinterpret_cast<void**>(&original_property_get), debug);

    if (!context_ok || !debug_ok) {
        bool rollback_ok = true;
        for (const auto& hook : std::initializer_list<HookRegistration>{context, debug}) {
            if (hook.symbol &&
                api->pltHook(main.base, hook.symbol, hook.original, nullptr) != ZN_SUCCESS) {
                rollback_ok = false;
            }
        }
        protocol.Fail(rollback_ok ? sui::adbd::Failure::HookFailure
                                  : sui::adbd::Failure::RollbackFailure);
        Report(rollback_ok ? "hook-install-failed" : "hook-rollback-failed");
        return;
    }

    // Only fully initialized hooks become active.
    if (!protocol.Complete()) {
        Report("initialization-cancelled");
        return;
    }
    Report("initialized");
}

}  // namespace

extern "C" __attribute__((visibility("default"), used)) ZygiskNextModule zn_module = {
    ZYGISK_NEXT_API_VERSION,
    OnModuleLoaded,
};

extern "C" __attribute__((visibility("default"), used)) uint32_t sui_adbd_inject_state() {
    return static_cast<uint32_t>(protocol.GetState());
}

extern "C" __attribute__((visibility("default"), used)) uint32_t sui_adbd_inject_failure() {
    return static_cast<uint32_t>(protocol.GetFailure());
}

extern "C" __attribute__((visibility("default"), used)) uint64_t sui_adbd_inject_attempt_token() {
    return attempt_token;
}

extern "C" __attribute__((visibility("default"), used)) uint64_t sui_adbd_inject_snapshot() {
    return protocol.Snapshot();
}
