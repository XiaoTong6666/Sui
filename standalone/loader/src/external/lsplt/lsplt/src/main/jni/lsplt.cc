#include "include/lsplt.hpp"

#include <sys/mman.h>
#include <sys/sysmacros.h>

#include <array>
#include <cinttypes>
#include <list>
#include <map>
#include <mutex>
#include <vector>

#include "elf_util.hpp"
#include "logging.hpp"
#include "syscall.hpp"

namespace {

inline auto PageStart(uintptr_t addr) {
    const uintptr_t page_size = getpagesize();
    return reinterpret_cast<char *>(addr / page_size * page_size);
}

inline auto PageEnd(uintptr_t addr) {
    const uintptr_t page_size = getpagesize();
    return reinterpret_cast<char *>(reinterpret_cast<uintptr_t>(PageStart(addr)) + page_size);
}

/*
 * =======================================================================================
 *                            High-Level Data Flow Diagram
 * =======================================================================================
 *
 * This diagram shows the journey from a user's hook request to the final state
 * managed by the global 'hook_info' object.
 *
 *
 *  +-----------------------------+
 *  | 1. User's Hook Requests     |
 *  | (std::vector<HookRequest>) |
 *  |                             |
 *  | [dev, inode, "read",  cb1]  |
 *  | [dev, inode, "write", cb2]  |
 *  +-------------+---------------+
 *                |
 *                |
 *                v
 *  +-------------+---------------+      +--------------------------------+
 *  | 2. CommitHook()             |      | /proc/self/maps                |
 *  |                             +<-----+ (Scanned to find loaded libs)  |
 *  |   - ScanHookInfo()          |      +--------------------------------+
 *  |   - Filter()                |
 *  |   - Merge()                 |
 *  |   - DoHook()                |
 *  +-------------+---------------+
 *                |
 *                |
 *                v
 *  +---------------------------------------------------------------------------------+
 *  | 3. Global State: 'hook_info' (HookInfos -> std::map<start_addr, HookInfo>)      |
 *  |                                                                                 |
 *  |  Key (start_addr)     Value (HookInfo Object)                                   |
 *  | +------------------+----------------------------------------------------------+ |
 *  | | 0x7f... (libc)   | HookInfo for libc (Contains active hook details)         | |
 *  | +------------------+----------------------------------------------------------+ |
 *  | | 0x7f... (ld.so)  | HookInfo for ld.so (No matching hooks, may be empty)     | |
 *  | +------------------+----------------------------------------------------------+ |
 *  | | ...              | ...                                                      | |
 *  | +------------------+----------------------------------------------------------+ |
 *  +---------------------------------------------------------------------------------+
 *
 */

struct HookRequest {
    dev_t dev;
    ino_t inode;
    std::pair<uintptr_t, uintptr_t> offset_range;
    std::string symbol;
    void *callback;
    void **backup;
};

/*
 * =======================================================================================
 *               Detailed `HookInfo` Structure Diagram (Focus on 'backup')
 * =======================================================================================
 *
 * This shows the contents of a single `HookInfo` object for a library (e.g., libc.so.6)
 * where one or more hooks are active. The 'backup' field is central to this state.
 *
 *
 *  HookInfo for libc.so.6 (Address: 0x7fABC000)
 * +--------------------------------------------------------------------+
 * |                                                                    |
 * |  //-- MapInfo fields --//                                          |
 * |  path:  "/usr/lib/libc.so.6"                                       |
 * |  inode: 12345                                                      |
 * |  ...                                                               |
 * |                                                                    |
 * |  //-- Hooking State --//                                           |
 * |                                                                    |
 * |  elf:  std::unique_ptr<Elf> (points to parsed ELF data)            |
 * |                                                                    |
 * |  backup: 0xBAADF00D ---------------------------------------------+ |
 * |       ^                                                            |
 * |       |---- (See full explanation of its roles below) -----------+ |
 * |                                                                    |
 * |  hooks: std::map<uintptr_t, uintptr_t>                             |
 * |        (A record of every active hook in this library)             |
 * |        +-----------------------------+---------------------------+ |
 * |        | Key (Address of PLT entry)  | Value (Original Func Ptr) | |
 * |        +-----------------------------+---------------------------+ |
 * |        | 0x7fABC100 (plt for "read") | 0x7fDEF100 (real_read)    | |
 * |        +-----------------------------+---------------------------+ |
 * |        | 0x7fABC240 (plt for "write")| 0x7fDEF200 (real_write)   | |
 * |        +-----------------------------+---------------------------+ |
 * |                                                                    |
 * +--------------------------------------------------------------------+
 *
 *
 * =======================================================================================
 *                   The Three Critical Roles of the `backup` Field
 * =======================================================================================
 *
 * The `backup` field is more than just a pointer; it's a state machine that governs the
 * entire lifecycle of a hooked library.
 *
 * 1. IT ACTS AS A STATE FLAG:
 *    - If `backup == 0`, it means this library is NOT hooked. The memory at its original
 *      address is the pristine, read-only version from the file on disk.
 *    - If `backup != 0`, it means the library IS actively hooked. It tells us:
 *        a) A writable, private copy of the library now exists at the original address.
 *        b) The pristine, original, read-only memory has been moved to the address
 *           stored in the `backup` field.
 *
 * 2. IT IS THE SOURCE FOR THE FINAL RESTORATION:
 *    - This is its most important role. When the VERY LAST hook is removed from this
 *      library, the `hooks` map becomes empty.
 *    - This emptiness triggers a final `sys_mremap` call that MOVES the pristine memory
 *      segment from the `backup` address BACK to the library's original address.
 *    - This atomically and efficiently restores the library to its exact pre-hook state,
 *      destroying the writable copy and cleaning up all modifications.
 *
 * 3. IT IS THE SOURCE FOR THE INITIAL COPY:
 *    - When the first hook is applied, the kernel first moves the original memory to the
 *      `backup` address.
 *    - The code then immediately `memcpy`s the content FROM this `backup` location TO the
 *      newly created writable mapping at the original address. This populates our
 *      writable "sandbox" with the library's original code.
 *
 */

struct HookInfo : public lsplt::MapInfo {
    std::map<uintptr_t, uintptr_t> hooks;
    uintptr_t backup;
    std::unique_ptr<Elf> elf;
    bool self;
    [[nodiscard]] bool Match(const HookRequest &info) const {
        return info.dev == dev && info.inode == inode && offset >= info.offset_range.first &&
               offset < info.offset_range.second;
    }
};

class HookInfos : public std::map<uintptr_t, HookInfo, std::greater<>> {
public:
    static auto CreateTargetsFromMemoryMaps(std::vector<lsplt::MapInfo> maps) {
        static ino_t kSelfInode = 0;
        static dev_t kSelfDev = 0;
        HookInfos info;
        if (kSelfInode == 0) {
            auto self = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
            for (auto &map : maps) {
                if (self >= map.start && self < map.end) {
                    kSelfInode = map.inode;
                    kSelfDev = map.dev;
                    LOGV("self inode = %lu", kSelfInode);
                    break;
                }
            }
        }
        for (auto &map : maps) {
            // we basically only care about r-?p entry
            // and for offset == 0 it's an ELF header
            // and for offset != 0 it's what we hook
            // both of them should not be xom
            if (!map.is_private || !(map.perms & PROT_READ) || map.path.empty() ||
                map.path[0] == '[') {
                continue;
            }
            auto start = map.start;
            const bool self = map.inode == kSelfInode && map.dev == kSelfDev;
            info.emplace(start, HookInfo{{std::move(map)}, {}, 0, nullptr, self});
        }
        return info;
    }

    // filter out ignored
    void Filter(const std::vector<HookRequest> &register_info) {
        for (auto iter = begin(); iter != end();) {
            const auto &info = iter->second;
            bool matched = false;
            for (const auto &reg : register_info) {
                if (info.Match(reg)) {
                    matched = true;
                    break;
                }
            }
            if (matched) {
                LOGV("match hook info %s:%lu %" PRIxPTR " %" PRIxPTR "-%" PRIxPTR,
                     iter->second.path.data(), iter->second.inode, iter->second.start,
                     iter->second.end, iter->second.offset);
                ++iter;
            } else {
                iter = erase(iter);
            }
        }
    }

    void Merge(HookInfos &old) {
        // merge with old map info
        if (old.size() == 0) return;
        for (auto &info : old) {
            if (info.second.backup) {
                erase(info.second.backup);
            }
            if (auto iter = find(info.first); iter != end()) {
                iter->second = std::move(info.second);
            } else if (info.second.backup) {
                emplace(info.first, std::move(info.second));
            }
        }
    }

    /**
     * =======================================================================================
     *                      Memory Remapping and Hooking Mechanism
     * =======================================================================================
     *
     * The following diagram illustrates the state of a process's address space before
     * and after hooking an PLT entry.
     *
     *
     * A) BEFORE HOOKING
     * -----------------
     * The library exists as a single, read-only, file-backed mapping.
     *
     *    Address Space
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *  | 0x7f1000         | <-- Original R/O mapping of libc.so
     *  |  .text, .got.plt |
     *  |  [PLT for 'read']| --> Points to original 'read' implementation.
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *
     *
     * B) AFTER HOOKING
     * ----------------
     * The memory layout is rearranged into two distinct segments.
     *
     *    Address Space
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *  | 0x7f1000         | <-- (3) New R/W private anonymous mapping.
     *  |  .text, .got.plt |     This is a mutable copy of the original.
     *  |  [PLT for 'read']| --> OVERWRITTEN to point to our callback function.
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *  | 0xBAADF00D       | <-- (1) Original mapping, moved here via mremap.
     *  |  (Backup Address)|     It remains an unmodified, R/O program image.
     *  |  [PLT for 'read']| --> Still points to original 'read'.
     *  +------------------+
     *  | ...              |
     *  +------------------+
     *
     *
     * Sequence of Operations (Referenced in Diagram B):
     * -------------------------------------------------
     * 1. MREMAP: The original, file-backed memory segment at `0x7f1000` is atomically
     *    moved to a new, kernel-selected address (`0xBAADF00D`). This becomes the backup.
     *    The `HookInfo.backup` field records this new address.
     *
     * 2. MMAP & MEMCPY: A new, writable, private anonymous mapping is created at the
     *    original address (`0x7f1000`). Its contents are immediately populated by copying
     *    the data from the backup segment.
     *
     * 3. OVERWRITE: With a writable copy now in place, the PLT entry for the target
     *    symbol ('read') is safely overwritten with the address of the user's callback.
     *
     * Restoration:
     * ------------
     * When the last hook is removed, this process is efficiently reversed. A single
     * `sys_mremap` call moves the unmodified backup segment from `0xBAADF00D` back to
     * `0x7f1000`, completely discarding the modified, anonymous copy and restoring the
     * process's memory to its original state.
     *
     */

    bool PatchPLTEntry(uintptr_t addr, uintptr_t callback, uintptr_t *backup) {
        LOGV("hooking %p", reinterpret_cast<void *>(addr));
        auto iter = lower_bound(addr);
        if (iter == end()) return false;
        // iter.first < addr
        auto &info = iter->second;
        if (info.end <= addr) return false;
        const auto len = info.end - info.start;
        if (!info.backup && !info.self) {
            // let os find a suitable address
            auto *backup_addr = sys_mmap(nullptr, len, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
            LOGD("backup %p to %p", reinterpret_cast<void *>(addr), backup_addr);
            if (backup_addr == MAP_FAILED) return false;
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE | MREMAP_DONTUNMAP, backup_addr);
                new_addr == MAP_FAILED || new_addr != backup_addr) {
                new_addr = sys_mremap(reinterpret_cast<void *>(info.start), len, len,
                                      MREMAP_FIXED | MREMAP_MAYMOVE, backup_addr);
                if (new_addr == MAP_FAILED || new_addr != backup_addr) {
                    return false;
                }
                LOGD("backup with MREMAP_DONTUNMAP failed, tried without it");
            }
            if (auto *new_addr = sys_mmap(reinterpret_cast<void *>(info.start), len,
                                          PROT_READ | PROT_WRITE | info.perms,
                                          MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
                new_addr == MAP_FAILED) {
                return false;
            }
            const uintptr_t page_size = getpagesize();
            for (uintptr_t src = reinterpret_cast<uintptr_t>(backup_addr), dest = info.start,
                           end = info.start + len;
                 dest < end; src += page_size, dest += page_size) {
                memcpy(reinterpret_cast<void *>(dest), reinterpret_cast<void *>(src), page_size);
            }
            info.backup = reinterpret_cast<uintptr_t>(backup_addr);
        }
        if (info.self) {
            // self hooking, no need backup since we are always dirty
            if (!(info.perms & PROT_WRITE)) {
                info.perms |= PROT_WRITE;
                mprotect(reinterpret_cast<void *>(info.start), len, info.perms);
            }
        }
        auto *the_addr = reinterpret_cast<uintptr_t *>(addr);
        auto the_backup = *the_addr;
        if (*the_addr != callback) {
            *the_addr = callback;
            if (backup) *backup = the_backup;
            __builtin___clear_cache(PageStart(addr), PageEnd(addr));
        }
        if (auto hook_iter = info.hooks.find(addr); hook_iter != info.hooks.end()) {
            if (hook_iter->second == callback) info.hooks.erase(hook_iter);
        } else {
            info.hooks.emplace(addr, the_backup);
        }
        if (info.hooks.empty() && !info.self) {
            LOGV("restore %p from %p", reinterpret_cast<void *>(info.start),
                 reinterpret_cast<void *>(info.backup));
            // Note that we have to always use sys_mremap here, see
            // https://cs.android.com/android/_/android/platform/bionic/+/4200e260d266fd0c176e71fbd720d0bab04b02db
            if (auto *new_addr =
                    sys_mremap(reinterpret_cast<void *>(info.backup), len, len,
                               MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                return false;
            }
            info.backup = 0;
        }
        return true;
    }

    /**
     * ------------------------------------------------------------------
     *                    Direct Hook Restoration Logic
     * ------------------------------------------------------------------
     * This block handles the restoration of a previously applied hook.
     * It operates under the efficient assumption that a corresponding
     * hook is already active within this `HookInfo`'s cache.
     *
     * The strategy is as follows:
     *
     * 1. IDENTIFY THE HOOK FROM CACHE: We iterate through the `info.hooks` map.
     *    This map's `key` is the memory address of the hooked PLT entry,
     *    and its `value` is the original function pointer we saved.
     *
     * 2. IDENTIFICATION CRITERION: A hook is identified as the correct one
     *    to restore if the original function address (the value) matches the
     *    `callback` pointer from the user's restore request (`reg.callback`).
     *
     * 3. RESTORE VIA DoHook: Once the match is found, we call the low-level
     *    `DoHook` function, passing the following parameters:
     *      - 1st arg: `hooked_addr` (the destination PLT entry address)
     *      - 2nd arg: `original_addr` (the source value from our cache)
     *    This writes the original function pointer back, undoing the hook.
     */
    bool RestoreFunction(std::vector<HookRequest> &register_info) {
        LOGV("restoring %zu functions", register_info.size());
        bool res = true;
        for (auto iter = register_info.begin(); iter != register_info.end();) {
            const auto &reg = *iter;
            bool restored = false;
            for (auto info_iter = rbegin(); info_iter != rend(); ++info_iter) {
                auto &info = info_iter->second;
                if (info.hooks.size() == 0 || info.dev != reg.dev || info.inode != reg.inode) {
                    continue;
                }
                for (const auto &[hooked_addr, original_addr] : info.hooks) {
                    // The `hooked_addr` is the Key: the address of the PLT entry.
                    // The `original_addr` is the Value: the original function ptr we backed up.
                    if (original_addr == reinterpret_cast<uintptr_t>(reg.callback)) {
                        LOGV("found matching hook for symbol [%s] at address %p.",
                             reg.symbol.c_str(), reinterpret_cast<void *>(hooked_addr));
                        restored = PatchPLTEntry(hooked_addr, original_addr, nullptr);
                        res = restored && res;
                        break;
                    }
                }
            }

            if (!restored) {
                LOGW("no matched hook found to restore function [%s]", reg.symbol.c_str());
                ++iter;
            } else {
                iter = register_info.erase(iter);
            }
        }
        if (!res) {
            LOGV("fallback to address searching for %zu functions not restored",
                 register_info.size());
        }
        return res;
    }

    bool ProcessRequest(std::vector<HookRequest> &register_info) {
        bool res = true;
        for (auto info_iter = rbegin(); info_iter != rend(); ++info_iter) {
            auto &info = info_iter->second;
            for (auto iter = register_info.begin(); iter != register_info.end();) {
                const auto &reg = *iter;
                if (info.offset != iter->offset_range.first || !info.Match(reg)) {
                    ++iter;
                    continue;
                }

                if (!info.elf) info.elf = std::make_unique<Elf>(info.start);
                if (info.elf && info.elf->Valid()) {
                    LOGV("finding symbol %s", iter->symbol.data());
                    auto possible_addr = info.elf->FindPltAddr(reg.symbol);
                    if (possible_addr.size() == 0) {
                        LOGW("symbol %s not found in PLT table", iter->symbol.data());
                        res = false;
                    } else {
                        LOGV("patching PLT entry for %s", iter->symbol.data());
                        for (auto addr : possible_addr) {
                            res = PatchPLTEntry(addr, reinterpret_cast<uintptr_t>(reg.callback),
                                                reinterpret_cast<uintptr_t *>(reg.backup)) &&
                                  res;
                        }
                    }
                }
                iter = register_info.erase(iter);
            }
        }
        return res;
    }

    bool CleanupAllHooks() {
        bool res = true;
        for (auto &[_, info] : *this) {
            if (!info.backup) continue;
            for (auto &[addr, backup] : info.hooks) {
                // store new address to backup since we don't need backup
                backup = *reinterpret_cast<uintptr_t *>(addr);
            }
            auto len = info.end - info.start;
            if (auto *new_addr =
                    mremap(reinterpret_cast<void *>(info.backup), len, len,
                           MREMAP_FIXED | MREMAP_MAYMOVE, reinterpret_cast<void *>(info.start));
                new_addr == MAP_FAILED || reinterpret_cast<uintptr_t>(new_addr) != info.start) {
                res = false;
                info.hooks.clear();
                continue;
            }
            if (!mprotect(PageStart(info.start), len, PROT_WRITE)) {
                for (auto &[addr, backup] : info.hooks) {
                    *reinterpret_cast<uintptr_t *>(addr) = backup;
                }
                mprotect(PageStart(info.start), len, info.perms);
            }
            info.hooks.clear();
            info.backup = 0;
        }
        return res;
    }
};

std::mutex g_hook_state_mutex;
std::vector<HookRequest> g_pending_hooks = {};
HookInfos g_global_hook_state;
}  // namespace

namespace lsplt::inline v2 {
[[maybe_unused]] std::vector<MapInfo> MapInfo::Scan(std::string_view pid) {
    constexpr static auto kPermLength = 5;
    constexpr static auto kMapEntry = 7;
    std::vector<MapInfo> info;
    auto path = "/proc/" + std::string{pid} + "/maps";
    auto maps = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "r"), &fclose};
    if (maps) {
        char *line = nullptr;
        size_t len = 0;
        ssize_t read;
        while ((read = getline(&line, &len, maps.get())) > 0) {
            line[read - 1] = '\0';
            uintptr_t start = 0;
            uintptr_t end = 0;
            uintptr_t off = 0;
            ino_t inode = 0;
            unsigned int dev_major = 0;
            unsigned int dev_minor = 0;
            std::array<char, kPermLength> perm{'\0'};
            int path_off;
            if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %4s %" PRIxPTR " %x:%x %lu %n%*s", &start,
                       &end, perm.data(), &off, &dev_major, &dev_minor, &inode,
                       &path_off) != kMapEntry) {
                continue;
            }
            while (path_off < read && isspace(line[path_off])) path_off++;
            auto &ref = info.emplace_back(start, end, 0, perm[3] == 'p', off,
                                          static_cast<dev_t>(makedev(dev_major, dev_minor)), inode,
                                          line + path_off);
            if (perm[0] == 'r') ref.perms |= PROT_READ;
            if (perm[1] == 'w') ref.perms |= PROT_WRITE;
            if (perm[2] == 'x') ref.perms |= PROT_EXEC;
        }
        free(line);
    }
    return info;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, std::string_view symbol, void *callback,
                                   void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(g_hook_state_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    [[maybe_unused]] const auto &info = g_pending_hooks.emplace_back(
        dev, inode,
        std::pair{std::numeric_limits<uintptr_t>::min(), std::numeric_limits<uintptr_t>::max()},
        std::string{symbol}, callback, backup);

    LOGV("RegisterHook %lu %s", info.inode, info.symbol.data());
    return true;
}

[[maybe_unused]] bool RegisterHook(dev_t dev, ino_t inode, uintptr_t offset, size_t size,
                                   std::string_view symbol, void *callback, void **backup) {
    if (dev == 0 || inode == 0 || symbol.empty() || !callback) return false;

    const std::unique_lock lock(g_hook_state_mutex);
    static_assert(std::numeric_limits<uintptr_t>::min() == 0);
    static_assert(std::numeric_limits<uintptr_t>::max() == -1);
    [[maybe_unused]] const auto &info = g_pending_hooks.emplace_back(
        dev, inode, std::pair{offset, offset + size}, std::string{symbol}, callback, backup);

    LOGV("RegisterHook %lu %" PRIxPTR "-%" PRIxPTR " %s", info.inode, info.offset_range.first,
         info.offset_range.second, info.symbol.data());
    return true;
}

[[maybe_unused]] bool CommitHook(std::vector<lsplt::MapInfo> &maps, bool unhook) {
    const std::unique_lock lock(g_hook_state_mutex);
    if (g_pending_hooks.empty()) return true;

    auto new_hook_state = HookInfos::CreateTargetsFromMemoryMaps(maps);
    if (new_hook_state.empty()) return false;

    new_hook_state.Filter(g_pending_hooks);

    new_hook_state.Merge(g_global_hook_state);
    // update to new map info
    g_global_hook_state = std::move(new_hook_state);

    if (unhook && g_global_hook_state.RestoreFunction(g_pending_hooks)) {
        return true;
    }
    return g_global_hook_state.ProcessRequest(g_pending_hooks);
}

[[maybe_unused]] bool CommitHook() {
    auto maps = MapInfo::Scan();
    return CommitHook(maps);
}

[[gnu::destructor]] [[maybe_unused]] bool InvalidateBackup() {
    const std::unique_lock lock(g_hook_state_mutex);
    return g_global_hook_state.CleanupAllHooks();
}
}  // namespace lsplt::inline v2
