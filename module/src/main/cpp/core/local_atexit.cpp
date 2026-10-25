/*
 * Copyright (C) 2020 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Based on https://github.com/5ec1cff/local_cxa_atexit_finalize_impl
#include <pthread.h>

#include <cstdlib>
#include <limits>

namespace {

struct AtexitEntry {
    void (*fn)(void*);
    void* arg;
    void* dso;
};

AtexitEntry* gEntries = nullptr;
size_t gCount = 0;
size_t gCapacity = 0;
pthread_mutex_t gMutex = PTHREAD_MUTEX_INITIALIZER;

extern "C" [[gnu::used]] int __cxa_atexit(void (*fn)(void*), void* arg, void* dso) {
    if (fn == nullptr) {
        return -1;
    }

    pthread_mutex_lock(&gMutex);
    if (gCount == gCapacity) {
        constexpr size_t kMaxEntries = std::numeric_limits<size_t>::max() / sizeof(AtexitEntry);
        if (gCapacity >= kMaxEntries) {
            pthread_mutex_unlock(&gMutex);
            return -1;
        }
        const size_t nextCapacity =
            gCapacity == 0 ? 8 : (gCapacity > kMaxEntries / 2 ? kMaxEntries : gCapacity * 2);
        void* next = realloc(gEntries, nextCapacity * sizeof(AtexitEntry));
        if (next == nullptr) {
            pthread_mutex_unlock(&gMutex);
            return -1;
        }
        gEntries = static_cast<AtexitEntry*>(next);
        gCapacity = nextCapacity;
    }
    gEntries[gCount++] = {fn, arg, dso};
    pthread_mutex_unlock(&gMutex);
    return 0;
}

extern "C" [[gnu::used]] void __cxa_finalize(void* dso) {
    for (;;) {
        pthread_mutex_lock(&gMutex);
        AtexitEntry entry{};
        for (size_t i = gCount; i != 0; --i) {
            if (gEntries[i - 1].fn != nullptr && (dso == nullptr || gEntries[i - 1].dso == dso)) {
                entry = gEntries[i - 1];
                gEntries[i - 1].fn = nullptr;
                break;
            }
        }
        if (entry.fn == nullptr) {
            bool hasPending = false;
            for (size_t i = 0; i < gCount; ++i) {
                if (gEntries[i].fn != nullptr) {
                    hasPending = true;
                    break;
                }
            }
            if (!hasPending) {
                free(gEntries);
                gEntries = nullptr;
                gCount = 0;
                gCapacity = 0;
            }
            pthread_mutex_unlock(&gMutex);
            return;
        }

        pthread_mutex_unlock(&gMutex);
        entry.fn(entry.arg);
    }
}

}  // namespace
