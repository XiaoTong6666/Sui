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
 * Copyright (c) 2026 Sui Contributors
 */

#pragma once

#include <atomic>
#include <cstdint>

#include <zygisk_next_api.h>

namespace sui::adbd {

enum class State : uint32_t {
    Unavailable,
    ApiAvailable,
    Loaded,
    Initializing,
    Initialized,
    Failed,
    TimedOut,
    LateLoad,
};

enum class Failure : uint32_t {
    None,
    UnsupportedApi,
    MissingInterface,
    MissingConfiguration,
    MissingExecutable,
    HookFailure,
    RollbackFailure,
    LateInvocation,
    DeadlineExpired,
};

// Per-process state; timeout never authorizes a second backend.
class Protocol final {
   public:
    bool AcceptApi(int requested_version, bool premain) {
        if (requested_version != ZYGISK_NEXT_API_VERSION) {
            Transition(State::Unavailable, State::Failed, Failure::UnsupportedApi);
            return false;
        }
        if (!premain) {
            Transition(State::Unavailable, State::LateLoad, Failure::LateInvocation);
            return false;
        }
        return Transition(State::Unavailable, State::ApiAvailable);
    }

    bool Loaded(bool required_api_present) {
        if (!required_api_present) {
            FailFrom(State::ApiAvailable, Failure::MissingInterface);
            return false;
        }
        return Transition(State::ApiAvailable, State::Loaded);
    }

    bool Begin() {
        return Transition(State::Loaded, State::Initializing);
    }
    bool Complete() {
        return Transition(State::Initializing, State::Initialized);
    }
    bool Fail(Failure reason) {
        return FailFrom(State::Initializing, reason);
    }

    // Timeout does not guarantee that outstanding hooks have stopped.
    bool Timeout() {
        return Transition(State::Initializing, State::TimedOut, Failure::DeadlineExpired);
    }

    uint64_t Snapshot() const {
        return status_.load();
    }
    State GetState() const {
        return static_cast<State>(Snapshot() & 0xffffffffU);
    }
    Failure GetFailure() const {
        return static_cast<Failure>(Snapshot() >> 32);
    }
    bool Active() const {
        return GetState() == State::Initialized;
    }

   private:
    static constexpr uint64_t Pack(State state, Failure reason = Failure::None) {
        return (static_cast<uint64_t>(reason) << 32) | static_cast<uint32_t>(state);
    }

    bool Transition(State from, State to, Failure reason = Failure::None) {
        uint64_t expected = Pack(from);
        return status_.compare_exchange_strong(expected, Pack(to, reason));
    }
    bool FailFrom(State from, Failure reason) {
        return Transition(from, State::Failed, reason);
    }

    std::atomic<uint64_t> status_{Pack(State::Unavailable)};
};

}  // namespace sui::adbd
