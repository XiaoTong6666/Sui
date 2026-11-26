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

#include <string>

namespace sui::legacy {

bool CreateDexRuntime(std::string& dex_path, std::string& oat_dir);
void PruneStaleDexRuntimes(bool include_current = false);

}  // namespace sui::legacy
