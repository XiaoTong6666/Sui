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

import java.util.Properties

val localProperties = Properties()
val localPropertiesFile = rootProject.file("local.properties")

if (localPropertiesFile.canRead()) {
    localPropertiesFile.inputStream().use(localProperties::load)
}

val apiRoot = if (localProperties.getProperty("api.useLocal") == "true") {
    localProperties.getProperty("api.dir") ?: "$rootDir/api"
} else {
    "$rootDir/api"
}

apply(from = "$apiRoot/manifest.gradle.kts")

fun runGitCommand(vararg args: String): String? =
    runCatching {
        val process = ProcessBuilder(*args)
            .directory(rootDir)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText().trim() }
        check(process.waitFor() == 0) { output }
        output
    }.getOrNull()

val gitCommitId = runGitCommand("git", "rev-parse", "--short", "HEAD") ?: "unknown"
val gitCommitCount = runGitCommand("git", "rev-list", "--count", "HEAD")?.toIntOrNull() ?: 1

val apiVersionMajor = extra["api_version_major"].toString()

val moduleLibraryName = "sui"
val moduleId = "zygisk-sui"
val moduleName = "Zygisk - Sui"
val moduleAuthor = "Sui Contributors & XiaoTong"
val moduleDescription = "Fork by XiaoTong.\\nModern superuser interface implementation. This module requires Magisk 24.0+ and Zygisk enabled. DO NOT add SystemUI and Settings to DenyList."
val moduleVersionMinor = 5
val moduleVersionPatch = "4.3"
val moduleUpdateJson = "https://xiaotong6666.github.io/Sui/sui_zygisk.json"
val moduleLocaleFilters = "en,zh,zh-rCN,zh-rTW"

extra["gitCommitId"] = gitCommitId
extra["gitCommitCount"] = gitCommitCount
extra["moduleLibraryName"] = moduleLibraryName
extra["moduleId"] = moduleId
extra["moduleName"] = moduleName
extra["moduleAuthor"] = moduleAuthor
extra["moduleDescription"] = moduleDescription
extra["moduleVersionMinor"] = moduleVersionMinor
extra["moduleVersionPatch"] = moduleVersionPatch
extra["moduleVersion"] = "v${apiVersionMajor}.${moduleVersionMinor}.${moduleVersionPatch}"
extra["moduleVersionCode"] = gitCommitCount
extra["moduleUpdateJson"] = moduleUpdateJson
extra["moduleLocaleFilters"] = moduleLocaleFilters
