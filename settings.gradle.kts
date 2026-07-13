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

import org.apache.tools.ant.DirectoryScanner
import java.util.Properties

pluginManagement {
    repositories {
        maven(url = "https://jitpack.io")
        gradlePluginPortal()
        google()
        mavenCentral()
        mavenLocal()
        maven(url = "https://maven.aliyun.com/repository/gradle-plugin")
        maven(url = "https://maven.aliyun.com/repository/google")
        maven(url = "https://maven.aliyun.com/repository/public")
    }
}

buildscript {
    configurations.classpath {
        resolutionStrategy {
            force("org.bitbucket.b_c:jose4j:0.9.6")
            force("org.jdom:jdom2:2.0.6.1")
            force("org.apache.commons:commons-lang3:3.20.0")
            force("org.bouncycastle:bcpkix-jdk18on:1.85")
            force("org.bouncycastle:bcprov-jdk18on:1.85")
            force("org.bouncycastle:bcutil-jdk18on:1.85")
        }
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        mavenLocal()
        maven(url = "https://maven.aliyun.com/repository/gradle-plugin")
        maven(url = "https://maven.aliyun.com/repository/google")
        maven(url = "https://maven.aliyun.com/repository/public")
    }
}

include(":module", ":ui")

DirectoryScanner.removeDefaultExclude("**/.gitattributes")

val localProperties = Properties()
val localPropertiesFile = file("local.properties")

if (localPropertiesFile.canRead()) {
    localPropertiesFile.inputStream().use(localProperties::load)
}

val apiRoot = if (localProperties.getProperty("api.useLocal") == "true") {
    localProperties.getProperty("api.dir") ?: "api"
} else {
    "api"
}

listOf("aidl", "rish", "shared", "api", "provider", "server-shared").forEach { moduleName ->
    include(":$moduleName")
    project(":$moduleName").projectDir = file("$apiRoot/$moduleName")
}
