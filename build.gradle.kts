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
import com.android.build.api.dsl.ApplicationExtension
import com.android.build.api.dsl.LibraryExtension
import java.util.Properties

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
    idea
    alias(libs.plugins.spotless)
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.refine) apply false
}

val forcedDependencies = listOf(
    "org.bitbucket.b_c:jose4j:0.9.6",            // Fix CVE-2024-29371
    "org.jdom:jdom2:2.0.6.1",                    // Fix CVE-2021-33813
    "org.apache.commons:commons-lang3:3.20.0",  // Fix CVE-2025-48924
    "org.bouncycastle:bcpkix-jdk18on:1.85",     // Fix GHSA-8xfc-gm6g-vgpv via AGP classpath
    "org.bouncycastle:bcprov-jdk18on:1.85",
    "org.bouncycastle:bcutil-jdk18on:1.85"
)

fun propertyString(name: String): String = providers.gradleProperty(name).get()
fun propertyInt(name: String): Int = propertyString(name).toInt()

fun ApplicationExtension.configureAndroidAppDefaults() {
    compileSdk = androidCompileSdk
    buildToolsVersion = androidBuildToolsVersion
    ndkVersion = androidNdkVersion

    defaultConfig {
        minSdk = 23
        targetSdk = androidTargetSdk
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        aidl = true
    }
}

fun LibraryExtension.configureAndroidLibraryDefaults() {
    compileSdk = androidCompileSdk
    buildToolsVersion = androidBuildToolsVersion
    ndkVersion = androidNdkVersion

    defaultConfig {
        minSdk = 23
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    buildFeatures {
        aidl = true
    }
}

allprojects {
    configurations.configureEach {
        resolutionStrategy {
            forcedDependencies.forEach { force(it) }
        }
    }
}

val androidCompileSdk = propertyInt("android.compileSdk")
val androidTargetSdk = propertyInt("android.targetSdk")
val androidBuildToolsVersion = propertyString("android.buildToolsVersion")
val androidNdkVersion = propertyString("android.ndkVersion")

idea {
    module {
        excludeDirs = excludeDirs + file("out")
        resourceDirs = resourceDirs + file("template") + file("scripts")
    }
}

subprojects {
    plugins.withId("com.android.application") {
        extensions.configure<ApplicationExtension>("android") {
            configureAndroidAppDefaults()
        }
    }

    plugins.withId("com.android.library") {
        extensions.configure<LibraryExtension>("android") {
            configureAndroidLibraryDefaults()
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.compilerArgs.add("-Xlint:deprecation")
    }
}

spotless {
    lineEndings = com.diffplug.spotless.LineEnding.UNIX

    java {
        target("**/src/*/java/**/*.java")
        targetExclude("**/build/**")
        palantirJavaFormat()
        importOrder()
        removeUnusedImports()
        formatAnnotations()
    }

    kotlin {
        target("**/src/*/kotlin/**/*.kt", "**/src/*/java/**/*.kt")
        targetExclude("**/build/**")
        ktlint().editorConfigOverride(mapOf(
            "ktlint_standard_max-line-length" to "disabled"
        ))
    }
    format("cpp") {
        target("**/src/main/cpp/**/*.c", "**/src/main/cpp/**/*.cpp", "**/src/main/cpp/**/*.h", "**/src/main/cpp/**/*.hpp")
        targetExclude("**/build/**")

        val localProperties = Properties()
        val localPropertiesFile = rootProject.file("local.properties")
        if (localPropertiesFile.exists()) {
            localPropertiesFile.inputStream().use { localProperties.load(it) }
        }

        var sdkDir = localProperties.getProperty("sdk.dir")
            ?: System.getenv("ANDROID_HOME")
            ?: System.getenv("ANDROID_SDK_ROOT")

        if (sdkDir.isNullOrEmpty()) {
            val commonPaths = listOf("/opt/android-sdk", "/usr/local/lib/android/sdk")
            sdkDir = commonPaths.firstOrNull { file(it).exists() } ?: ""
        }

        val osName = System.getProperty("os.name").lowercase()
        val platform = when {
            "linux" in osName -> "linux-x86_64"
            "mac" in osName -> "darwin-x86_64"
            else -> "windows-x86_64"
        }

        var clangPath = "$sdkDir/ndk/$androidNdkVersion/toolchains/llvm/prebuilt/$platform/bin/clang-format"
        if ("windows" in osName) clangPath += ".exe"

        if (file(clangPath).exists()) {
            clangFormat("21.0.0").style("file").pathToExe(clangPath)
        } else {
            println("Spotless Warning: Clang-format not found at $clangPath")
            clangFormat().style("file")
        }
    }
}

tasks.register("format") {
    dependsOn("spotlessApply")
    group = "formatting"
    description = "Formats the code using Spotless"
}
