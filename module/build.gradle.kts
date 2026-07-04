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

import org.apache.tools.ant.filters.FixCrLfFilter
import java.io.File
import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.refine)
}

apply(from = "$rootDir/module.gradle.kts")

val gitCommitCount = extra["gitCommitCount"] as Int
val moduleVersion = extra["moduleVersion"] as String
val moduleId = extra["moduleId"] as String
val moduleVersionCode = extra["moduleVersionCode"] as Int
val gitCommitId = extra["gitCommitId"] as String
val moduleName = extra["moduleName"] as String
val moduleAuthor = extra["moduleAuthor"] as String
val moduleDescription = extra["moduleDescription"] as String
val moduleUpdateJson = extra["moduleUpdateJson"] as String
val uiProject = project(":ui")
val outDir = rootProject.file("out")
val magiskTemplateDir = rootProject.file("template/magisk_module")
val modulePropValues = mapOf(
    "id" to moduleId,
    "name" to moduleName,
    "author" to moduleAuthor,
    "description" to moduleDescription,
    "updateJson" to moduleUpdateJson
)

fun String.capitalized(): String = replaceFirstChar { char ->
    if (char.isLowerCase()) char.titlecase() else char.toString()
}

fun sha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val bytesRead = input.read(buffer)
            if (bytesRead < 0) break
            digest.update(buffer, 0, bytesRead)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

android {
    namespace = "rikka.sui"
    defaultConfig {
        minSdk = 23
        versionCode = gitCommitCount
        versionName = moduleVersion.substring(1)
        externalNativeBuild {
            cmake {
                arguments += listOf("-DZYGISK_MODULE_ID:STRING=\"$moduleId\"", "-DANDROID_STL=none")
            }
        }
    }
    buildFeatures {
        viewBinding = true
        prefab = true
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.31.0+"
        }
    }
    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            ndk {
                debugSymbolLevel = "SYMBOL_TABLE"
            }
        }
    }
    lint {
        checkReleaseBuilds = false
    }
    dependenciesInfo {
        includeInApk = false
    }
}

dependencies {
    implementation(libs.refine.runtime)

    implementation(libs.libcxx)
    implementation(libs.nativehelper)
    implementation(libs.parcelablelist)

    implementation(libs.androidx.annotation)
    implementation(libs.androidx.core)

    implementation(project(":aidl"))
    implementation(project(":shared"))
    implementation(project(":api"))
    implementation(project(":rish"))
    implementation(project(":server-shared"))

    implementation(libs.hidden.compat)
    compileOnly(libs.hidden.stub)
}

androidComponents {
    onVariants(selector().all()) { variant ->
        val variantCapped = variant.name.capitalized()
        val variantLowered = variant.name.lowercase()
        val buildType = requireNotNull(variant.buildType) { "Variant ${variant.name} is missing buildType" }
        val buildTypeCapped = buildType.capitalized()
        val buildTypeLowered = buildType.lowercase()

        val buildMetadata = "${moduleVersionCode}-${gitCommitId}-${buildTypeLowered}"
        val zipName = "Sui-${moduleVersion}_${buildMetadata}.zip"
        val magiskDir = file("$outDir/${buildTypeLowered}")
        val dexDir = if (buildTypeLowered == "release") {
            layout.buildDirectory.dir("intermediates/dex/${variantLowered}/minify${variantCapped}WithR8")
        } else {
            layout.buildDirectory.dir("intermediates/dex/${variantLowered}/mergeDex$variantCapped")
        }
        val strippedLibsDir = layout.buildDirectory.dir(
            "intermediates/stripped_native_libs/${variantLowered}/strip${variantCapped}DebugSymbols/out/lib"
        )
        val uiApkDir = uiProject.layout.buildDirectory.dir("outputs/apk/$buildTypeLowered")

        tasks.register<Sync>("prepareMagiskFiles${variantCapped}") {
            into(magiskDir)
            from(magiskTemplateDir) {
                exclude("module.prop", "action.sh")
            }
            from(magiskTemplateDir) {
                include("module.prop")
                expand(
                    modulePropValues + mapOf(
                        "version" to "${moduleVersion} (${buildMetadata})",
                        "versionCode" to moduleVersionCode.toString()
                    )
                )
                filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
            }
            from(magiskTemplateDir) {
                include("action.sh")
                filter<FixCrLfFilter>("eol" to FixCrLfFilter.CrLf.newInstance("lf"))
            }
            from(dexDir) {
                include("classes.dex")
                rename { "sui.dex" }
            }
            from(strippedLibsDir) {
                into("lib")
            }
            from(uiApkDir) {
                exclude("output-metadata.json")
                rename { "sui.apk" }
            }
            doLast {
                fileTree(magiskDir)
                    .files
                    .asSequence()
                    .filterNot { it.name == ".gitattributes" }
                    .forEach { file ->
                        file("${file.path}.sha256").writeText(sha256(file))
                    }
            }
        }

        tasks.register<Zip>("zip${variantCapped}") {
            dependsOn("prepareMagiskFiles${variantCapped}")
            from(magiskDir)
            archiveFileName.set(zipName)
            destinationDirectory.set(outDir)
        }

        tasks.register<Exec>("push${variantCapped}") {
            workingDir = outDir
            commandLine("adb", "push", zipName, "/data/local/tmp/")
        }

        tasks.register<Exec>("flash${variantCapped}") {
            dependsOn("push${variantCapped}")
            commandLine("adb", "shell", "su", "-c", "magisk --install-module /data/local/tmp/${zipName}")
        }

        tasks.register<Exec>("flashWithKsud${variantCapped}") {
            dependsOn("push${variantCapped}")
            commandLine("adb", "shell", "su", "-c", "ksud module install /data/local/tmp/${zipName}")
        }

        tasks.register<Exec>("flashAndReboot${variantCapped}") {
            dependsOn("flash${variantCapped}")
            commandLine("adb", "shell", "reboot")
            isIgnoreExitValue = true
        }

        tasks.register<Exec>("flashWithKsudAndReboot${variantCapped}") {
            dependsOn("flashWithKsud${variantCapped}")
            commandLine("adb", "shell", "reboot")
            isIgnoreExitValue = true
        }
    }
}

afterEvaluate {
    listOf("Debug", "Release").forEach { buildType ->
        tasks.named("pre${buildType}Build").configure {
            dependsOn(":ui:assemble${buildType}")
        }

        tasks.named("prepareMagiskFiles${buildType}").configure {
            dependsOn("assemble${buildType}")
        }

        tasks.named("assemble${buildType}").configure {
            finalizedBy("zip${buildType}")
        }

        tasks.named("push${buildType}").configure {
            dependsOn("assemble${buildType}")
        }
    }
}
