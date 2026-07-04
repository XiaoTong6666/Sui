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
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.refine)
}

apply(from = "$rootDir/module.gradle.kts")

val gitCommitCount = extra["gitCommitCount"] as Int
val moduleVersion = extra["moduleVersion"] as String
val moduleLocaleFilters = (extra["moduleLocaleFilters"] as String)
    .split(',')
    .map(String::trim)
    .filter(String::isNotEmpty)

android {
    namespace = "rikka.sui"

    defaultConfig {
        minSdk = 23
        versionCode = gitCommitCount
        versionName = moduleVersion.substring(1)
        vectorDrawables.useSupportLibrary = true
    }

    androidResources {
        localeFilters += moduleLocaleFilters
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    packaging {
        resources {
            excludes += listOf(
                "/META-INF/*.version",
                "/META-INF/*.kotlin_module",
                "/kotlin/**",
                "**.bin"
            )
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
    implementation(libs.smart.refresh.kernel)
    implementation(libs.smart.refresh.header.material)
    implementation(libs.smart.refresh.header.classics)
    compileOnly(libs.support.annotations)

    implementation(libs.refine.runtime)

    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.coroutines.android)

    implementation(project(":aidl"))
    implementation(project(":api"))
    compileOnly(libs.hidden.stub)

    implementation(libs.parcelablelist)
    implementation(libs.rikkax.insets)
    implementation(libs.rikkax.lifecycle.resource.livedata)
    implementation(libs.rikkax.lifecycle.viewmodel.lazy)
    implementation(libs.rikkax.recyclerview.adapter)
    implementation(libs.rikkax.recyclerview.ktx)
    implementation(libs.rikkax.widget.borderview)
    implementation(libs.rikkax.html.ktx)

    implementation(libs.androidx.annotation)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.fragment.ktx)
    implementation(libs.androidx.recyclerview)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(libs.androidx.lifecycle.livedata.ktx)
    implementation(libs.androidx.swiperefreshlayout)

    implementation(libs.google.material)
    implementation(libs.androidx.dynamicanimation)
    implementation(libs.fastscroll)
    implementation(libs.appiconloader)
}
