plugins {
    id("com.android.library")
}

// --- 1. 动态版本定义 ---

// 定义 NeoZygisk (Rust Daemon) 所需的常量
val minAPatchVersion = 10000
val minKsuVersion = 10940
val maxKsuVersion = 20000
val minMagiskVersion = 26100

// 动态计算版本信息
val verCode: Int = providers.exec {
    commandLine("git", "rev-list", "HEAD", "--count")
}.standardOutput.asText.get().trim().toIntOrNull() ?: 1

val verName: String = providers.exec {
    commandLine("git", "describe", "--tags", "--always")
}.standardOutput.asText.get().trim().let { if (it.isEmpty() || it == "unknown") "dev" else it }

val commitHash: String = providers.exec {
    commandLine("git", "rev-parse", "--verify", "--short", "HEAD")
}.standardOutput.asText.get().trim()

android {
    namespace = "rikka.sui.standalone"
    compileSdk = 36
    ndkVersion = "29.0.14206865"

    defaultConfig {
        minSdk = 24
        externalNativeBuild {
            cmake {
                arguments += "-DZKSU_VERSION=$verName-$verCode-$commitHash"
                arguments += "-DSUI_SOCKET_NAME=\"sui_\""
                cFlags += listOf("-Wall", "-Wextra", "-Oz", "-flto", "-fvisibility=hidden", "-fno-stack-protector", "-fomit-frame-pointer")
                cppFlags += listOf("-Wall", "-Wextra", "-Oz", "-flto", "-fvisibility=hidden", "-fno-rtti", "-fno-exceptions", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables")
                abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
                targets += "zygisk"
                targets += listOf("zygisk", "libzygisk_ptrace.so")
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("loader/src/CMakeLists.txt")
        }
    }

    buildFeatures {
        buildConfig = false
    }
}

// --- 3. 配置 Rust Daemon 构建任务 ---

val rustTargets = mapOf(
    "arm64-v8a" to "aarch64-linux-android",
    "armeabi-v7a" to "armv7-linux-androideabi",
    "x86_64" to "x86_64-linux-android",
    "x86" to "i686-linux-android"
)

rustTargets.values.forEach { target ->
    tasks.register<Exec>("buildZygiskd_${target.replace('-', '_')}") {
        group = "build"
        description = "Builds the Rust daemon for $target"

        workingDir = file("zygiskd")

        val ndkDir = android.ndkDirectory
        val hostTag = "linux-x86_64"
        val apiLevel = 24

        val linkerPrefix = when (target) {
            "armv7-linux-androideabi" -> "armv7a-linux-androideabi"
            else -> target
        }

        val linkerPath = file("$ndkDir/toolchains/llvm/prebuilt/$hostTag/bin/${linkerPrefix}${apiLevel}-clang").absolutePath
        val arPath = file("$ndkDir/toolchains/llvm/prebuilt/$hostTag/bin/llvm-ar").absolutePath

        if (!file(linkerPath).exists()) {
            throw GradleException("Linker for $target not found at: $linkerPath")
        }

        // [关键修改] 只保留 Linker 和 AR 的环境变量
        val envTarget = target.replace('-', '_').uppercase()
        environment("CARGO_TARGET_${envTarget}_LINKER", linkerPath)
        environment("CARGO_TARGET_${envTarget}_AR", arPath)

        // [关键修改] 把 PATH 设置独立出来，确保 cargo 能找到
        val userHome = System.getProperty("user.home")
        environment("PATH", "${System.getenv("PATH")}:${File(userHome, ".cargo/bin")}")

        val cargoExecutable = File(userHome, ".cargo/bin/cargo").absolutePath
        commandLine(cargoExecutable, "build", "--target", target, "--release")
    }
}


// --- 4. [修改] 收集产物任务 (支持多架构) ---

tasks.register("copyStandaloneBinaries") { // 注意这里不再是 Copy 类型，而是普通 Task
    // 1. 声明依赖
    rustTargets.values.forEach { target ->
        dependsOn(tasks.named("buildZygiskd_${target.replace('-', '_')}"))
    }
    dependsOn(tasks.named("externalNativeBuildRelease"))

    // 2. 定义输出目录 (供 module 模块引用)
    val outputDir = layout.buildDirectory.dir("intermediates/standalone_out")
    outputs.dir(outputDir) // 声明输出，帮助 Gradle 建立依赖链

    doLast {
        val destDir = outputDir.get().asFile
        // 先清空输出目录，防止残留
        if (destDir.exists()) destDir.deleteRecursively()
        destDir.mkdirs()

        rustTargets.forEach { (abi, target) ->
            println("Processing ABI: $abi (Target: $target)")

            // 1. 复制 sui_daemon
            val zygiskdSource = file("${project.projectDir}/zygiskd/build/intermediates/rust/$target/release/zygiskd")
            if (zygiskdSource.exists()) {
                project.copy {
                    from(zygiskdSource)
                    rename { "sui_daemon" }
                    into(File(destDir, abi))
                }
                println("  -> Copied sui_daemon")
            } else {
                throw GradleException("sui_daemon not found at $zygiskdSource")
            }

            // 2. 复制 libsui_loader.so
            val loaderSource = file("${layout.buildDirectory.get()}/intermediates/cmake/release/obj/$abi/libzygisk.so")
            if (loaderSource.exists()) {
                project.copy {
                    from(loaderSource)
                    rename { "libsui_loader.so" }
                    into(File(destDir, abi))
                }
                println("  -> Copied libsui_loader.so")
            } else {
                throw GradleException("libzygisk.so not found at $loaderSource")
            }
            val monitorSource = file("${layout.buildDirectory.get()}/intermediates/stripped_native_libs/release/stripReleaseDebugSymbols/out/lib/$abi/libzygisk_ptrace.so")

            // 如果 stripped 找不到，尝试找 obj 目录 (有时可执行文件不会被 strip task 处理)
            val monitorSourceObj = file("${layout.buildDirectory.get()}/intermediates/cmake/release/obj/$abi/libzygisk_ptrace.so")

            if (monitorSource.exists()) {
                project.copy {
                    from(monitorSource)
                    rename { "sui_monitor" }
                    into(File(destDir, abi))
                }
                println("  -> Copied sui_monitor (from stripped)")
            } else if (monitorSourceObj.exists()) {
                project.copy {
                    from(monitorSourceObj)
                    rename { "sui_monitor" }
                    into(File(destDir, abi))
                }
                println("  -> Copied sui_monitor (from obj)")
            } else {
                throw GradleException("sui_monitor (libzygisk_ptrace.so) not found at $monitorSource or $monitorSourceObj")
            }
        }

        println("Standalone binaries copied to: $destDir")
    }
}