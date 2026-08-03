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

package rikka.sui.gradle

import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.api.tasks.options.Option
import org.gradle.process.ExecOperations
import org.gradle.work.DisableCachingByDefault
import java.io.ByteArrayOutputStream
import javax.inject.Inject

enum class ModuleInstallerMode {
    AUTO,
    MAGISK,
    KERNEL_SU,
}

@DisableCachingByDefault(because = "Executes adb commands against connected devices")
abstract class AdbModuleTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val moduleZip: RegularFileProperty

    @get:Input
    @get:Optional
    abstract val installer: Property<ModuleInstallerMode>

    @get:Input
    abstract val reboot: Property<Boolean>

    @get:Input
    @get:Optional
    abstract val device: Property<String>

    @get:Inject
    abstract val execOperations: ExecOperations

    private enum class RootAccess {
        SU,
        ADBD,
    }

    private enum class RootImplementation {
        APATCH,
        KERNEL_SU,
        MAGISK,
    }

    private data class ModuleInstaller(
        val displayName: String,
        val command: String,
        val useMagiskMountNamespace: Boolean = false,
    )

    @Option(option = "device", description = "ADB serial; defaults to all online devices")
    fun setDeviceOption(serial: String) {
        device.set(serial)
    }

    private fun targetDevices(): List<String> {
        device.orNull?.let { serial ->
            if (serial.isBlank()) {
                throw GradleException("Device serial must not be blank")
            }
            return listOf(serial.trim())
        }

        val output = ByteArrayOutputStream()
        execOperations.exec {
            commandLine("adb", "devices")
            standardOutput = output
        }
        val devices = output.toString(Charsets.UTF_8)
            .lineSequence()
            .map { it.trim().split(Regex("\\s+")) }
            .filter { it.size >= 2 && it[1] == "device" }
            .map { it[0] }
            .toList()
        if (devices.isEmpty()) {
            throw GradleException("No online adb devices found")
        }
        return devices
    }

    private fun adb(serial: String, vararg arguments: String, ignoreExitValue: Boolean = false): Int {
        logger.lifecycle("adb -s {} {}", serial, arguments.joinToString(" "))
        return execOperations.exec {
            commandLine(listOf("adb", "-s", serial) + arguments)
            isIgnoreExitValue = ignoreExitValue
        }.exitValue
    }

    private fun adbOutput(serial: String, vararg arguments: String): String? {
        val output = ByteArrayOutputStream()
        val error = ByteArrayOutputStream()
        val result = execOperations.exec {
            commandLine(listOf("adb", "-s", serial) + arguments)
            standardOutput = output
            errorOutput = error
            isIgnoreExitValue = true
        }
        return if (result.exitValue == 0) output.toString(Charsets.UTF_8).trim() else null
    }

    private fun hasRootSu(serial: String): Boolean = adbOutput(serial, "shell", "su", "-c", "id -u")
        ?.lineSequence()
        ?.lastOrNull() == "0"

    private fun shellQuote(value: String): String = "'${value.replace("'", "'\\''")}'"

    private fun rootCommand(access: RootAccess, command: String, useMagiskMountNamespace: Boolean = false): String {
        val commandWithPath =
            "export PATH=/data/adb/ksu/bin:/data/adb/magisk:/debug_ramdisk:\$PATH; $command"
        return when (access) {
            RootAccess.SU -> {
                val mountNamespace = if (useMagiskMountNamespace) "-M " else ""
                "su $mountNamespace-c ${shellQuote(commandWithPath)}"
            }

            RootAccess.ADBD -> commandWithPath
        }
    }

    private fun rootOutput(serial: String, access: RootAccess, command: String): String? = adbOutput(serial, "shell", rootCommand(access, command))

    private fun rootExec(
        serial: String,
        access: RootAccess,
        command: String,
        useMagiskMountNamespace: Boolean = false,
    ) {
        adb(serial, "shell", rootCommand(access, command, useMagiskMountNamespace))
    }

    private fun enableAdbRoot(serial: String): Boolean {
        logger.lifecycle("Device {} has no working su; trying adb root", serial)
        adb(serial, "root", ignoreExitValue = true)
        repeat(20) {
            val uid = adbOutput(serial, "shell", "id", "-u")
            if (uid == "0") {
                return true
            }
            if (uid != null) {
                return false
            }
            Thread.sleep(500)
        }
        return false
    }

    private fun rootAccess(serial: String): RootAccess {
        if (hasRootSu(serial)) {
            logger.lifecycle("Device {}: using su", serial)
            return RootAccess.SU
        }
        if (enableAdbRoot(serial)) {
            logger.lifecycle("Device {}: using root adbd", serial)
            return RootAccess.ADBD
        }
        throw GradleException("Device $serial has neither a working su command nor root-capable adbd")
    }

    private fun commandAvailable(serial: String, access: RootAccess, test: String): Boolean = rootOutput(serial, access, "$test && echo available")
        ?.lineSequence()
        ?.lastOrNull() == "available"

    private fun findInstaller(
        serial: String,
        access: RootAccess,
        implementation: RootImplementation,
    ): ModuleInstaller? = when (implementation) {
        RootImplementation.APATCH -> {
            if (commandAvailable(serial, access, "[ -x /data/adb/apd ]")) {
                ModuleInstaller("APatch", "/data/adb/apd module install")
            } else {
                null
            }
        }

        RootImplementation.KERNEL_SU -> {
            val executable = when {
                commandAvailable(serial, access, "[ -x /data/adb/ksud ]") -> "/data/adb/ksud"

                commandAvailable(serial, access, "[ -x /data/adb/ksu/bin/ksud ]") ->
                    "/data/adb/ksu/bin/ksud"

                else -> null
            }
            executable?.let { ModuleInstaller("KernelSU", "$it module install") }
        }

        RootImplementation.MAGISK -> {
            val executable = listOf(
                "/data/adb/magisk/magisk",
                "/debug_ramdisk/magisk",
                "/sbin/magisk",
                "/data/adb/magisk/magisk64",
                "/data/adb/magisk/magisk32",
            ).firstOrNull { commandAvailable(serial, access, "[ -x $it ]") }
                ?: rootOutput(serial, access, "command -v magisk 2>/dev/null")
                    ?.lineSequence()
                    ?.lastOrNull()
            executable?.let {
                ModuleInstaller("Magisk", "$it --install-module", useMagiskMountNamespace = true)
            }
        }
    }

    private fun resolveInstaller(
        serial: String,
        access: RootAccess,
        requested: ModuleInstallerMode,
    ): ModuleInstaller {
        val candidates = when (requested) {
            ModuleInstallerMode.AUTO ->
                listOf(RootImplementation.APATCH, RootImplementation.KERNEL_SU, RootImplementation.MAGISK)

            ModuleInstallerMode.MAGISK -> listOf(RootImplementation.MAGISK)

            ModuleInstallerMode.KERNEL_SU -> listOf(RootImplementation.KERNEL_SU)
        }
        return candidates.firstNotNullOfOrNull { findInstaller(serial, access, it) }
            ?: throw GradleException("Unable to find $requested module installer on device $serial")
    }

    @TaskAction
    fun run() {
        val zip = moduleZip.get().asFile
        val destination = "/data/local/tmp/${zip.name}"
        val failedDevices = mutableListOf<String>()

        targetDevices().forEach { serial ->
            var adbdRooted = false
            var rebootIssued = false
            try {
                adb(serial, "push", zip.absolutePath, destination)
                installer.orNull?.let { requested ->
                    val access = rootAccess(serial)
                    adbdRooted = access == RootAccess.ADBD
                    val selected = resolveInstaller(serial, access, requested)
                    logger.lifecycle("Device {}: installing with {}", serial, selected.displayName)
                    val command = "${selected.command} ${shellQuote(destination)}"
                    rootExec(serial, access, command, selected.useMagiskMountNamespace)
                }
                if (reboot.get()) {
                    rebootIssued = adb(serial, "reboot", ignoreExitValue = true) == 0
                }
            } catch (e: Exception) {
                logger.error("Failed on device $serial: ${e.message}")
                failedDevices += serial
            } finally {
                if (adbdRooted && !rebootIssued) {
                    adb(serial, "unroot", ignoreExitValue = true)
                }
            }
        }

        if (failedDevices.isNotEmpty()) {
            throw GradleException("ADB operation failed on: ${failedDevices.joinToString()}")
        }
    }
}
