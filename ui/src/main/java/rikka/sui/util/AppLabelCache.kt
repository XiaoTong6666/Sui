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

package rikka.sui.util

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.util.Log
import android.widget.TextView
import androidx.collection.LruCache
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import kotlin.coroutines.CoroutineContext

object AppLabelCache : CoroutineScope {

    override val coroutineContext: CoroutineContext get() = Dispatchers.Main

    private val lruCache = LruCache<String, CharSequence>(2000)

    private val dispatcher: CoroutineDispatcher

    init {
        val availableProcessorsCount = try {
            Runtime.getRuntime().availableProcessors()
        } catch (ignored: Exception) {
            1
        }
        val threadCount = 1.coerceAtLeast(availableProcessorsCount / 2)
        val loadLabelExecutor: Executor = Executors.newFixedThreadPool(threadCount)
        dispatcher = loadLabelExecutor.asCoroutineDispatcher()
    }

    private fun get(packageName: String): CharSequence? = lruCache[packageName]

    private fun put(packageName: String, label: CharSequence) {
        lruCache.put(packageName, label)
    }

    fun clear() {
        lruCache.evictAll()
    }

    fun loadLabel(pm: PackageManager, info: ApplicationInfo): CharSequence = try {
        info.loadLabel(pm)
    } catch (e: Throwable) {
        info.packageName
    }

    @JvmStatic
    fun loadLabelAsync(
        context: Context,
        info: ApplicationInfo,
        view: TextView,
        transformer: ((CharSequence) -> CharSequence)? = null,
    ): Job {
        val packageName = info.packageName
        val cachedLabel = get(packageName)
        if (cachedLabel != null) {
            view.text = transformer?.invoke(cachedLabel) ?: cachedLabel
            return launch { }
        }

        view.text = transformer?.invoke(packageName) ?: packageName

        return launch {
            val label = try {
                withContext(dispatcher) {
                    val pm = context.packageManager
                    val loaded = loadLabel(pm, info)
                    put(packageName, loaded)
                    loaded
                }
            } catch (e: CancellationException) {
                return@launch
            } catch (e: Throwable) {
                Log.w("AppLabelCache", "Load label for $packageName", e)
                packageName
            }

            view.text = transformer?.invoke(label) ?: label
        }
    }
}
