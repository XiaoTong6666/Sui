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
import android.content.ContextWrapper
import android.content.pm.ApplicationInfo
import android.graphics.Bitmap
import android.util.Log
import android.widget.ImageView
import androidx.collection.LruCache
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.zhanghai.android.appiconloader.AppIconLoader
import rikka.sui.R
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import kotlin.coroutines.CoroutineContext

object AppIconCache : CoroutineScope {

    private class AppIconLruCache(maxSize: Int) : LruCache<String, Bitmap>(maxSize) {
        override fun sizeOf(key: String, value: Bitmap): Int = value.byteCount / 1024
    }

    override val coroutineContext: CoroutineContext get() = Dispatchers.Main

    private val lruCache: LruCache<String, Bitmap>

    private val dispatcher: CoroutineDispatcher

    private val appIconLoaders = ConcurrentHashMap<Int, AppIconLoader>()

    init {
        // Initialize app icon lru cache
        val maxMemory = Runtime.getRuntime().maxMemory() / 1024
        val availableCacheSize = (maxMemory / 4).toInt()
        lruCache = AppIconLruCache(availableCacheSize)

        // Initialize load icon scheduler
        val availableProcessorsCount = try {
            Runtime.getRuntime().availableProcessors()
        } catch (ignored: Exception) {
            1
        }
        val threadCount = 1.coerceAtLeast(availableProcessorsCount / 2)
        val loadIconExecutor: Executor = Executors.newFixedThreadPool(threadCount) { r ->
            Thread(r).apply {
                priority = Thread.MIN_PRIORITY
            }
        }
        dispatcher = loadIconExecutor.asCoroutineDispatcher()
    }

    fun dispatcher(): CoroutineDispatcher = dispatcher

    private fun get(packageName: String, userId: Int, size: Int): Bitmap? = lruCache["$packageName:$userId:$size"]

    private fun put(packageName: String, userId: Int, size: Int, bitmap: Bitmap) {
        lruCache.put("$packageName:$userId:$size", bitmap)
    }

    private fun remove(packageName: String, userId: Int, size: Int) {
        lruCache.remove("$packageName:$userId:$size")
    }

    private fun loadIconBitmap(context: Context, info: ApplicationInfo, userId: Int, size: Int): Bitmap {
        val cachedBitmap = get(info.packageName, userId, size)
        if (cachedBitmap != null) {
            return cachedBitmap
        }
        val loader = appIconLoaders.getOrPut(size) {
            AppIconLoader(
                size,
                AppIconUtil.shouldShrinkNonAdaptiveIcons(context),
                object : ContextWrapper(context) {
                    override fun getApplicationContext(): Context = context
                },
            )
        }
        val bitmap = loader.loadIcon(info, false)
        put(info.packageName, userId, size, bitmap)
        return bitmap
    }

    @JvmStatic
    fun loadIconBitmapAsync(
        context: Context,
        info: ApplicationInfo,
        userId: Int,
        view: ImageView,
        size: Int,
    ): Job? {
        val cachedBitmap = get(info.packageName, userId, size)
        if (cachedBitmap != null) {
            view.setImageBitmap(cachedBitmap)
            return null
        }

        view.setImageDrawable(null)

        return launch {
            val bitmap = try {
                withContext(dispatcher) {
                    loadIconBitmap(context, info, userId, size)
                }
            } catch (e: CancellationException) {
                // do nothing if canceled
                return@launch
            } catch (e: Throwable) {
                Log.w("AppIconCache", "Load icon for $userId:${info.packageName}", e)
                null
            }

            if (bitmap != null) {
                view.setImageBitmap(bitmap)
            } else {
                view.setImageBitmap(null)
            }
        }
    }
}
