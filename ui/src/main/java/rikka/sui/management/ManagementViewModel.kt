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
 * Copyright (c) 2021-2026 Sui Contributors
 */
package rikka.sui.management

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import androidx.core.content.edit
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.sui.model.AppInfo
import rikka.sui.util.AppInfoComparator
import rikka.sui.util.AppLabelCache
import rikka.sui.util.BridgeServiceClient

class ManagementViewModel : ViewModel() {

    private val uiDebugMode = false
    private val fullList = ArrayList<AppInfo>()
    var showOnlyShizukuApps = false
    var isMonetEnabled = false
    var isLegacyShizukuBinderCompatEnabled = false
    private var hasLoadedGlobalSettings = false
    val appList = MutableLiveData<Resource<List<AppInfo>?>?>(null)
    private var currentQuery: String? = null
    private var reloadJob: Job? = null

    private fun buildDisplayList(): List<AppInfo> {
        var tempSequence = fullList.asSequence()
        if (!currentQuery.isNullOrBlank()) {
            tempSequence = tempSequence.filter { appInfo ->
                val appName = appInfo.label ?: ""
                val packageName = appInfo.packageInfo.packageName
                appName.contains(currentQuery!!, ignoreCase = true) || packageName.contains(currentQuery!!, ignoreCase = true)
            }
        }
        return tempSequence.sortedWith(AppInfoComparator()).toList()
    }

    private fun displayList() {
        appList.postValue(Resource.success(buildDisplayList()))
    }

    fun filter(query: String?) {
        currentQuery = query
        viewModelScope.launch(Dispatchers.IO) {
            displayList()
        }
    }
    fun toggleShizukuFilter(enable: Boolean, context: Context, onResult: (Boolean) -> Unit) {
        if (showOnlyShizukuApps == enable) {
            onResult(true)
            return
        }

        viewModelScope.launch(Dispatchers.IO) {
            val currentFlags = BridgeServiceClient.getGlobalSettings()
            val newFlags = if (enable) {
                currentFlags or BridgeServiceClient.FLAG_SHOW_ONLY_SHIZUKU_APPS
            } else {
                currentFlags and BridgeServiceClient.FLAG_SHOW_ONLY_SHIZUKU_APPS.inv()
            }
            val success = BridgeServiceClient.setGlobalSettings(newFlags)

            withContext(Dispatchers.Main) {
                if (success) {
                    showOnlyShizukuApps = enable
                    reload(context)
                }
                onResult(success)
            }
        }
    }

    fun toggleMonetSetting(context: Context, onResult: (Boolean) -> Unit) {
        val newState = !isMonetEnabled

        viewModelScope.launch(Dispatchers.IO) {
            val currentFlags = BridgeServiceClient.getGlobalSettings()
            val newFlags = if (!newState) {
                currentFlags or BridgeServiceClient.FLAG_MONET_DISABLED
            } else {
                currentFlags and BridgeServiceClient.FLAG_MONET_DISABLED.inv()
            }
            val success = BridgeServiceClient.setGlobalSettings(newFlags)

            withContext(Dispatchers.Main) {
                if (success) {
                    isMonetEnabled = newState
                    val prefs = context.getSharedPreferences("sui_settings", Context.MODE_PRIVATE)
                    prefs.edit { putBoolean("monet_enabled", newState) }
                }
                onResult(success)
            }
        }
    }

    fun toggleLegacyShizukuBinderCompat(onResult: (Boolean) -> Unit) {
        val newState = !isLegacyShizukuBinderCompatEnabled

        viewModelScope.launch(Dispatchers.IO) {
            val currentFlags = BridgeServiceClient.getGlobalSettings()
            val newFlags = if (newState) {
                currentFlags or BridgeServiceClient.FLAG_LEGACY_SHIZUKU_BINDER_COMPAT
            } else {
                currentFlags and BridgeServiceClient.FLAG_LEGACY_SHIZUKU_BINDER_COMPAT.inv()
            }
            val success = BridgeServiceClient.setGlobalSettings(newFlags)

            withContext(Dispatchers.Main) {
                if (success) {
                    isLegacyShizukuBinderCompatEnabled = newState
                }
                onResult(success)
            }
        }
    }

    fun batchUpdate(targetMode: Int, context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            if (uiDebugMode) {
                fullList.forEach { it.defaultFlags = targetMode }
                displayList()
                return@launch
            }

            try {
                BridgeServiceClient.batchUpdateUnconfigured(targetMode)
            } catch (e: Throwable) {
                android.util.Log.e("SuiViewModel", "update failed", e)
                appList.postValue(Resource.error(e, null))
                return@launch
            }
            reload(context)
        }
    }

    fun reload(context: Context) {
        reloadJob?.cancel()
        appList.postValue(Resource.loading(null))

        if (uiDebugMode) {
            reloadJob = viewModelScope.launch(Dispatchers.IO) {
                val fakeData = createFakeAppList()
                fullList.clear()
                fullList.addAll(fakeData)
                displayList()
            }
            return
        }

        reloadJob = viewModelScope.launch(Dispatchers.IO) {
            val pm = context.packageManager
            try {
                if (!hasLoadedGlobalSettings) {
                    val flags = BridgeServiceClient.getGlobalSettings()
                    showOnlyShizukuApps = (flags and BridgeServiceClient.FLAG_SHOW_ONLY_SHIZUKU_APPS) != 0
                    isMonetEnabled = (flags and BridgeServiceClient.FLAG_MONET_DISABLED) == 0
                    isLegacyShizukuBinderCompatEnabled =
                        (flags and BridgeServiceClient.FLAG_LEGACY_SHIZUKU_BINDER_COMPAT) != 0
                    hasLoadedGlobalSettings = true
                }

                val result = BridgeServiceClient.getApplications(-1, showOnlyShizukuApps)
                if (result.isNotEmpty()) {
                    val labelDispatcher = Dispatchers.IO.limitedParallelism(4)
                    coroutineScope {
                        result.mapNotNull { app ->
                            val applicationInfo = app?.packageInfo?.applicationInfo ?: return@mapNotNull null
                            async(labelDispatcher) {
                                app.label = AppLabelCache.loadLabel(pm, applicationInfo)
                            }
                        }.awaitAll()
                    }
                }

                fullList.clear()
                fullList.addAll(result)

                displayList()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                android.util.Log.e("SuiViewModel", "THE SMOKING GUN! The final error is:", e)
                appList.postValue(Resource.error(e, null))
            }
        }
    }

    fun cancelReload() {
        reloadJob?.cancel()
        reloadJob = null
        appList.postValue(Resource.success(buildDisplayList()))
    }

    private fun createFakeAppList(): List<AppInfo> {
        val names = listOf(
            "Ciallo", "0721", "0d00", "小潼", "xiaotong",
            "测试QQ", "91av", "糖心vlog", "禁漫天堂", "哔咔",
            "AcFun(伪)", "伪萌娘百科", "喵喵喵", "测试新闻阅读器", "虚拟地图",
            "伪联系人", "虚构记事本", "测试QQ浏览器", "假计算器", "虚拟音乐盒",
            "FakeWeChat", "仿微博", "虚拟支付宝", "TestGame", "假装抖音",
            "仿快手Lite", "测试天气通", "伪知乎", "虚构邮箱", "假浏览器",
            "模拟短信", "测试电话", "虚拟文件管理器", "仿酷狗音乐", "假设记账本",
            "虚拟Steam", "测试百度网盘", "仿Telegram", "虚构推特", "假装网易云",
            "伪系统设置", "测试图库", "虚拟录音机", "假相机", "伪Chrome",
            "虚拟记事贴", "测试视频播放器", "仿哔哩哔哩", "假购物App", "虚构新闻中心",
        )

        return names.mapIndexed { index, name ->
            val pkg = "com.example.fakeapp${index + 1}"
            AppInfo().apply {
                packageInfo = PackageInfo().apply {
                    packageName = pkg
                    applicationInfo = ApplicationInfo().apply {
                        nonLocalizedLabel = name
                        this.packageName = pkg
                    }
                }
                label = name
                flags = 0
                effectiveFlags = 0
                defaultFlags = 0
            }
        }
    }
}
