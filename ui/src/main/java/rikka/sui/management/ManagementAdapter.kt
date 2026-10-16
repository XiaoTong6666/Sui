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
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.RecyclerView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.sui.model.AppInfo
import rikka.sui.util.UiStyleSettings

class ManagementAdapter(
    context: Context,
) : RecyclerView.Adapter<ManagementAppItemViewHolder>() {

    private val inflater = LayoutInflater.from(context)
    private val materialUi = UiStyleSettings.isMaterial(context)
    private val adapterScope = MainScope()
    private val items = ArrayList<AppInfo>()
    private var updateJob: Job? = null

    init {
        setHasStableIds(true)
    }

    override fun getItemCount(): Int = items.size

    override fun getItemId(position: Int): Long {
        val item = items[position]
        val uid = item.packageInfo.applicationInfo?.uid?.toLong() ?: 0L
        return uid * 31L + item.packageInfo.packageName.hashCode().toLong()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ManagementAppItemViewHolder = ManagementAppItemViewHolder.create(inflater, parent, materialUi)

    override fun onBindViewHolder(holder: ManagementAppItemViewHolder, position: Int) {
        holder.bind(items[position], this)
        if (materialUi) holder.updateMaterialAppearance(position, items.size)
    }

    override fun onViewRecycled(holder: ManagementAppItemViewHolder) {
        holder.recycle()
        super.onViewRecycled(holder)
    }

    fun updateData(data: List<AppInfo>) {
        updateJob?.cancel()
        val newData = ArrayList(data)

        updateJob = adapterScope.launch(Dispatchers.Default) {
            val oldData = withContext(Dispatchers.Main) { ArrayList(items) }
            val result = DiffUtil.calculateDiff(object : DiffUtil.Callback() {
                override fun getOldListSize(): Int = oldData.size

                override fun getNewListSize(): Int = newData.size

                override fun areItemsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean {
                    val oldItem = oldData[oldItemPosition]
                    val newItem = newData[newItemPosition]
                    return oldItem.packageInfo.packageName == newItem.packageInfo.packageName &&
                        oldItem.packageInfo.applicationInfo?.uid == newItem.packageInfo.applicationInfo?.uid
                }

                override fun areContentsTheSame(oldItemPosition: Int, newItemPosition: Int): Boolean = oldData[oldItemPosition] == newData[newItemPosition]
            })

            withContext(Dispatchers.Main) {
                if (!isActive) return@withContext
                items.clear()
                items.addAll(newData)
                result.dispatchUpdatesTo(this@ManagementAdapter)
            }
        }
    }

    override fun onDetachedFromRecyclerView(recyclerView: RecyclerView) {
        updateJob?.cancel()
        adapterScope.cancel()
        super.onDetachedFromRecyclerView(recyclerView)
    }
}
