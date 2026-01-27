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

import android.content.res.ColorStateList
import android.graphics.Typeface
import android.util.Log
import android.util.TypedValue
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.AdapterView
import android.widget.AdapterView.OnItemSelectedListener
import android.widget.ArrayAdapter
import kotlinx.coroutines.Job
import rikka.recyclerview.BaseViewHolder
import rikka.sui.databinding.ManagementAppItemBinding
import rikka.sui.model.AppInfo
import rikka.sui.server.SuiConfig
import rikka.sui.util.AppIconCache
import rikka.sui.util.BridgeServiceClient
import rikka.sui.util.UserHandleCompat

class ManagementAppItemViewHolder(
    private val binding: ManagementAppItemBinding,
    private val optionsAdapter: ArrayAdapter<CharSequence>,
) : BaseViewHolder<AppInfo>(binding.root),
    View.OnClickListener {
    companion object {
        fun newCreator(optionsAdapter: ArrayAdapter<CharSequence>) = Creator<AppInfo> { inflater: LayoutInflater, parent: ViewGroup? ->
            ManagementAppItemViewHolder(
                ManagementAppItemBinding.inflate(inflater, parent, false),
                optionsAdapter,
            )
        }

        private val SANS_SERIF = Typeface.create("sans-serif", Typeface.NORMAL)
        private val SANS_SERIF_MEDIUM = Typeface.create("sans-serif-medium", Typeface.NORMAL)
    }

    private inline val packageName get() = data.packageInfo.packageName
    private inline val ai get() = data.packageInfo.applicationInfo
    private inline val uid get() = ai!!.uid

    private var loadIconJob: Job? = null
    private var suppressSelectionCallback = false

    private val icon get() = binding.icon
    private val name get() = binding.title
    private val pkg get() = binding.summary
    private val spinner get() = binding.button1

    private val textColorSecondary: ColorStateList
    private val textColorPrimary: ColorStateList

    private val onItemSelectedListener: OnItemSelectedListener =
        object : OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>,
                view: View,
                position: Int,
                id: Long,
            ) {
                if (suppressSelectionCallback) return
                val newValue =
                    when (position) {
                        0 -> SuiConfig.FLAG_ALLOWED
                        1 -> SuiConfig.FLAG_DENIED
                        2 -> SuiConfig.FLAG_HIDDEN
                        else -> 0
                    }
                try {
                    BridgeServiceClient
                        .getService()
                        .updateFlagsForUid(data.packageInfo.applicationInfo!!.uid, SuiConfig.MASK_PERMISSION, newValue)
                } catch (e: Throwable) {
                    Log.e("SuiSettings", "updateFlagsForUid", e)
                    return
                }
                data.flags = data.flags and SuiConfig.MASK_PERMISSION.inv() or newValue
                setSpinnerSelection(position)
                syncViewStateForFlags()
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

    init {
        val typedValue = TypedValue()
        context.theme.resolveAttribute(android.R.attr.textColorSecondary, typedValue, true)
        textColorSecondary = context.getColorStateList(typedValue.resourceId)

        context.theme.resolveAttribute(android.R.attr.textColorPrimary, typedValue, true)
        textColorPrimary = context.getColorStateList(typedValue.resourceId)

        itemView.setOnClickListener(this)

        this.itemView.setOnClickListener { spinner.performClick() }
        spinner.adapter = optionsAdapter
        spinner.onItemSelectedListener = onItemSelectedListener
    }

    override fun onClick(v: View) {
        adapter.notifyItemChanged(bindingAdapterPosition, Any())
    }

    override fun onBind() {
        loadIconJob?.cancel()

        val userId = UserHandleCompat.getUserId(uid)

        name.text =
            if (userId != UserHandleCompat.myUserId()) {
                "${data.label} - ($userId)"
            } else {
                data.label
            }
        pkg.text = ai!!.packageName

        syncViewStateForFlags()

        icon.setImageDrawable(null)
        loadIconJob = AppIconCache.loadIconBitmapAsync(context, ai!!, ai!!.uid / 100000, icon)
    }

    override fun onBind(payloads: List<Any>) {}

    override fun onRecycle() {
        if (loadIconJob?.isActive == true) {
            loadIconJob?.cancel()
        }
    }

    private fun syncViewStateForFlags() {
        val explicitFlags = data.flags and SuiConfig.MASK_PERMISSION
        val effectiveFlags =
            if (explicitFlags != 0) {
                explicitFlags
            } else {
                data.defaultFlags and SuiConfig.MASK_PERMISSION
            }
        val allowed = effectiveFlags and SuiConfig.FLAG_ALLOWED != 0
        val denied = effectiveFlags and SuiConfig.FLAG_DENIED != 0
        val hidden = effectiveFlags and SuiConfig.FLAG_HIDDEN != 0

        if (allowed) {
            binding.title.setTextColor(textColorPrimary)
            binding.title.typeface = SANS_SERIF_MEDIUM
        } else if (denied) {
            binding.title.setTextColor(textColorSecondary)
            binding.title.typeface = SANS_SERIF
        } else if (hidden) {
            binding.title.setTextColor(textColorSecondary)
            binding.title.typeface = SANS_SERIF
        } else {
            binding.title.setTextColor(textColorSecondary)
            binding.title.typeface = SANS_SERIF
        }

        val explicitAllowed = explicitFlags and SuiConfig.FLAG_ALLOWED != 0
        val explicitDenied = explicitFlags and SuiConfig.FLAG_DENIED != 0
        val explicitHidden = explicitFlags and SuiConfig.FLAG_HIDDEN != 0
        if (explicitAllowed) {
            setSpinnerSelection(0)
        } else if (explicitDenied) {
            setSpinnerSelection(1)
        } else if (explicitHidden) {
            setSpinnerSelection(2)
        } else {
            setSpinnerSelection(3)
        }
    }

    private fun setSpinnerSelection(position: Int) {
        suppressSelectionCallback = true
        spinner.setSelection(position, false)
        suppressSelectionCallback = false
    }
}
