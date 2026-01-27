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
import android.content.res.Configuration
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.TextView
import androidx.core.text.HtmlCompat
import me.zhanghai.android.fastscroll.PopupTextProvider
import rikka.recyclerview.BaseRecyclerViewAdapter
import rikka.recyclerview.ClassCreatorPool
import rikka.sui.R
import rikka.sui.model.AppInfo
import java.util.Locale

class ManagementAdapter(
    context: Context,
) : BaseRecyclerViewAdapter<ClassCreatorPool>(),
    PopupTextProvider {
    init {
        creatorPool.putRule(AppInfo::class.java, ManagementAppItemViewHolder.newCreator(createOptionsAdapter(context)))
        setHasStableIds(true)
    }

    private fun createOptionsAdapter(context: Context): ArrayAdapter<CharSequence> {
        val theme = context.theme
        val isNight = context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_YES != 0

        val typedValue = TypedValue()
        theme.resolveAttribute(androidx.appcompat.R.attr.colorAccent, typedValue, true)
        val colorAccent = typedValue.data

        theme.resolveAttribute(android.R.attr.colorForeground, typedValue, true)
        val colorForeground = typedValue.data

        theme.resolveAttribute(android.R.attr.textColorTertiary, typedValue, true)
        val textColorTertiary =
            try {
                context.getColorStateList(typedValue.resourceId)
            } catch (e: Exception) {
                android.content.res.ColorStateList
                    .valueOf(android.graphics.Color.GRAY)
            }

        val colorError = if (isNight) 0xFF8A80 else 0xFF5252

        val adapter =
            object : ArrayAdapter<CharSequence>(
                context,
                android.R.layout.simple_spinner_item,
                arrayOf(
                    HtmlCompat.fromHtml(
                        String.format(
                            "<font face=\"sans-serif-medium\" color=\"#%2\$s\">%1\$s</font>",
                            context.getString(R.string.permission_allowed),
                            String.format(
                                Locale.ENGLISH,
                                "%06x",
                                colorAccent and 0xffffff,
                            ),
                        ),
                        HtmlCompat.FROM_HTML_MODE_LEGACY,
                    ),
                    HtmlCompat.fromHtml(
                        String.format(
                            "<font face=\"sans-serif-medium\" color=\"#%2\$s\">%1\$s</font>",
                            context.getString(R.string.permission_denied),
                            String.format(
                                Locale.ENGLISH,
                                "%06x",
                                colorError and 0xffffff,
                            ),
                        ),
                        HtmlCompat.FROM_HTML_MODE_LEGACY,
                    ),
                    HtmlCompat.fromHtml(
                        String.format(
                            "<font face=\"sans-serif-medium\" color=\"#%2\$s\">%1\$s</font>",
                            context.getString(R.string.permission_hidden),
                            String.format(
                                Locale.ENGLISH,
                                "%06x",
                                colorForeground and 0xffffff,
                            ),
                        ),
                        HtmlCompat.FROM_HTML_MODE_LEGACY,
                    ),
                    context.getString(R.string.permission_default),
                ),
            ) {
                override fun getView(
                    position: Int,
                    convertView: View?,
                    parent: ViewGroup,
                ): View {
                    val view = super.getView(position, convertView, parent)
                    (view.findViewById<TextView>(android.R.id.text1))?.let {
                        it.setTextColor(textColorTertiary)
                        it.gravity = Gravity.CENTER_VERTICAL or Gravity.END
                    }
                    return view
                }
            }
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        return adapter
    }

    override fun getItemId(position: Int): Long = getItemAt<Any>(position).hashCode().toLong()

    override fun onCreateCreatorPool(): ClassCreatorPool = ClassCreatorPool()

    fun updateData(data: List<AppInfo>) {
        getItems<Any>().clear()
        getItems<Any>().addAll(data)
        notifyDataSetChanged()
    }

    override fun getPopupText(
        view: View,
        position: Int,
    ): CharSequence = try {
        val appInfo = getItemAt<AppInfo>(position)
        val appName = appInfo.label

        if (appName.isNullOrEmpty()) {
            " "
        } else {
            appName.substring(0, 1).uppercase()
        }
    } catch (e: Exception) {
        ""
    }
}
