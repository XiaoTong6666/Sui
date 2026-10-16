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
package rikka.sui.widget

import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.util.TypedValue
import android.view.Gravity
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.PopupWindow
import android.widget.TextView
import androidx.appcompat.widget.PopupMenu
import androidx.core.graphics.ColorUtils
import androidx.core.graphics.drawable.toDrawable
import androidx.core.view.get
import androidx.core.view.size
import com.google.android.material.card.MaterialCardView
import com.google.android.material.color.MaterialColors
import rikka.sui.R
import kotlin.math.max
import kotlin.math.min

/** An anchored, Material-themed View menu. No AppCompat popup internals are modified. */
fun PopupMenu.showMaterialMenu(anchor: View, endInsetDp: Int = 0, onDismiss: () -> Unit = {}): PopupWindow {
    val context = anchor.context
    val density = context.resources.displayMetrics.density
    fun dp(value: Float) = (value * density + 0.5f).toInt()
    fun color(attr: Int) = MaterialColors.getColor(anchor, attr)

    val surface = color(R.attr.colorSurfaceContainerLow)
    val selectedSurface = color(R.attr.colorSecondaryContainer)
    val primaryText = color(R.attr.colorOnSurface)
    val selectedText = color(R.attr.colorOnSecondaryContainer)
    val ripple = color(R.attr.colorOnSurface)

    val visibleItems = (0 until menu.size).map(menu::get).filter(MenuItem::isVisible)
    val submenuIds = setOf(R.id.action_batch_unconfigured, R.id.action_ui_style, R.id.action_adb_root)
    val hasSubmenu = visibleItems.any { it.itemId in submenuIds }
    val textPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        textSize = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_SP,
            14f,
            context.resources.displayMetrics,
        )
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
    }
    val textWidth = visibleItems.maxOfOrNull { textPaint.measureText(it.title?.toString().orEmpty()) } ?: 0f
    val hasSelection = visibleItems.any { it.isCheckable || it.isChecked }
    // Checked items place their leading icon before the label, as Compose does.
    val desiredWidth = textWidth.toInt() + dp(if (hasSelection) 64f else 36f) + dp(if (hasSubmenu) 20f else 0f)
    val width = min(max(dp(160f), desiredWidth), min(dp(280f), context.resources.displayMetrics.widthPixels - dp(24f)))

    val content = LinearLayout(context).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(4f), dp(4f), dp(4f), dp(4f))
    }

    val card = MaterialCardView(context).apply {
        radius = dp(16f).toFloat()
        cardElevation = 0f
        strokeWidth = 0
        setCardBackgroundColor(surface)
        addView(content)
    }

    val popup = PopupWindow(card, width, ViewGroup.LayoutParams.WRAP_CONTENT, true).apply {
        setBackgroundDrawable(Color.TRANSPARENT.toDrawable())
        elevation = dp(12f).toFloat()
        isOutsideTouchable = true
        inputMethodMode = PopupWindow.INPUT_METHOD_NOT_NEEDED
        setOnDismissListener(onDismiss)
    }

    for ((index, item) in visibleItems.withIndex()) {
        val checked = item.isChecked
        val outerRadius = dp(12f).toFloat()
        val innerRadius = dp(4f).toFloat()
        val topRadius = if (index == 0) outerRadius else innerRadius
        val bottomRadius = if (index == visibleItems.lastIndex) outerRadius else innerRadius
        // A checked item uses a 12dp shape regardless of its position. The
        // ripple mask must match the selected fill, not the unselected shape.
        val rowCorners = if (checked) {
            FloatArray(8) { outerRadius }
        } else {
            floatArrayOf(
                topRadius,
                topRadius,
                topRadius,
                topRadius,
                bottomRadius,
                bottomRadius,
                bottomRadius,
                bottomRadius,
            )
        }
        val rowFill = GradientDrawable().apply {
            cornerRadii = rowCorners
            setColor(if (checked) selectedSurface else Color.TRANSPARENT)
        }
        val mask = GradientDrawable().apply {
            cornerRadii = rowCorners
            setColor(Color.WHITE)
        }
        val row = LinearLayout(context).apply {
            gravity = Gravity.CENTER_VERTICAL
            orientation = LinearLayout.HORIZONTAL
            minimumHeight = dp(44f)
            isClickable = item.isEnabled
            isFocusable = item.isEnabled
            background = RippleDrawable(ColorStateList.valueOf(ColorUtils.setAlphaComponent(ripple, 0x20)), rowFill, mask)
            setPadding(dp(12f), dp(2f), dp(12f), dp(2f))
        }

        if (checked) {
            val check = ImageView(context).apply {
                setImageResource(R.drawable.ic_material_check_24)
                imageTintList = ColorStateList.valueOf(selectedText)
                contentDescription = context.getString(android.R.string.ok)
            }
            row.addView(
                check,
                LinearLayout.LayoutParams(dp(20f), dp(20f)).apply {
                    marginEnd = dp(10f)
                },
            )
        }

        val label = TextView(context).apply {
            text = item.title.toString()
            setTextColor(if (checked) selectedText else primaryText)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
            maxLines = 2
            includeFontPadding = false
        }
        row.addView(label, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))

        if (item.itemId in submenuIds) {
            val arrow = ImageView(context).apply {
                setImageResource(R.drawable.ic_material_popup_next)
                imageTintList = ColorStateList.valueOf(primaryText)
                contentDescription = null
            }
            row.addView(
                arrow,
                LinearLayout.LayoutParams(dp(20f), dp(20f)).apply {
                    marginStart = dp(6f)
                },
            )
        }

        row.setOnClickListener {
            popup.dismiss()
            menu.performIdentifierAction(item.itemId, 0)
        }
        content.addView(
            row,
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                // M3E segmented menu token: a 2dp gap between item shapes.
                if (index > 0) topMargin = dp(2f)
            },
        )
    }

    // Match the MIUIX overflow menu's 20dp end inset, including in RTL.
    val endInset = dp(endInsetDp.toFloat())
    val xOffset = if (anchor.layoutDirection == View.LAYOUT_DIRECTION_RTL) endInset else -endInset
    popup.showAsDropDown(anchor, xOffset, dp(4f), Gravity.END)
    return popup
}
