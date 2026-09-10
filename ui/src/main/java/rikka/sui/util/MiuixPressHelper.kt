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

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Context
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Rect
import android.graphics.Typeface
import android.graphics.drawable.DrawableWrapper
import android.text.Spannable
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.ListView
import android.widget.PopupWindow
import androidx.appcompat.widget.ListPopupWindow
import androidx.appcompat.widget.PopupMenu
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import androidx.core.graphics.toColorInt
import androidx.core.view.get
import androidx.core.view.size
import androidx.dynamicanimation.animation.SpringAnimation
import androidx.dynamicanimation.animation.SpringForce
import rikka.sui.R
import rikka.sui.ktx.resolveColor
import java.lang.ref.WeakReference
import java.lang.reflect.Field

class MiuixPressHelper : View.OnTouchListener {
    private var scaleXAnimation: SpringAnimation? = null
    private var scaleYAnimation: SpringAnimation? = null
    private val viewBounds = Rect()

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouch(v: View, event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                initAnimations(v)
                v.isPressed = true
                scaleDown()
            }

            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                v.isPressed = false
                scaleUp()
            }

            MotionEvent.ACTION_MOVE -> {
                v.getDrawingRect(viewBounds)
                if (!viewBounds.contains(event.x.toInt(), event.y.toInt())) {
                    scaleUp()
                }
            }
        }
        return false
    }

    private fun initAnimations(v: View) {
        if (scaleXAnimation == null) {
            scaleXAnimation = SpringAnimation(v, SpringAnimation.SCALE_X).apply {
                spring = SpringForce(1f).apply {
                    dampingRatio = 0.8f
                    stiffness = 600f
                }
            }
            scaleYAnimation = SpringAnimation(v, SpringAnimation.SCALE_Y).apply {
                spring = SpringForce(1f).apply {
                    dampingRatio = 0.8f
                    stiffness = 600f
                }
            }
        }
    }

    private fun scaleDown() {
        scaleXAnimation?.animateToFinalPosition(0.94f)
        scaleYAnimation?.animateToFinalPosition(0.94f)
    }

    private fun scaleUp() {
        scaleXAnimation?.animateToFinalPosition(1f)
        scaleYAnimation?.animateToFinalPosition(1f)
    }
}

fun PopupMenu.applyMiuixPopupStyle() {
    try {
        val mAnchorField = this.javaClass.getDeclaredField("mAnchor")
        mAnchorField.isAccessible = true
        val anchor = mAnchorField.get(this) as? View
        if (anchor != null) {
            val loc = IntArray(2)
            anchor.getLocationOnScreen(loc)
            MiuixPopupState.anchorX = loc[0]
            MiuixPopupState.anchorY = loc[1]
        }
    } catch (e: Exception) {
        Log.e("Sui", "Failed to extract popup anchor", e)
    }

    this.show()
    try {
        val mPopupField = this.javaClass.getDeclaredField("mPopup")
        mPopupField.isAccessible = true
        val mPopup = mPopupField.get(this)

        val getPopupMethod = mPopup.javaClass.getDeclaredMethod("getPopup")
        getPopupMethod.isAccessible = true
        val popup = getPopupMethod.invoke(mPopup)

        val getListViewMethod = popup.javaClass.getDeclaredMethod("getListView")
        getListViewMethod.isAccessible = true
        val listView = getListViewMethod.invoke(popup) as? ListView

        var listPopupWindow: Any? = null
        try {
            val mPopupWindowField = popup.javaClass.getDeclaredField("mPopup")
            mPopupWindowField.isAccessible = true
            listPopupWindow = mPopupWindowField.get(popup)

            val setForceIgnoreOutsideTouchMethod = listPopupWindow.javaClass.getDeclaredMethod("setForceIgnoreOutsideTouch", Boolean::class.javaPrimitiveType)
            setForceIgnoreOutsideTouchMethod.isAccessible = true
            setForceIgnoreOutsideTouchMethod.invoke(listPopupWindow, true)
        } catch (_: Exception) {
        }

        try {
            val setForceShowIconMethod = mPopup.javaClass.getDeclaredMethod("setForceShowIcon", Boolean::class.javaPrimitiveType)
            setForceShowIconMethod.isAccessible = true
            setForceShowIconMethod.invoke(mPopup, true)
        } catch (_: Exception) {}

        try {
            val setOverlapAnchorMethod = mPopup.javaClass.getDeclaredMethod("setOverlapAnchor", Boolean::class.javaPrimitiveType)
            setOverlapAnchorMethod.isAccessible = true
            setOverlapAnchorMethod.invoke(mPopup, false)
        } catch (_: Exception) {}

        listView?.let {
            it.clipToOutline = false
            it.isVerticalScrollBarEnabled = false
            it.overScrollMode = View.OVER_SCROLL_NEVER

            val padding = (8 * it.resources.displayMetrics.density).toInt()
            it.setPadding(0, padding, 0, padding)
            it.clipToPadding = false

            val baseSelector = MiuixSmoothCardDrawable.createSelectorWithOverlay(
                it.context,
                Color.TRANSPARENT,
                0f,
                false,
            )

            it.selector = object : DrawableWrapper(baseSelector) {
                override fun setBounds(left: Int, top: Int, right: Int, bottom: Int) {
                    var newTop = top
                    var newBottom = bottom

                    val firstChild = it.getChildAt(0)
                    if (firstChild != null && it.firstVisiblePosition == 0 && top == firstChild.top) {
                        newTop = kotlin.math.min(top, 0)
                    }

                    val lastChild = it.getChildAt(it.childCount - 1)
                    if (lastChild != null && it.lastVisiblePosition == it.count - 1 && bottom == lastChild.bottom) {
                        newBottom = kotlin.math.max(bottom, it.height)
                    }

                    super.setBounds(left, newTop, right, newBottom)
                }
            }
        }

        try {
            (listPopupWindow as? ListPopupWindow)?.let {
                try {
                    if (listView != null) {
                        val radiusPx = 16f * listView.context.resources.displayMetrics.density
                        var bgColor = ContextCompat.getColor(listView.context, R.color.miuix_card_normal)
                        val isNight = (listView.context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
                        if (!isNight && MonetSettings.isMonetEnabled(listView.context)) {
                            val primaryColor = listView.context.theme.resolveColor(androidx.appcompat.R.attr.colorPrimary)
                            bgColor = ColorUtils.blendARGB(bgColor, primaryColor, 0.10f)
                        }
                        it.setBackgroundDrawable(MiuixSmoothCardDrawable(radiusPx, bgColor, false))
                    }
                } catch (e: Exception) {
                    Log.e("Sui", "Failed to apply squircle background to popup menu", e)
                }

                try {
                    val popupObj = it
                    var currentClass: Class<*>? = popupObj.javaClass
                    var popupWindowField: Field? = null

                    while (currentClass != null) {
                        try {
                            val field = currentClass.getDeclaredField("mPopup")
                            if (field.type == PopupWindow::class.java) {
                                popupWindowField = field
                                break
                            }
                        } catch (_: NoSuchFieldException) {}
                        currentClass = currentClass.superclass
                    }

                    if (popupWindowField != null) {
                        popupWindowField.isAccessible = true
                        val internalPopupWindow = popupWindowField.get(popupObj) as? PopupWindow

                        internalPopupWindow?.let { pw ->
                            pw.isClippingEnabled = false
                            try {
                                val setIsLaidOutInScreen = pw.javaClass.getMethod("setIsLaidOutInScreen", Boolean::class.javaPrimitiveType)
                                setIsLaidOutInScreen.invoke(pw, true)
                            } catch (_: Exception) {}

                            pw.contentView?.let { cv ->
                                cv.outlineProvider = MiuixSquircleProvider(16f)
                                cv.clipToOutline = true
                            }
                        }
                    }
                } catch (_: Exception) {}

                val showMethod = it.javaClass.getMethod("show")
                showMethod.invoke(it)
            }
        } catch (_: Exception) {}
    } catch (e: Exception) {
        Log.e("Sui", "Failed to apply Miuix style to PopupMenu", e)
    }
}

fun PopupMenu.colorCheckedItemsMiuixBlue(context: Context) {
    val highlightColor = context.theme.resolveColor(R.attr.colorPrimary)
    val menu = this.menu
    for (i in 0 until menu.size) {
        val item = menu[i]
        if (item.isChecked) {
            val title = item.title?.toString() ?: continue
            val spannable = SpannableString(title)
            spannable.setSpan(
                ForegroundColorSpan(highlightColor),
                0,
                spannable.length,
                Spannable.SPAN_INCLUSIVE_INCLUSIVE,
            )
            spannable.setSpan(
                StyleSpan(Typeface.BOLD),
                0,
                spannable.length,
                Spannable.SPAN_INCLUSIVE_INCLUSIVE,
            )
            item.title = spannable
        }
    }
}

object MiuixPopupDimOverlay {
    private var currentOverlayRef: WeakReference<View>? = null
    private var showCount = 0

    fun show(activity: Activity) {
        showCount++
        var overlay = currentOverlayRef?.get()

        if (overlay == null || overlay.context != activity) {
            overlay?.let { (it.parent as? ViewGroup)?.removeView(it) }

            overlay = View(activity).apply {
                layoutParams = ViewGroup.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.MATCH_PARENT,
                )
                val isDark = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
                setBackgroundColor(if (isDark) "#99000000".toColorInt() else "#4D000000".toColorInt())
                alpha = 0f
            }
            currentOverlayRef = WeakReference(overlay)

            val decorView = activity.window.decorView as ViewGroup
            decorView.addView(overlay)
        }

        overlay.animate().cancel()
        overlay.animate().alpha(1f).setDuration(250).setInterpolator(DecelerateInterpolator(1.5f)).start()
    }

    fun hide() {
        showCount--
        if (showCount > 0) return
        if (showCount < 0) showCount = 0

        val overlay = currentOverlayRef?.get() ?: return

        overlay.animate().cancel()
        overlay.animate().alpha(0f).setDuration(250).setInterpolator(DecelerateInterpolator(1.5f)).withEndAction {
            if (showCount <= 0) {
                (overlay.parent as? ViewGroup)?.removeView(overlay)
                if (currentOverlayRef?.get() == overlay) {
                    currentOverlayRef = null
                }
            }
        }.start()
    }

    fun cleanUp() {
        showCount = 0
        val overlay = currentOverlayRef?.get()
        overlay?.animate()?.cancel()
        (overlay?.parent as? ViewGroup)?.removeView(overlay)
        currentOverlayRef = null
    }
}
