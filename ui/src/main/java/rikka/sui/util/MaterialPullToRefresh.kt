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

import android.graphics.Canvas
import android.view.HapticFeedbackConstants
import android.view.MotionEvent
import android.view.ViewConfiguration
import android.widget.EdgeEffect
import androidx.recyclerview.widget.RecyclerView

/**
 * The list stays in place while pulling for refresh. The bottom edge uses the
 * platform's stretch overscroll instead of the MIUIX translated spring.
 */
class MaterialPullToRefresh(
    private val onProgress: (Float, Boolean) -> Unit,
    private val onRefresh: () -> Unit,
) : RecyclerView.OnItemTouchListener {

    var isRefreshing = false
        private set
    private var dragging = false
    private var startY = 0f
    private var pointerId = MotionEvent.INVALID_POINTER_ID
    private var pulled = 0f
    private var thresholdReached = false

    val edgeEffectFactory = object : RecyclerView.EdgeEffectFactory() {
        override fun createEdgeEffect(view: RecyclerView, direction: Int): EdgeEffect {
            if (direction != DIRECTION_TOP) return EdgeEffect(view.context)
            // The top gesture belongs to the refresh indicator, not a spring.
            return object : EdgeEffect(view.context) {
                override fun draw(canvas: Canvas) = false
                override fun onPull(deltaDistance: Float) {}
                override fun onPull(deltaDistance: Float, displacement: Float) {}
                override fun onPullDistance(deltaDistance: Float, displacement: Float) = deltaDistance
                override fun onAbsorb(velocity: Int) {}
            }
        }
    }

    override fun onInterceptTouchEvent(rv: RecyclerView, e: MotionEvent): Boolean {
        when (e.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                pointerId = e.getPointerId(0)
                startY = e.y
                dragging = false
                pulled = 0f
                thresholdReached = false
            }

            MotionEvent.ACTION_POINTER_UP -> updatePointer(e)

            MotionEvent.ACTION_MOVE -> {
                if (isRefreshing || pointerId == MotionEvent.INVALID_POINTER_ID) return false
                val index = e.findPointerIndex(pointerId)
                if (index < 0) return false
                val y = e.getY(index)
                if (rv.canScrollVertically(-1)) {
                    startY = y
                    return false
                }
                val slop = ViewConfiguration.get(rv.context).scaledTouchSlop
                if (y - startY > slop) {
                    dragging = true
                    updatePull(rv, y, slop)
                    return true
                }
            }

            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> reset()
        }
        return false
    }

    override fun onTouchEvent(rv: RecyclerView, e: MotionEvent) {
        if (!dragging) return
        when (e.actionMasked) {
            MotionEvent.ACTION_POINTER_UP -> updatePointer(e)

            MotionEvent.ACTION_MOVE -> {
                val index = e.findPointerIndex(pointerId)
                if (index >= 0) updatePull(rv, e.getY(index), ViewConfiguration.get(rv.context).scaledTouchSlop)
            }

            MotionEvent.ACTION_UP -> {
                val trigger = pulled >= refreshThreshold(rv)
                reset()
                if (trigger) {
                    isRefreshing = true
                    onProgress(1f, true)
                    onRefresh()
                } else {
                    onProgress(0f, false)
                }
            }

            MotionEvent.ACTION_CANCEL -> {
                reset()
                onProgress(0f, false)
            }
        }
    }

    override fun onRequestDisallowInterceptTouchEvent(disallowIntercept: Boolean) {}

    fun finishRefresh() {
        isRefreshing = false
        reset()
        onProgress(0f, false)
    }

    private fun updatePull(rv: RecyclerView, y: Float, slop: Int) {
        pulled = ((y - startY - slop).coerceAtLeast(0f) * 0.65f)
        val threshold = refreshThreshold(rv)
        val reached = pulled >= threshold
        if (reached && !thresholdReached) {
            rv.performHapticFeedback(HapticFeedbackConstants.CLOCK_TICK)
        }
        thresholdReached = reached
        onProgress((pulled / threshold).coerceIn(0f, 1f), false)
    }

    private fun refreshThreshold(rv: RecyclerView) = 80f * rv.resources.displayMetrics.density

    private fun updatePointer(event: MotionEvent) {
        val lifted = event.actionIndex
        if (event.getPointerId(lifted) != pointerId) return
        val replacement = if (lifted == 0) 1 else 0
        if (replacement < event.pointerCount) {
            val y = event.getY(replacement)
            startY += y - event.getY(lifted)
            pointerId = event.getPointerId(replacement)
        } else {
            pointerId = MotionEvent.INVALID_POINTER_ID
        }
    }

    private fun reset() {
        pointerId = MotionEvent.INVALID_POINTER_ID
        dragging = false
        pulled = 0f
        thresholdReached = false
    }
}
