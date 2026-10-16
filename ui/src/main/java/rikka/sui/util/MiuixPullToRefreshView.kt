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

import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import androidx.core.view.animation.PathInterpolatorCompat
import rikka.sui.R
import rikka.sui.util.refresh.RefreshHeader
import rikka.sui.util.refresh.RefreshKernel
import rikka.sui.util.refresh.RefreshLayout
import rikka.sui.util.refresh.SpinnerStyle
import kotlin.math.cos
import kotlin.math.max
import kotlin.math.min
import kotlin.math.sin
import rikka.sui.util.refresh.RefreshState as SmartRefreshState

class MiuixPullToRefreshView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr),
    RefreshHeader {

    enum class RefreshState {
        IDLE,
        PULLING,
        THRESHOLD_REACHED,
        REFRESHING,
        REFRESH_COMPLETE,
    }

    var state: RefreshState = RefreshState.IDLE
        set(value) {
            if (field != value) {
                field = value
                if (value == RefreshState.REFRESHING) {
                    startRotating()
                } else {
                    stopRotating()
                }
                if (value == RefreshState.REFRESH_COMPLETE) {
                    startCompleteAnimation()
                }
                invalidate()
            }
        }

    var pullProgress: Float = 0f
        set(value) {
            field = value.coerceIn(0f, 1f)
            invalidate()
        }

    var dragOffset: Float = 0f
        set(value) {
            field = value
            invalidate()
        }

    var thresholdOffset: Float = 0f
    var maxDragDistancePx: Float = 0f

    private val color = ContextCompat.getColor(context, R.color.miuix_pull_to_refresh_color)
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = this@MiuixPullToRefreshView.color
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
    }

    private var rotationAngle = 0f
    private var rotationAnimator: ValueAnimator? = null

    private var completeProgress = 0f
    private var completeAnimator: ValueAnimator? = null

    private var circleSizePx = 0f
    private var indicatorRadiusPx = 0f
    private var ringStrokeWidthPx = 0f

    private val arcRectF = RectF()

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        circleSizePx = resources.getDimension(R.dimen.miuix_pull_to_refresh_circle_size)
        ringStrokeWidthPx = circleSizePx / 11f
        indicatorRadiusPx = max(circleSizePx / 2f, circleSizePx / 3.5f)
        paint.strokeWidth = ringStrokeWidthPx
    }

    @SuppressLint("UseKtx")
    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (state == RefreshState.IDLE) return

        val visibleHeight = dragOffset.coerceAtLeast(0f)
        if (visibleHeight <= 0f) return

        canvas.save()
        val clipBottom = (visibleHeight + ringStrokeWidthPx).coerceAtMost(height.toFloat())
        canvas.clipRect(0f, 0f, width.toFloat(), clipBottom)

        val safePadding = resources.getDimension(R.dimen.miuix_pull_to_refresh_safe_padding)
        val cx = width / 2f

        val drawRadius = indicatorRadiusPx.coerceAtMost(dragOffset / 2f)

        val idealCy = (dragOffset / 2f).coerceAtLeast(drawRadius + safePadding)

        val cy = idealCy.coerceAtMost((dragOffset - drawRadius).coerceAtLeast(0f))

        paint.color = color

        when (state) {
            RefreshState.PULLING -> {
                val alphaF = if (pullProgress > 0.6f) (pullProgress - 0.5f) * 2f else 0f
                paint.alpha = (alphaF * 255).toInt()
                canvas.drawCircle(cx, cy, drawRadius, paint)
            }

            RefreshState.THRESHOLD_REACHED, RefreshState.REFRESHING -> {
                paint.alpha = 255
                val overDrag = (dragOffset - thresholdOffset).coerceAtLeast(0f)

                val availableTop = (cy - drawRadius - safePadding).coerceAtLeast(0f)
                val availableBottom = (visibleHeight - cy - drawRadius).coerceAtLeast(0f)
                val maxLineLength = (min(availableTop, availableBottom) * 2f).coerceAtLeast(0f)
                val lineLength = overDrag.coerceAtMost(maxLineLength)

                if (lineLength > 0f) {
                    val topY = cy - lineLength / 2f
                    val bottomY = cy + lineLength / 2f

                    arcRectF.set(
                        cx - drawRadius,
                        topY - drawRadius,
                        cx + drawRadius,
                        bottomY + drawRadius,
                    )
                    canvas.drawRoundRect(arcRectF, drawRadius, drawRadius, paint)
                } else {
                    canvas.drawCircle(cx, cy, drawRadius, paint)
                }

                if (state == RefreshState.REFRESHING && lineLength <= 0f) {
                    val scaleRatio = drawRadius / indicatorRadiusPx
                    val orbitRadius = drawRadius - 2 * ringStrokeWidthPx * scaleRatio
                    val currentStroke = ringStrokeWidthPx * scaleRatio

                    val angleRad = (rotationAngle - 90f) * (Math.PI / 180.0)
                    val dotCx = cx + (orbitRadius * cos(angleRad)).toFloat()
                    val dotCy = cy + (orbitRadius * sin(angleRad)).toFloat()

                    paint.style = Paint.Style.FILL
                    canvas.drawCircle(dotCx, dotCy, currentStroke, paint)
                    paint.style = Paint.Style.STROKE
                }
            }

            RefreshState.REFRESH_COMPLETE -> {
                val alphaF = (1f - (completeProgress * 2f)).coerceIn(0f, 1f)
                paint.alpha = (alphaF * 255).toInt()

                val animatedRadius = drawRadius * (1f - (completeProgress * 0.1f))
                canvas.drawCircle(cx, cy, animatedRadius, paint)
            }

            RefreshState.IDLE -> {}
        }

        canvas.restore()
    }

    private fun startRotating() {
        if (rotationAnimator?.isRunning == true) return
        rotationAngle = 0f
        rotationAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 1000
            interpolator = LinearInterpolator()
            repeatCount = ValueAnimator.INFINITE
            addUpdateListener {
                rotationAngle = (it.animatedValue as Float) * 360f
                if (state == RefreshState.REFRESHING) {
                    invalidate()
                }
            }
            start()
        }
    }

    private fun stopRotating() {
        rotationAnimator?.cancel()
        rotationAnimator = null
    }

    private fun startCompleteAnimation() {
        completeAnimator?.cancel()
        completeProgress = 0f

        val cubicBezierInterpolator = PathInterpolatorCompat.create(0f, 0f, 0f, 0.37f)

        completeAnimator = ValueAnimator.ofFloat(0f, 1f).apply {
            duration = 300
            interpolator = cubicBezierInterpolator
            addUpdateListener {
                completeProgress = it.animatedValue as Float
                invalidate()
            }
            start()
        }
    }

    override fun getView(): View = this

    override fun getSpinnerStyle(): SpinnerStyle = SpinnerStyle.Translate

    @SuppressLint("RestrictedApi")
    override fun setPrimaryColors(vararg colors: Int) {}

    @SuppressLint("RestrictedApi")
    override fun onInitialized(kernel: RefreshKernel, height: Int, maxDragHeight: Int) {
        thresholdOffset = height.toFloat()
        maxDragDistancePx = maxDragHeight.toFloat()
    }

    @SuppressLint("RestrictedApi")
    override fun onMoving(isDragging: Boolean, percent: Float, offset: Int, height: Int, maxDragHeight: Int) {
        dragOffset = offset.toFloat()
        pullProgress = percent

        if (isDragging && state != RefreshState.REFRESHING && state != RefreshState.REFRESH_COMPLETE) {
            state = if (offset >= height) {
                RefreshState.THRESHOLD_REACHED
            } else {
                RefreshState.PULLING
            }
        }
    }

    @SuppressLint("RestrictedApi")
    override fun onReleased(refreshLayout: RefreshLayout, height: Int, maxDragHeight: Int) {
    }

    @SuppressLint("RestrictedApi")
    override fun onStartAnimator(refreshLayout: RefreshLayout, height: Int, maxDragHeight: Int) {
        state = RefreshState.REFRESHING
    }

    @SuppressLint("RestrictedApi")
    override fun onFinish(refreshLayout: RefreshLayout, success: Boolean): Int {
        state = RefreshState.REFRESH_COMPLETE
        return 300
    }

    @SuppressLint("RestrictedApi")
    override fun onHorizontalDrag(percentX: Float, offsetX: Int, offsetMax: Int) {}

    override fun isSupportHorizontalDrag(): Boolean = false

    override fun autoOpen(duration: Int, dragRate: Float, animationOnly: Boolean): Boolean = false

    @SuppressLint("RestrictedApi")
    override fun onStateChanged(refreshLayout: RefreshLayout, oldState: SmartRefreshState, newState: SmartRefreshState) {
        when (newState) {
            SmartRefreshState.None, SmartRefreshState.PullDownToRefresh -> state = RefreshState.IDLE
            SmartRefreshState.ReleaseToRefresh -> state = RefreshState.THRESHOLD_REACHED
            SmartRefreshState.Refreshing -> state = RefreshState.REFRESHING
        }
    }
}
