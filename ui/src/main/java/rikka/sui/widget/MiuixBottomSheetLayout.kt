package rikka.sui.widget

import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.content.Context
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.VelocityTracker
import android.view.View
import android.view.ViewConfiguration
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import androidx.core.animation.doOnEnd
import androidx.core.view.NestedScrollingParent3
import androidx.core.view.NestedScrollingParentHelper
import androidx.core.view.ViewCompat
import rikka.sui.R
import kotlin.math.abs

class MiuixBottomSheetLayout @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : FrameLayout(context, attrs, defStyleAttr),
    NestedScrollingParent3 {

    private val parentHelper = NestedScrollingParentHelper(this)
    private var dragOffsetY = 0f

    private val touchSlop = ViewConfiguration.get(context).scaledTouchSlop
    private val maximumVelocity = ViewConfiguration.get(context).scaledMaximumFlingVelocity.toFloat()

    private var velocityTracker: VelocityTracker? = null
    private var isDragging = false
    private var lastY = 0f

    var onDismissRequest: (() -> Unit)? = null
    var isDismissing = false

    var onDimAlphaChange: ((Float) -> Unit)? = null
    var onDimAlphaAnimate: ((Float, Long) -> Unit)? = null

    @get:SuppressLint("UseKtx")
    private val sheet: View? get() = if (childCount > 0) getChildAt(0) else null

    init {
        // Dim overlay is now hosted in the Activity's DecorView via MiuixBottomSheetDialog
    }

    fun show() {
        onDimAlphaChange?.invoke(0f)
        onDimAlphaAnimate?.invoke(1f, 250L)

        sheet?.visibility = View.INVISIBLE
        post {
            sheet?.let {
                it.visibility = View.VISIBLE
                it.translationY = it.height.toFloat()
                ValueAnimator.ofFloat(it.translationY, 0f).apply {
                    duration = 250
                    interpolator = DecelerateInterpolator(1.5f)
                    addUpdateListener { anim ->
                        it.translationY = anim.animatedValue as Float
                    }
                    start()
                }
            }
        }
    }

    fun dismiss() {
        if (isDismissing) return
        isDismissing = true
        onDimAlphaAnimate?.invoke(0f, 250L)

        sheet?.let {
            ValueAnimator.ofFloat(it.translationY, it.height.toFloat()).apply {
                duration = 250
                interpolator = DecelerateInterpolator(1.5f)
                addUpdateListener { anim ->
                    it.translationY = anim.animatedValue as Float
                }
                doOnEnd { onDismissRequest?.invoke() }
                start()
            }
        } ?: run {
            onDismissRequest?.invoke()
        }
    }

    override fun onInterceptTouchEvent(ev: MotionEvent): Boolean {
        if (isDismissing) return false

        when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                val s = sheet
                if (s != null && ev.y < s.top + s.translationY) {
                    dismiss()
                    return true
                }
                lastY = ev.y
                velocityTracker = VelocityTracker.obtain()
                velocityTracker?.addMovement(ev)
            }

            MotionEvent.ACTION_MOVE -> {
                velocityTracker?.addMovement(ev)
                val dy = ev.y - lastY
                if (abs(dy) > touchSlop) {
                    isDragging = true
                    lastY = ev.y
                    return true
                }
            }

            MotionEvent.ACTION_CANCEL, MotionEvent.ACTION_UP -> {
                velocityTracker?.recycle()
                velocityTracker = null
                isDragging = false
            }
        }
        return super.onInterceptTouchEvent(ev)
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (isDismissing) return false

        velocityTracker?.addMovement(event)
        when (event.actionMasked) {
            MotionEvent.ACTION_MOVE -> {
                val dy = event.y - lastY
                lastY = event.y

                var newOffset = dragOffsetY + dy
                setDragOffset(newOffset)
            }

            MotionEvent.ACTION_UP -> {
                velocityTracker?.computeCurrentVelocity(1000, maximumVelocity)
                val velocityY = velocityTracker?.yVelocity ?: 0f
                handleSettle(velocityY)
                velocityTracker?.recycle()
                velocityTracker = null
                isDragging = false
            }

            MotionEvent.ACTION_CANCEL -> {
                handleSettle(0f)
                velocityTracker?.recycle()
                velocityTracker = null
                isDragging = false
            }
        }
        return true
    }

    private fun setDragOffset(offset: Float) {
        dragOffsetY = offset.coerceAtLeast(0f)
        sheet?.translationY = dragOffsetY

        val sh = sheet?.height?.toFloat() ?: 500f
        val dimAlpha = 1f - (dragOffsetY / sh).coerceIn(0f, 1f)
        onDimAlphaChange?.invoke(dimAlpha)
    }

    private fun handleSettle(velocityY: Float) {
        val windowHeightPx = height.toFloat()
        val sheetHeightPx = sheet?.height?.toFloat() ?: windowHeightPx
        val dismissThresholdPx = resources.getDimension(R.dimen.miuix_bottom_sheet_dismiss_threshold)
        val velocityThresholdPx = resources.getDimension(R.dimen.miuix_bottom_sheet_velocity_threshold)

        val shouldDismiss = (velocityY > velocityThresholdPx) ||
            (dragOffsetY > dismissThresholdPx && velocityY > -velocityThresholdPx)

        if (shouldDismiss) {
            isDismissing = true
            val targetDuration = if (velocityY > 100f) {
                ((sheetHeightPx - dragOffsetY) * 2 / velocityY * 1000).toInt().coerceIn(150, 450)
            } else {
                250
            }

            ValueAnimator.ofFloat(dragOffsetY, sheetHeightPx).apply {
                duration = targetDuration.toLong()
                interpolator = DecelerateInterpolator(1.5f)
                addUpdateListener { setDragOffset(it.animatedValue as Float) }
                doOnEnd { onDismissRequest?.invoke() }
                start()
            }
            onDimAlphaAnimate?.invoke(0f, targetDuration.toLong())
        } else {
            ValueAnimator.ofFloat(dragOffsetY, 0f).apply {
                duration = 250
                interpolator = DecelerateInterpolator(1.5f)
                addUpdateListener { setDragOffset(it.animatedValue as Float) }
                start()
            }
        }
    }

    override fun onStartNestedScroll(child: View, target: View, axes: Int, type: Int): Boolean = axes and ViewCompat.SCROLL_AXIS_VERTICAL != 0

    override fun onNestedScrollAccepted(child: View, target: View, axes: Int, type: Int) {
        parentHelper.onNestedScrollAccepted(child, target, axes, type)
    }

    override fun onStopNestedScroll(target: View, type: Int) {
        parentHelper.onStopNestedScroll(target, type)
        handleSettle(0f)
    }

    override fun onNestedScroll(
        target: View,
        dxConsumed: Int,
        dyConsumed: Int,
        dxUnconsumed: Int,
        dyUnconsumed: Int,
        type: Int,
        consumed: IntArray,
    ) {
        if (dyUnconsumed < 0) {
            val dy = -dyUnconsumed.toFloat()
            setDragOffset(dragOffsetY + dy)
            consumed[1] = dyUnconsumed
        }
    }

    override fun onNestedScroll(
        target: View,
        dxConsumed: Int,
        dyConsumed: Int,
        dxUnconsumed: Int,
        dyUnconsumed: Int,
        type: Int,
    ) {}

    override fun onNestedPreScroll(target: View, dx: Int, dy: Int, consumed: IntArray, type: Int) {
        if (dragOffsetY > 0 || (dragOffsetY == 0f && dy < 0 && !target.canScrollVertically(-1))) {
            val delta = -dy.toFloat()
            val newOffset = dragOffsetY + delta
            if (newOffset >= 0) {
                setDragOffset(newOffset)
                consumed[1] = dy
            } else {
                consumed[1] = -dragOffsetY.toInt()
                setDragOffset(0f)
            }
        }
    }

    override fun onNestedPreFling(target: View, velocityX: Float, velocityY: Float): Boolean {
        if (dragOffsetY > 0) {
            handleSettle(velocityY)
            return true
        }
        return false
    }
}
