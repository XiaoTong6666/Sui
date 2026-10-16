package rikka.sui.widget

import android.animation.ValueAnimator
import android.annotation.SuppressLint
import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF
import android.util.AttributeSet
import android.view.MotionEvent
import android.view.View
import android.view.animation.DecelerateInterpolator
import androidx.core.content.ContextCompat
import rikka.sui.R

class MiuixDragHandleView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : View(context, attrs, defStyleAttr) {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = ContextCompat.getColor(context, R.color.miuix_drag_handle_color)
        style = Paint.Style.FILL
    }

    private var currentWidth = resources.getDimension(R.dimen.miuix_drag_handle_default_width)
    private var currentScaleY = 1f
    private var isPressing = false

    private val rectF = RectF()

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val w = resources.getDimension(R.dimen.miuix_drag_handle_pressed_width).toInt()
        val h = (resources.getDimension(R.dimen.miuix_drag_handle_default_height) * 1.5f).toInt()
        setMeasuredDimension(
            resolveSize(w, widthMeasureSpec),
            resolveSize(h, heightMeasureSpec),
        )
    }

    override fun onDraw(canvas: Canvas) {
        val cx = width / 2f
        val cy = height / 2f
        val w = currentWidth / 2f
        val h = resources.getDimension(R.dimen.miuix_drag_handle_default_height) / 2f * currentScaleY
        val radius = h

        rectF.set(cx - w, cy - h, cx + w, cy + h)
        paint.alpha = if (isPressing) (255 * 0.35f).toInt() else (255 * 0.2f).toInt()

        canvas.drawRoundRect(rectF, radius, radius, paint)
    }

    @SuppressLint("ClickableViewAccessibility")
    override fun onTouchEvent(event: MotionEvent): Boolean = when (event.actionMasked) {
        MotionEvent.ACTION_DOWN -> {
            isPressing = true
            animateTo(resources.getDimension(R.dimen.miuix_drag_handle_pressed_width), 1.15f, 100L)
            true
        }

        MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
            isPressing = false
            animateTo(resources.getDimension(R.dimen.miuix_drag_handle_default_width), 1f, 150L)
            true
        }

        else -> super.onTouchEvent(event)
    }

    private fun animateTo(targetWidth: Float, targetScaleY: Float, duration: Long) {
        ValueAnimator.ofFloat(currentWidth, targetWidth).apply {
            this.duration = duration
            interpolator = DecelerateInterpolator(1.5f)
            addUpdateListener {
                currentWidth = it.animatedValue as Float
                invalidate()
            }
            start()
        }
        ValueAnimator.ofFloat(currentScaleY, targetScaleY).apply {
            this.duration = duration
            interpolator = DecelerateInterpolator(1.5f)
            addUpdateListener {
                currentScaleY = it.animatedValue as Float
                invalidate()
            }
            start()
        }
    }
}
