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
package rikka.sui.widget;

import android.animation.ValueAnimator;
import android.content.Context;
import android.util.AttributeSet;
import android.view.animation.DecelerateInterpolator;
import com.google.android.material.button.MaterialButton;

public class MaterialExpressiveButton extends MaterialButton {

    private static final int PRESS_DURATION_MS = 160;
    private static final int RELEASE_DURATION_MS = 220;

    private final int normalCornerRadius;
    private final int pressedCornerRadius;
    private ValueAnimator cornerAnimator;
    private int targetCornerRadius;
    private boolean ready;

    public MaterialExpressiveButton(Context context, AttributeSet attrs) {
        super(context, attrs);
        float density = getResources().getDisplayMetrics().density;
        normalCornerRadius = Math.round(20f * density);
        pressedCornerRadius = Math.round(12f * density);
        setCornerRadius(normalCornerRadius);
        targetCornerRadius = normalCornerRadius;
        ready = true;
    }

    @Override
    protected void drawableStateChanged() {
        super.drawableStateChanged();
        if (!ready) return;

        int target = isPressed() && isEnabled() ? pressedCornerRadius : normalCornerRadius;
        if (targetCornerRadius == target) return;
        targetCornerRadius = target;

        if (cornerAnimator != null) {
            cornerAnimator.cancel();
            cornerAnimator = null;
        }
        if (getCornerRadius() == target) return;
        cornerAnimator = ValueAnimator.ofInt(getCornerRadius(), target);
        cornerAnimator.setDuration(target == pressedCornerRadius ? PRESS_DURATION_MS : RELEASE_DURATION_MS);
        cornerAnimator.setInterpolator(new DecelerateInterpolator());
        cornerAnimator.addUpdateListener(animation -> setCornerRadius((int) animation.getAnimatedValue()));
        cornerAnimator.start();
    }

    @Override
    protected void onDetachedFromWindow() {
        if (cornerAnimator != null) {
            cornerAnimator.cancel();
            cornerAnimator = null;
        }
        setCornerRadius(normalCornerRadius);
        targetCornerRadius = normalCornerRadius;
        super.onDetachedFromWindow();
    }
}
