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

package rikka.sui.app;

import android.app.Application;
import android.content.ComponentName;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.activity.EdgeToEdge;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.graphics.ColorUtils;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.color.DynamicColors;
import rikka.sui.R;
import rikka.sui.ktx.ResourcesKt;
import rikka.sui.util.MonetSettings;

public class AppActivity extends AppCompatActivity {

    private final Application application;
    private final Resources resources;
    private final ComponentName componentName;

    private ViewGroup rootView;
    private ViewGroup toolbarContainer;

    public AppActivity(Application application, Resources resources, ComponentName componentName) {
        this.application = application;
        this.resources = resources;
        this.componentName = componentName;
    }

    @Override
    public Context getApplicationContext() {
        return application;
    }

    @Override
    public ClassLoader getClassLoader() {
        return AppActivity.class.getClassLoader();
    }

    @Override
    public Resources getResources() {
        return resources;
    }

    @Override
    public ComponentName getComponentName() {
        return componentName;
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        setTheme(R.style.Theme_Sui);

        final boolean monetEnabled = MonetSettings.isMonetEnabled(this);
        MonetSettings.syncFromServerAsync(this, (changed, enabled) -> {
            if (!changed) {
                return;
            }
            runOnUiThread(() -> {
                if (!isFinishing() && !isDestroyed()) {
                    recreate();
                }
            });
        });
        if (monetEnabled) {
            DynamicColors.applyToActivityIfAvailable(this);
        }

        super.onCreate(savedInstanceState);

        try {
            super.setContentView(R.layout.appbar_fragment_activity);

            rootView = findViewById(R.id.root);
            toolbarContainer = findViewById(R.id.toolbar_container);
            Toolbar toolbar = findViewById(R.id.toolbar);

            if (toolbar != null) {
                setSupportActionBar(toolbar);
            } else {
                android.util.Log.e("Sui", "Toolbar not found in appbar_fragment_activity layout");
            }

            ViewCompat.setOnApplyWindowInsetsListener(toolbarContainer, (v, insets) -> {
                int statusBarHeight = insets.getInsets(WindowInsetsCompat.Type.systemBars()).top;
                v.setPadding(v.getPaddingLeft(), statusBarHeight, v.getPaddingRight(), v.getPaddingBottom());
                return insets;
            });

            EdgeToEdge.enable(this);

            boolean isNight = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                    == Configuration.UI_MODE_NIGHT_YES;
            if (isNight && monetEnabled) {
                int primaryColor = ResourcesKt.resolveColor(getTheme(), androidx.appcompat.R.attr.colorPrimary);
                int blendedBg = ColorUtils.blendARGB(Color.BLACK, primaryColor, 0.10f);
                rootView.setBackgroundColor(blendedBg);
                if (toolbarContainer != null) {
                    toolbarContainer.setBackgroundColor(blendedBg);
                }
                getWindow().setBackgroundDrawable(new ColorDrawable(blendedBg));
            }
        } catch (Throwable t) {
            android.util.Log.e("Sui", "Fatal error in AppActivity.onCreate", t);
        }
    }

    @Override
    public void setContentView(int layoutResID) {
        getLayoutInflater().inflate(layoutResID, rootView, true);
    }

    public void setContentView(@Nullable View view) {
        setContentView(
                view,
                new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    public void setContentView(@Nullable View view, @Nullable ViewGroup.LayoutParams params) {
        rootView.addView(view, 0, params);
    }
}
