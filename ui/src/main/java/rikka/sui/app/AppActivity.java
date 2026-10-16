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
import android.graphics.drawable.ColorDrawable;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.activity.EdgeToEdge;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import com.google.android.material.color.DynamicColors;
import com.google.android.material.color.MaterialColors;
import rikka.sui.R;
import rikka.sui.util.MaterialTonalColors;
import rikka.sui.util.MiuixTonalColors;
import rikka.sui.util.MonetSettings;
import rikka.sui.util.UiDebugMode;
import rikka.sui.util.UiStyleSettings;

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
        if (!UiDebugMode.ENABLED) {
            UiStyleSettings.syncFromServerAsync(this, changed -> {
                if (changed) {
                    runOnUiThread(() -> {
                        if (!isFinishing() && !isDestroyed()) recreate();
                    });
                }
            });
        }
        final boolean materialUi = UiStyleSettings.isMaterial(this);
        setTheme(materialUi ? R.style.Theme_Sui_Material : R.style.Theme_Sui);

        final boolean monetEnabled =
                materialUi ? UiStyleSettings.isMaterialDynamicColorEnabled(this) : MonetSettings.isMonetEnabled(this);
        if (!materialUi && !UiDebugMode.ENABLED) {
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
        }
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

            if (materialUi) {
                int accent = MaterialColors.getColor(rootView, androidx.appcompat.R.attr.colorAccent);
                boolean dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                        == Configuration.UI_MODE_NIGHT_YES;
                int background = MaterialTonalColors.surfaceContainerFromAccent(accent, dark);
                rootView.setBackgroundColor(background);
                toolbarContainer.setBackgroundColor(background);
                if (toolbar != null) {
                    toolbar.setBackgroundColor(background);
                }
                getWindow().setBackgroundDrawable(new ColorDrawable(background));
            }

            if (!materialUi && monetEnabled) {
                int accent = MaterialColors.getColor(rootView, androidx.appcompat.R.attr.colorAccent);
                boolean dark = (getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                        == Configuration.UI_MODE_NIGHT_YES;
                int surface = MiuixTonalColors.fromAccent(accent, dark).surface;
                rootView.setBackgroundColor(surface);
                toolbarContainer.setBackgroundColor(surface);
                if (toolbar != null) {
                    toolbar.setBackgroundColor(surface);
                }
                getWindow().setBackgroundDrawable(new ColorDrawable(surface));
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
