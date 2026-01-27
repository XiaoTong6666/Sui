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
import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.activity.EdgeToEdge;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import com.google.android.material.appbar.AppBarLayout;
import rikka.sui.R;

public class AppActivity extends AppCompatActivity {

    private final Application application;
    private final Resources resources;

    private ViewGroup rootView;
    private AppBarLayout toolbarContainer;

    public AppActivity(Application application, Resources resources) {
        this.application = application;
        this.resources = resources;
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
    public android.content.ComponentName getComponentName() {
        return new android.content.ComponentName(
                getPackageName(), "com.android.settings.Settings$WifiSettingsActivity");
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        setTheme(R.style.Theme_Material3_DayNight_NoActionBar);
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
            EdgeToEdge.enable(this);
        } catch (Throwable t) {
            android.util.Log.e("Sui", "Fatal error in AppActivity.onCreate", t);
        }
    }

    @Override
    public void setContentView(int layoutResID) {
        getLayoutInflater().inflate(layoutResID, rootView, true);
        rootView.bringChildToFront(toolbarContainer);
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
