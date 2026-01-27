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
package rikka.sui;

import android.app.ActivityManager;
import android.app.Application;
import android.content.res.Resources;
import android.os.Build;
import android.os.Bundle;
import androidx.annotation.Nullable;
import java.util.Objects;
import rikka.sui.app.AppActivity;
import rikka.sui.management.ManagementFragment;

public class SuiActivity extends AppActivity {

    public SuiActivity(Application application, Resources resources) {
        super(application, resources);
    }

    @Override
    public android.content.ComponentName getComponentName() {
        return new android.content.ComponentName(
                getPackageName(), "com.android.settings.Settings$WifiSettingsActivity");
    }

    private int resolveThemeColor(@androidx.annotation.AttrRes int attrRes) {
        android.util.TypedValue typedValue = new android.util.TypedValue();
        getTheme().resolveAttribute(attrRes, typedValue, true);
        return typedValue.data;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        if (savedInstanceState != null) {
            savedInstanceState.remove("android:support:fragments");
            savedInstanceState.remove("android:fragments");
        }
        super.onCreate(savedInstanceState);
        com.google.android.material.color.DynamicColors.applyToActivityIfAvailable(this);
        setContentView(R.layout.main);
        setTitle("Sui");
        Objects.requireNonNull(getSupportActionBar()).setSubtitle(BuildConfig.VERSION_NAME);

        if (getSupportFragmentManager().findFragmentById(R.id.fragment_container) == null) {
            getSupportFragmentManager()
                    .beginTransaction()
                    .replace(R.id.fragment_container, new ManagementFragment())
                    .commit();
        }
        invalidateOptionsMenu();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU /*API33/A13*/) {
            ActivityManager.TaskDescription taskDescription = new ActivityManager.TaskDescription.Builder()
                    .setLabel("Sui")
                    .setPrimaryColor(resolveThemeColor(androidx.appcompat.R.attr.colorPrimary))
                    .build();
            setTaskDescription(taskDescription);
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P /*API28/A9*/) {
            setTaskDescription(new ActivityManager.TaskDescription(
                    "Sui", 0, resolveThemeColor(androidx.appcompat.R.attr.colorPrimary)));
        } else {
            setTaskDescription(new ActivityManager.TaskDescription("Sui"));
        }
    }
}
