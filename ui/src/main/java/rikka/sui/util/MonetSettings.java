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

package rikka.sui.util;

import android.content.Context;
import android.content.SharedPreferences;

public final class MonetSettings {

    private static final String PREFS_NAME = "sui_settings";
    private static final String KEY_MONET_ENABLED = "monet_enabled";

    public interface SyncCallback {
        void onMonetStateSynced(boolean changed, boolean enabled);
    }

    private MonetSettings() {}

    private static SharedPreferences getPrefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static boolean isMonetEnabled(Context context) {
        return getPrefs(context).getBoolean(KEY_MONET_ENABLED, false);
    }

    public static void setMonetEnabled(Context context, boolean enabled) {
        getPrefs(context).edit().putBoolean(KEY_MONET_ENABLED, enabled).apply();
    }

    public static boolean syncFromServer(Context context) {
        SharedPreferences prefs = getPrefs(context);
        Integer flags = BridgeServiceClient.getGlobalSettingsOrNull();
        if (flags == null) {
            return prefs.getBoolean(KEY_MONET_ENABLED, false);
        }

        boolean enabled = (flags & BridgeServiceClient.FLAG_MONET_DISABLED) == 0;
        setMonetEnabled(context, enabled);
        return enabled;
    }

    public static void syncFromServerAsync(Context context) {
        syncFromServerAsync(context, null);
    }

    public static void syncFromServerAsync(Context context, SyncCallback callback) {
        Context appContext = context.getApplicationContext();
        SharedPreferences prefs = getPrefs(appContext);
        boolean cachedEnabled = prefs.getBoolean(KEY_MONET_ENABLED, false);
        new Thread(
                        () -> {
                            boolean syncedEnabled = syncFromServer(appContext);
                            if (callback != null) {
                                callback.onMonetStateSynced(cachedEnabled != syncedEnabled, syncedEnabled);
                            }
                        },
                        "SuiMonetSync")
                .start();
    }
}
