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

public final class UiStyleSettings {

    public interface SyncCallback {
        void onSynced(boolean changed);
    }

    public static final String MIUIX = "miuix";
    public static final String MATERIAL = "material";

    private static final String PREFS_NAME = "sui_settings";
    private static final String KEY_UI_STYLE = "ui_style";
    private static final String KEY_MATERIAL_DYNAMIC_COLOR = "material_dynamic_color_enabled";

    private UiStyleSettings() {}

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext().getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    public static String getStyle(Context context) {
        return MATERIAL.equals(prefs(context).getString(KEY_UI_STYLE, MIUIX)) ? MATERIAL : MIUIX;
    }

    public static boolean isMaterial(Context context) {
        return MATERIAL.equals(getStyle(context));
    }

    public static void setStyle(Context context, String style) {
        prefs(context)
                .edit()
                .putString(KEY_UI_STYLE, MATERIAL.equals(style) ? MATERIAL : MIUIX)
                .apply();
    }

    public static boolean isMaterialDynamicColorEnabled(Context context) {
        return prefs(context).getBoolean(KEY_MATERIAL_DYNAMIC_COLOR, true);
    }

    public static void setMaterialDynamicColorEnabled(Context context, boolean enabled) {
        prefs(context).edit().putBoolean(KEY_MATERIAL_DYNAMIC_COLOR, enabled).apply();
    }

    // The permission dialog runs in SystemUI. The server owns the shared style bits.
    public static boolean updateServer(String style, boolean materialDynamicColorEnabled) {
        int mask = BridgeServiceClient.FLAG_UI_MATERIAL | BridgeServiceClient.FLAG_MATERIAL_DYNAMIC_DISABLED;
        int value = (MATERIAL.equals(style) ? BridgeServiceClient.FLAG_UI_MATERIAL : 0)
                | (materialDynamicColorEnabled ? 0 : BridgeServiceClient.FLAG_MATERIAL_DYNAMIC_DISABLED);
        return BridgeServiceClient.updateGlobalSettings(mask, value);
    }

    public static boolean syncFromServer(Context context) {
        Integer flags = BridgeServiceClient.getGlobalSettingsOrNull();
        if (flags == null) return false;
        String style = (flags & BridgeServiceClient.FLAG_UI_MATERIAL) != 0 ? MATERIAL : MIUIX;
        boolean dynamic = (flags & BridgeServiceClient.FLAG_MATERIAL_DYNAMIC_DISABLED) == 0;
        boolean changed = !style.equals(getStyle(context)) || dynamic != isMaterialDynamicColorEnabled(context);
        if (changed) {
            prefs(context)
                    .edit()
                    .putString(KEY_UI_STYLE, style)
                    .putBoolean(KEY_MATERIAL_DYNAMIC_COLOR, dynamic)
                    .apply();
        }
        return changed;
    }

    public static void syncFromServerAsync(Context context, SyncCallback callback) {
        Context appContext = context.getApplicationContext();
        new Thread(
                        () -> {
                            boolean changed = syncFromServer(appContext);
                            if (callback != null) callback.onSynced(changed);
                        },
                        "Sui-ui-style-sync")
                .start();
    }
}
