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
import android.content.res.Configuration;
import com.google.android.material.color.MaterialColors;
import com.materialkolor.dynamiccolor.ColorSpec;
import com.materialkolor.hct.Hct;
import com.materialkolor.scheme.DynamicScheme;
import com.materialkolor.scheme.SchemeTonalSpot;

public final class MiuixTonalColors {

    public static final class Palette {
        public final int primary;
        public final int surface;
        public final int surfaceContainer;
        public final int surfaceContainerHigh;

        private Palette(SchemeTonalSpot scheme) {
            primary = scheme.getPrimary();
            surface = scheme.getSurface();
            surfaceContainer = scheme.getSurfaceContainer();
            surfaceContainerHigh = scheme.getSurfaceContainerHigh();
        }
    }

    private static int cachedAccent;
    private static boolean cachedDark;
    private static Palette cachedPalette;

    private MiuixTonalColors() {}

    // Matches miuix-kmp 0.9.4: TonalSpot + SPEC_2025 on PHONE.
    public static synchronized Palette fromAccent(int accent, boolean dark) {
        if (cachedPalette == null || cachedAccent != accent || cachedDark != dark) {
            SchemeTonalSpot scheme = new SchemeTonalSpot(
                    Hct.Companion.fromInt(accent),
                    dark,
                    0.0,
                    ColorSpec.SpecVersion.SPEC_2025,
                    DynamicScheme.Platform.PHONE);
            cachedPalette = new Palette(scheme);
            cachedAccent = accent;
            cachedDark = dark;
        }
        return cachedPalette;
    }

    public static int primaryForTheme(Context context) {
        int fallback = MaterialColors.getColor(context, androidx.appcompat.R.attr.colorPrimary, 0xff277af7);
        if (!MonetSettings.isMonetEnabled(context)) {
            return fallback;
        }
        int accent = MaterialColors.getColor(context, androidx.appcompat.R.attr.colorAccent, fallback);
        boolean dark = (context.getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK)
                == Configuration.UI_MODE_NIGHT_YES;
        return fromAccent(accent, dark).primary;
    }
}
