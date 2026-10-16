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

import com.materialkolor.hct.Hct;
import com.materialkolor.palettes.TonalPalette;

public final class MaterialTonalColors {

    // Tonal Spot / spec_2025 (phone) neutral and neutral variant palettes.
    private static final double NEUTRAL_CHROMA = 5.0;
    private static final double NEUTRAL_VARIANT_CHROMA = 8.5;
    private static final double DARK_CARD_TONE = 18.0;
    private static final int DARK_SURFACE_CONTAINER_TONE = 9;
    private static final int LIGHT_SURFACE_CONTAINER_TONE = 94;

    private MaterialTonalColors() {}

    public static int cardFromAccent(int accentColor) {
        double hue = Hct.Companion.fromInt(accentColor).getHue();
        return Hct.Companion.from(hue, NEUTRAL_VARIANT_CHROMA, DARK_CARD_TONE).toInt();
    }

    public static int surfaceContainerFromAccent(int accentColor, boolean dark) {
        double hue = Hct.Companion.fromInt(accentColor).getHue();
        // TonalSpot SPEC_2025 surfaceContainer: neutral T9 (dark), T94 (light).
        int tone = dark ? DARK_SURFACE_CONTAINER_TONE : LIGHT_SURFACE_CONTAINER_TONE;
        return TonalPalette.Companion.fromHueAndChroma(hue, NEUTRAL_CHROMA).tone(tone);
    }
}
