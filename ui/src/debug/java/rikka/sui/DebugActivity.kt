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
package rikka.sui

import android.os.Bundle
import android.util.TypedValue
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.appcompat.widget.Toolbar
import androidx.core.graphics.drawable.toDrawable
import androidx.core.view.ViewCompat
import com.google.android.material.color.MaterialColors
import rikka.sui.management.ManagementFragment
import rikka.sui.util.MaterialTonalColors
import rikka.sui.util.MiuixTonalColors
import rikka.sui.util.MonetSettings
import rikka.sui.util.UiStyleSettings

class DebugActivity : AppCompatActivity() {
    companion object {
        init {
            AppCompatDelegate.setCompatVectorFromResourcesEnabled(true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        val materialUi = UiStyleSettings.isMaterial(this)
        setTheme(if (materialUi) R.style.Theme_Sui_Material else R.style.Theme_Sui)
        val monetEnabled = if (materialUi) UiStyleSettings.isMaterialDynamicColorEnabled(this) else MonetSettings.isMonetEnabled(this)
        if (monetEnabled) {
            com.google.android.material.color.DynamicColors
                .applyToActivityIfAvailable(this)
        }
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        setContentView(R.layout.appbar_fragment_activity)

        if (materialUi) {
            val root: android.view.View = findViewById(R.id.root)
            val accent = MaterialColors.getColor(root, androidx.appcompat.R.attr.colorAccent)
            val dark = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
                android.content.res.Configuration.UI_MODE_NIGHT_YES
            val background = MaterialTonalColors.surfaceContainerFromAccent(accent, dark)
            root.setBackgroundColor(background)
            findViewById<android.view.View>(R.id.toolbar_container).setBackgroundColor(background)
            findViewById<android.view.View>(R.id.toolbar).setBackgroundColor(background)
            window.setBackgroundDrawable(background.toDrawable())
        } else if (monetEnabled) {
            val root: android.view.View = findViewById(R.id.root)
            val accent = MaterialColors.getColor(root, androidx.appcompat.R.attr.colorAccent)
            val dark = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_NIGHT_MASK) ==
                android.content.res.Configuration.UI_MODE_NIGHT_YES
            val surface = MiuixTonalColors.fromAccent(accent, dark).surface
            root.setBackgroundColor(surface)
            findViewById<android.view.View>(R.id.toolbar_container).setBackgroundColor(surface)
            findViewById<android.view.View>(R.id.toolbar).setBackgroundColor(surface)
            window.setBackgroundDrawable(surface.toDrawable())
        }

        val toolbarContainer: android.view.ViewGroup = findViewById(R.id.toolbar_container)
        ViewCompat.setOnApplyWindowInsetsListener(toolbarContainer) { v, insets ->
            val statusBarHeight = insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.systemBars()).top
            v.setPadding(v.paddingLeft, statusBarHeight, v.paddingRight, v.paddingBottom)
            insets
        }

        val toolbar: Toolbar = findViewById(R.id.toolbar)
        setSupportActionBar(toolbar)
        try {
            val typedValue = TypedValue()
            theme.resolveAttribute(androidx.appcompat.R.attr.colorAccent, typedValue, true)
            val accentColor = typedValue.data
            val accentHex = String.format("#%06X", 0xFFFFFF and accentColor)
            val subtitleHtml = "<font color='$accentHex'>$accentHex</font>"
            val coloredSubtitle =
                androidx.core.text.HtmlCompat
                    .fromHtml(subtitleHtml, androidx.core.text.HtmlCompat.FROM_HTML_MODE_LEGACY)
            supportActionBar?.title = "Sui(Debug)"
            supportActionBar?.subtitle = coloredSubtitle
        } catch (e: Exception) {
            supportActionBar?.title = "Sui(Debug)"
        }

        if (savedInstanceState == null) {
            supportFragmentManager
                .beginTransaction()
                .replace(R.id.fragment_container, ManagementFragment())
                .commit()
        }
    }
}
