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
import rikka.sui.management.ManagementFragment

class DebugActivity : AppCompatActivity() {
    companion object {
        init {
            AppCompatDelegate.setCompatVectorFromResourcesEnabled(true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        com.google.android.material.color.DynamicColors
            .applyToActivityIfAvailable(this)
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)

        setContentView(R.layout.appbar_fragment_activity)

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
