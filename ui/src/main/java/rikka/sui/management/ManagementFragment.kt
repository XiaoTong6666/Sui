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
package rikka.sui.management

import android.graphics.Typeface
import android.os.Bundle
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.ForegroundColorSpan
import android.text.style.RelativeSizeSpan
import android.text.style.StyleSpan
import android.text.style.URLSpan
import android.util.TypedValue
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.Animation
import androidx.annotation.AttrRes
import androidx.appcompat.widget.SearchView
import androidx.core.view.MenuHost
import androidx.core.view.MenuProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.isGone
import androidx.core.view.isVisible
import androidx.lifecycle.Lifecycle
import androidx.recyclerview.widget.DefaultItemAnimator
import rikka.lifecycle.Resource
import rikka.lifecycle.Status
import rikka.lifecycle.viewModels
import rikka.recyclerview.fixEdgeEffect
import rikka.sui.R
import rikka.sui.app.AppFragment
import rikka.sui.databinding.ManagementBinding
import rikka.sui.model.AppInfo

class ManagementFragment : AppFragment() {

    private var _binding: ManagementBinding? = null
    val binding: ManagementBinding get() = _binding!!

    private val viewModel by viewModels { ManagementViewModel() }
    private val adapter by lazy { ManagementAdapter(requireContext()) }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = ManagementBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        val menuHost: MenuHost = requireActivity()
        menuHost.addMenuProvider(
            object : MenuProvider {
                override fun onCreateMenu(menu: Menu, menuInflater: MenuInflater) {
                    menuInflater.inflate(R.menu.management_menu, menu)

                    val searchItem = menu.findItem(R.id.action_search)
                    val searchView = searchItem.actionView as SearchView

                    var isSearchViewInitialized = false
                    searchView.setOnQueryTextListener(object : SearchView.OnQueryTextListener {
                        override fun onQueryTextSubmit(query: String?): Boolean = false
                        override fun onQueryTextChange(newText: String?): Boolean {
                            if (!isSearchViewInitialized && newText.isNullOrEmpty()) {
                                isSearchViewInitialized = true
                                return true
                            }
                            viewModel.filter(newText)
                            return true
                        }
                    })
                    val overflowItem = menu.findItem(R.id.action_overflow)
                    requireActivity().findViewById<View>(R.id.toolbar)?.post {
                        val overflowButtonView = requireActivity().findViewById<View>(R.id.action_overflow)
                        if (overflowButtonView != null) {
                            overflowButtonView.setOnClickListener { anchorView ->
                                showOverflowPopupMenu(anchorView)
                            }
                        } else {
                            overflowItem.setOnMenuItemClickListener {
                                showOverflowPopupMenu(requireActivity().findViewById(R.id.toolbar))
                                true
                            }
                        }
                    }
                }

                override fun onMenuItemSelected(menuItem: MenuItem): Boolean = false
            },
            viewLifecycleOwner,
            Lifecycle.State.RESUMED,
        )

        val context = view.context
        view.post {
            val parentView = view.parent as? ViewGroup
            if (parentView != null) {
                val hostPaddingLeft = parentView.paddingLeft
                val hostPaddingRight = parentView.paddingRight
                if (hostPaddingLeft > 0 || hostPaddingRight > 0) {
                    val layoutParams = view.layoutParams as? ViewGroup.MarginLayoutParams
                    if (layoutParams != null) {
                        layoutParams.leftMargin = -hostPaddingLeft
                        layoutParams.rightMargin = -hostPaddingRight
                        view.layoutParams = layoutParams
                    }
                }
            }
        }
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { _, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())

            binding.list.setPadding(
                binding.list.paddingLeft,
                0,
                binding.list.paddingRight,
                systemBars.bottom,
            )

            insets
        }
        binding.list.apply {
//            borderVisibilityChangedListener =
//                OnBorderVisibilityChangedListener { top: Boolean, _: Boolean, _: Boolean, _: Boolean ->
//                    appActivity?.appBar?.setRaised(!top)
//                }
            setHasFixedSize(true)
            adapter = this@ManagementFragment.adapter
            (itemAnimator as DefaultItemAnimator).supportsChangeAnimations = false
            fixEdgeEffect()
            this.setItemViewCacheSize(20)
            this.recycledViewPool.setMaxRecycledViews(0, 20)
            me.zhanghai.android.fastscroll.FastScrollerBuilder(this)
                .useMd2Style()
                .build()

            layoutAnimationListener = object : Animation.AnimationListener {
                override fun onAnimationStart(animation: Animation?) {}
                override fun onAnimationEnd(animation: Animation?) {}
                override fun onAnimationRepeat(animation: Animation?) {}
            }
        }

        binding.swipeRefresh.apply {
            setOnRefreshListener {
                viewModel.reload(context)
            }
            val typedValue = TypedValue()

            context.theme.resolveAttribute(androidx.appcompat.R.attr.colorAccent, typedValue, true)
            val colorAccent = typedValue.data
            setColorSchemeColors(colorAccent)

            context.theme.resolveAttribute(androidx.appcompat.R.attr.actionBarSize, typedValue, true)
            val actionBarSize = TypedValue.complexToDimensionPixelSize(typedValue.data, resources.displayMetrics)
            setProgressViewOffset(false, actionBarSize, (64 * resources.displayMetrics.density + actionBarSize).toInt())
        }

        viewModel.appList.observe(viewLifecycleOwner) {
            when (it?.status) {
                Status.LOADING -> onLoading()
                Status.SUCCESS -> onSuccess(it)
                Status.ERROR -> onError(it.error)
                else -> {}
            }
        }
        if (savedInstanceState == null) {
            viewModel.reload(requireContext())
        }
    }
    private fun showOverflowPopupMenu(anchorView: View) {
        val popupMenu = androidx.appcompat.widget.PopupMenu(requireContext(), anchorView)
        popupMenu.inflate(R.menu.overflow_popup_menu)
        popupMenu.menu.findItem(R.id.action_filter_shizuku)?.isChecked = viewModel.showOnlyShizukuApps
        popupMenu.setOnMenuItemClickListener { menuItem ->
            when (menuItem.itemId) {
                R.id.action_filter_shizuku -> {
                    menuItem.isChecked = !menuItem.isChecked
                    viewModel.toggleShizukuFilter(menuItem.isChecked, requireContext())
                    true
                }

                R.id.action_batch_unconfigured -> {
                    showBatchOptionsMenu(anchorView)
                    true
                }

                R.id.action_add_shortcut -> {
                    try {
                        rikka.sui.util.BridgeServiceClient.requestPinnedShortcut()
                        android.widget.Toast.makeText(requireContext(), "在尝试创建喵...", android.widget.Toast.LENGTH_SHORT).show()
                    } catch (e: Throwable) {
                        android.util.Log.e("SuiShortcutRPC", "Failed to request pinned shortcut via RPC", e)
                        android.widget.Toast.makeText(requireContext(), "创建失败喵: " + e.message, android.widget.Toast.LENGTH_LONG).show()
                    }
                    true
                }

                R.id.action_about -> {
                    showAboutDialog()
                    true
                }

                else -> false
            }
        }
        popupMenu.show()
    }
    private fun showBatchOptionsMenu(anchorView: View) {
        val popupMenu = androidx.appcompat.widget.PopupMenu(requireContext(), anchorView)
        popupMenu.inflate(R.menu.batch_options_menu)

        val currentDefaultMode = viewModel.appList.value?.data?.firstOrNull()?.defaultFlags
            ?.and(rikka.sui.server.SuiConfig.MASK_PERMISSION) ?: 0

        val typedValue = TypedValue()
        requireContext().theme.resolveAttribute(androidx.appcompat.R.attr.colorPrimary, typedValue, true)
        val highlightColor = typedValue.data

        val menu = popupMenu.menu
        for (i in 0 until menu.size()) {
            val item = menu.getItem(i)

            val isSelected = when (item.itemId) {
                R.id.batch_allow -> currentDefaultMode == rikka.sui.server.SuiConfig.FLAG_ALLOWED
                R.id.batch_deny -> currentDefaultMode == rikka.sui.server.SuiConfig.FLAG_DENIED
                R.id.batch_hidden -> currentDefaultMode == rikka.sui.server.SuiConfig.FLAG_HIDDEN
                R.id.batch_ask -> currentDefaultMode == 0
                else -> false
            }
            if (isSelected) {
                val spannableTitle = android.text.SpannableString(item.title)
                spannableTitle.setSpan(
                    android.text.style.ForegroundColorSpan(highlightColor),
                    0,
                    spannableTitle.length,
                    android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                spannableTitle.setSpan(
                    android.text.style.StyleSpan(android.graphics.Typeface.BOLD),
                    0,
                    spannableTitle.length,
                    android.text.Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                )

                item.title = spannableTitle
            }
        }
        popupMenu.setOnMenuItemClickListener { item ->
            val targetMode = when (item.itemId) {
                R.id.batch_allow -> rikka.sui.server.SuiConfig.FLAG_ALLOWED
                R.id.batch_deny -> rikka.sui.server.SuiConfig.FLAG_DENIED
                R.id.batch_hidden -> rikka.sui.server.SuiConfig.FLAG_HIDDEN
                R.id.batch_ask -> 0
                else -> -1
            }

            if (targetMode != -1) {
                performBatchUpdate(targetMode)
            }
            true
        }
        popupMenu.show()
    }
    private fun performBatchUpdate(targetMode: Int) {
        binding.progress.isVisible = true
        binding.list.isGone = true

        viewModel.batchUpdate(targetMode, requireContext())
    }
    private fun resolveThemeColor(@AttrRes attrRes: Int): Int {
        val typedValue = TypedValue()
        requireContext().theme.resolveAttribute(attrRes, typedValue, true)
        return typedValue.data
    }

    private fun showAboutDialog() {
        val versionName = try {
            rikka.sui.BuildConfig.VERSION_NAME
        } catch (e: Exception) {
            "Unknown"
        }
        val message = SpannableStringBuilder().apply {
            val title = "Sui\n"
            append(title)
            val typedValue = TypedValue()
            requireContext().theme.resolveAttribute(com.google.android.material.R.attr.colorOnSurface, typedValue, true)
            setSpan(RelativeSizeSpan(1.2f), 0, title.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            setSpan(StyleSpan(Typeface.BOLD), 0, title.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            setSpan(ForegroundColorSpan(typedValue.data), 0, title.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            append(getString(R.string.about_version, versionName))
            append("\n\n")
            append(getString(R.string.about_license_part1))
            val startGithub = length
            append(getString(R.string.about_license_part2))
            setSpan(URLSpan("https://github.com/XiaoTong6666/Sui"), startGithub, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            append(getString(R.string.about_license_part3))
            append("\n\n")
            append(getString(R.string.about_contributors))
        }

        com.google.android.material.dialog.MaterialAlertDialogBuilder(requireContext())
            .setMessage(message)
            .setPositiveButton(R.string.about_button_ok, null)
            .show()
            .findViewById<android.widget.TextView>(android.R.id.message)
            ?.movementMethod = LinkMovementMethod.getInstance()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }

    private fun onLoading() {
        binding.progress.isVisible = true
        binding.list.isGone = true

        binding.swipeRefresh.isRefreshing = false
        binding.swipeRefresh.isEnabled = false

        adapter.updateData(emptyList())
    }

    private fun onError(e: Throwable) {
        binding.progress.isGone = true
        binding.list.isVisible = true

        binding.swipeRefresh.isRefreshing = false
        binding.swipeRefresh.isEnabled = true
    }

    private fun onSuccess(data: Resource<List<AppInfo>?>) {
        binding.progress.isGone = true
        binding.list.isVisible = true

        binding.swipeRefresh.isRefreshing = false
        binding.swipeRefresh.isEnabled = true

        data.data?.let {
            adapter.updateData(it)

            if (it.isNotEmpty()) {
                binding.list.scheduleLayoutAnimation()
            }
        }
    }
}
