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

import android.content.DialogInterface
import android.content.res.Configuration
import android.graphics.Typeface
import android.os.Bundle
import android.os.SystemClock
import android.text.Spannable
import android.text.SpannableString
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.method.LinkMovementMethod
import android.text.style.ForegroundColorSpan
import android.text.style.RelativeSizeSpan
import android.text.style.StyleSpan
import android.text.style.URLSpan
import android.view.ContextThemeWrapper
import android.view.Gravity
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.animation.DecelerateInterpolator
import android.widget.FrameLayout
import android.widget.PopupWindow
import android.widget.Toast
import androidx.appcompat.widget.PopupMenu
import androidx.appcompat.widget.SearchView
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import androidx.core.view.MenuHost
import androidx.core.view.MenuProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.get
import androidx.core.view.isGone
import androidx.core.view.isVisible
import androidx.core.view.size
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.DefaultItemAnimator
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import rikka.sui.BuildConfig
import rikka.sui.R
import rikka.sui.app.AppFragment
import rikka.sui.databinding.ManagementBinding
import rikka.sui.ktx.resolveColor
import rikka.sui.model.AppInfo
import rikka.sui.server.SuiConfig
import rikka.sui.util.BridgeServiceClient
import rikka.sui.util.EdgeDragFastScroller
import rikka.sui.util.MaterialPullToRefresh
import rikka.sui.util.MiuixBounceEdgeEffectFactory
import rikka.sui.util.MiuixPopupDimOverlay
import rikka.sui.util.MiuixPressHelper
import rikka.sui.util.MiuixPullToRefreshView
import rikka.sui.util.MiuixSmoothCardDrawable
import rikka.sui.util.MiuixSquircleUtils
import rikka.sui.util.MiuixTonalColors
import rikka.sui.util.UiStyleSettings
import rikka.sui.util.applyMiuixPopupStyle
import rikka.sui.widget.MiuixBottomSheetDialog
import rikka.sui.widget.showMaterialMenu

class ManagementFragment : AppFragment() {

    private var _binding: ManagementBinding? = null
    val binding: ManagementBinding get() = _binding!!

    private val viewModel by lazy {
        ViewModelProvider(this)[ManagementViewModel::class.java]
    }
    private val adapter by lazy { ManagementAdapter(requireContext(), viewModel.isUiDebugMode) }

    private val bounceEdgeEffectFactory by lazy {
        MiuixBounceEdgeEffectFactory {
            context?.let { viewModel.reload(it) }
        }
    }
    private val materialPullToRefresh by lazy {
        MaterialPullToRefresh(
            onProgress = { progress, refreshing -> updateMaterialPull(progress, refreshing) },
            onRefresh = { context?.let(viewModel::reload) },
        )
    }

    private var lastMenuClickTime = 0L
    private var lastPopupDismissTime = 0L
    private var overflowPopupMenu: PopupMenu? = null
    private var materialOverflowPopup: PopupWindow? = null
    private val materialUi get() = UiStyleSettings.isMaterial(requireContext())

    private fun setMaterialLoadingCentered(center: Boolean) {
        val indicator = _binding?.materialLoadingIndicator ?: return
        val params = indicator.layoutParams as FrameLayout.LayoutParams
        val gravity = if (center) Gravity.CENTER else Gravity.TOP or Gravity.CENTER_HORIZONTAL
        if (params.gravity != gravity) {
            params.gravity = gravity
            indicator.layoutParams = params
        }
        if (center) {
            indicator.translationY = 0f
            indicator.scaleX = 1f
            indicator.scaleY = 1f
            indicator.alpha = 1f
        }
    }

    private fun updateMaterialPull(progress: Float, refreshing: Boolean) {
        val indicator = _binding?.materialLoadingIndicator ?: return
        indicator.isVisible = progress > 0f || refreshing
        if (!indicator.isVisible) return

        setMaterialLoadingCentered(false)
        val fraction = progress.coerceIn(0f, 1f)
        val height = indicator.containerHeight.toFloat()
        val restingOffset = 40f * resources.displayMetrics.density
        // Slide the contained indicator down from above the list; do not translate the list.
        indicator.translationY = -height + (height + restingOffset) * fraction
        indicator.scaleX = 1f
        indicator.scaleY = 1f
        indicator.alpha = fraction.coerceAtLeast(0.15f)
    }

    private fun PopupMenu.showForUi(
        anchorView: View,
        trailingCheckIds: Set<Int> = emptySet(),
        onDismiss: () -> Unit = {},
    ) {
        if (materialUi) {
            showMaterialMenu(anchorView, endInsetDp = 20, onDismiss = onDismiss)
        } else {
            applyMiuixPopupStyle(trailingCheckIds = trailingCheckIds)
        }
    }

    private fun popupContext(overflow: Boolean = false): android.content.Context = when {
        materialUi -> requireContext()
        overflow -> ContextThemeWrapper(requireContext(), R.style.Theme_Sui_PopupMenu_OverflowRightOffset)
        else -> ContextThemeWrapper(requireContext(), R.style.Theme_Sui_PopupMenu)
    }

    private fun cancelRefreshForFastScroll() {
        if (materialUi) {
            if (!materialPullToRefresh.isRefreshing && viewModel.appList.value?.status != Status.LOADING) return
            materialPullToRefresh.finishRefresh()
            viewModel.cancelReload()
            return
        }
        if (!bounceEdgeEffectFactory.isRefreshActive() && viewModel.appList.value?.status != Status.LOADING) {
            return
        }

        bounceEdgeEffectFactory.cancelRefresh()
        binding.pullToRefreshIndicator.state = MiuixPullToRefreshView.RefreshState.IDLE
        binding.pullToRefreshIndicator.dragOffset = 0f
        binding.pullToRefreshIndicator.pullProgress = 0f
        viewModel.cancelReload()
    }

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
                    if (materialUi) {
                        overflowItem.setIcon(R.drawable.ic_more_vert_material_24)
                    }
                    requireActivity().findViewById<View>(R.id.toolbar)?.post {
                        val searchButtonView = requireActivity().findViewById<View>(R.id.action_search)
                        if (searchButtonView != null && !materialUi) {
                            searchButtonView.background = ContextCompat.getDrawable(requireContext(), R.drawable.miuix_action_icon_bg)
                            searchButtonView.setOnLongClickListener { true }
                            searchButtonView.setOnTouchListener(MiuixPressHelper())
                        }

                        val overflowButtonView = requireActivity().findViewById<View>(R.id.action_overflow)
                        if (overflowButtonView != null) {
                            if (!materialUi) {
                                overflowButtonView.background = ContextCompat.getDrawable(requireContext(), R.drawable.miuix_action_icon_bg)
                                overflowButtonView.setOnLongClickListener { true }
                                overflowButtonView.setOnTouchListener(MiuixPressHelper())
                            }
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
        val density = requireContext().resources.displayMetrics.density

        if (materialUi) binding.pullToRefreshIndicator.isGone = true

        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { _, insets ->
            val navBars = insets.getInsets(WindowInsetsCompat.Type.navigationBars())

            val basePaddingBottom = if (navBars.bottom > 0) (32f * density).toInt() else (16f * density).toInt()
            val extraPadding = Integer.max(0, navBars.bottom - basePaddingBottom)

            binding.list.setPadding(
                binding.list.paddingLeft,
                0,
                binding.list.paddingRight,
                basePaddingBottom + extraPadding,
            )

            insets
        }

        bounceEdgeEffectFactory.stateListener = object : MiuixBounceEdgeEffectFactory.PullStateChangeListener {
            override fun onPullStateChanged(dragOffset: Float, state: MiuixPullToRefreshView.RefreshState, thresholdOffset: Float, maxDragDistancePx: Float) {
                _binding?.pullToRefreshIndicator?.apply {
                    this.state = state
                    this.dragOffset = dragOffset
                    this.thresholdOffset = thresholdOffset
                    this.maxDragDistancePx = maxDragDistancePx
                    val progress = dragOffset / thresholdOffset
                    this.pullProgress = progress
                }
            }
        }

        binding.list.apply {
            setHasFixedSize(true)
            adapter = this@ManagementFragment.adapter
            (itemAnimator as DefaultItemAnimator).supportsChangeAnimations = false
            if (materialUi) {
                edgeEffectFactory = materialPullToRefresh.edgeEffectFactory
                addOnItemTouchListener(materialPullToRefresh)
            } else {
                edgeEffectFactory = bounceEdgeEffectFactory
            }
            this.setItemViewCacheSize(20)
            this.recycledViewPool.setMaxRecycledViews(0, 20)
            EdgeDragFastScroller(this) {
                cancelRefreshForFastScroll()
            }
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
        val currentTime = SystemClock.elapsedRealtime()
        if (currentTime - lastPopupDismissTime < 200 || currentTime - lastMenuClickTime < 300) {
            return
        }
        lastMenuClickTime = currentTime

        if (materialOverflowPopup != null) {
            materialOverflowPopup?.dismiss()
            materialOverflowPopup = null
            return
        }
        if (overflowPopupMenu != null) {
            overflowPopupMenu?.dismiss()
            overflowPopupMenu = null
            return
        }

        val popupMenu = PopupMenu(popupContext(overflow = true), anchorView, Gravity.END)
        if (!materialUi) overflowPopupMenu = popupMenu
        popupMenu.inflate(R.menu.overflow_popup_menu)

        anchorView.isActivated = true
        popupMenu.setOnDismissListener {
            if (!materialUi) MiuixPopupDimOverlay.hide()
            anchorView.isActivated = false
            lastPopupDismissTime = SystemClock.elapsedRealtime()
            if (overflowPopupMenu === popupMenu) {
                overflowPopupMenu = null
            }
        }
        if (!materialUi) MiuixPopupDimOverlay.show(requireActivity())

        val highlightColor = if (materialUi) {
            requireContext().theme.resolveColor(R.attr.colorPrimary)
        } else {
            MiuixTonalColors.primaryForTheme(requireContext())
        }
        val filterItem = popupMenu.menu.findItem(R.id.action_filter_shizuku)
        val isChecked = viewModel.showOnlyShizukuApps
        filterItem?.isChecked = isChecked

        filterItem?.title?.let { title ->
            val plainTitle = title.toString()
            filterItem.title = if (isChecked) {
                val ssb = SpannableString(plainTitle)
                ssb.setSpan(
                    ForegroundColorSpan(highlightColor),
                    0,
                    plainTitle.length,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                ssb
            } else {
                plainTitle
            }
        }

        val monetItem = popupMenu.menu.findItem(R.id.action_monet)
        val isMonetEnabled = if (materialUi) UiStyleSettings.isMaterialDynamicColorEnabled(requireContext()) else viewModel.isMonetEnabled
        monetItem?.isChecked = isMonetEnabled

        monetItem?.title?.let { title ->
            val plainTitle = title.toString()
            monetItem.title = if (isMonetEnabled) {
                val ssb = SpannableString(plainTitle)
                ssb.setSpan(
                    ForegroundColorSpan(highlightColor),
                    0,
                    plainTitle.length,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                ssb
            } else {
                plainTitle
            }
        }

        val legacyCompatItem = popupMenu.menu.findItem(R.id.action_legacy_shizuku_binder_compat)
        val isLegacyCompatEnabled = viewModel.isLegacyShizukuBinderCompatEnabled
        legacyCompatItem?.isChecked = isLegacyCompatEnabled

        legacyCompatItem?.title?.let { title ->
            val plainTitle = title.toString()
            legacyCompatItem.title = if (isLegacyCompatEnabled) {
                val ssb = SpannableString(plainTitle)
                ssb.setSpan(
                    ForegroundColorSpan(highlightColor),
                    0,
                    plainTitle.length,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                ssb
            } else {
                plainTitle
            }
        }

        val ksuNoEscapeItem = popupMenu.menu.findItem(R.id.action_ksu_no_escape)
        val isKsuNoEscapeEnabled = viewModel.isKsuNoEscapeEnabled
        ksuNoEscapeItem?.isChecked = isKsuNoEscapeEnabled

        ksuNoEscapeItem?.title?.let { title ->
            val plainTitle = title.toString()
            ksuNoEscapeItem.title = if (isKsuNoEscapeEnabled) {
                val ssb = SpannableString(plainTitle)
                ssb.setSpan(
                    ForegroundColorSpan(highlightColor),
                    0,
                    plainTitle.length,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                ssb
            } else {
                plainTitle
            }
        }

        val adbRootItem = popupMenu.menu.findItem(R.id.action_adb_root)
        adbRootItem?.title?.let { title ->
            val plainTitle = title.toString()
            adbRootItem.title = if (viewModel.adbRootMode != ManagementViewModel.ADB_ROOT_OFF) {
                val ssb = SpannableString(plainTitle)
                ssb.setSpan(
                    ForegroundColorSpan(highlightColor),
                    0,
                    plainTitle.length,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                ssb
            } else {
                plainTitle
            }
        }

        popupMenu.setOnMenuItemClickListener { menuItem ->
            when (menuItem.itemId) {
                R.id.action_filter_shizuku -> {
                    val newState = !viewModel.showOnlyShizukuApps
                    val context = requireContext()
                    viewModel.toggleShizukuFilter(newState, context) { success ->
                        if (!success) {
                            android.widget.Toast.makeText(context, "Failed to apply filter", android.widget.Toast.LENGTH_SHORT).show()
                        }
                    }
                    true
                }

                R.id.action_batch_unconfigured -> {
                    showBatchOptionsMenu(anchorView)
                    true
                }

                R.id.action_add_shortcut -> {
                    if (!viewModel.isUiDebugMode) {
                        try {
                            BridgeServiceClient.requestPinnedShortcut()
                            Toast.makeText(requireContext(), R.string.toast_request_shortcut, Toast.LENGTH_SHORT).show()
                        } catch (e: Throwable) {
                            android.util.Log.e("SuiShortcutRPC", "Failed to request pinned shortcut via RPC", e)
                            Toast.makeText(requireContext(), getString(R.string.toast_request_shortcut_failed, e.message), Toast.LENGTH_LONG).show()
                        }
                    }
                    true
                }

                R.id.action_about -> {
                    showAboutDialog()
                    true
                }

                R.id.action_monet -> {
                    val context = requireContext()
                    if (materialUi) {
                        val enabled = !UiStyleSettings.isMaterialDynamicColorEnabled(context)
                        viewModel.saveUiAppearance(context, UiStyleSettings.MATERIAL, enabled) { success ->
                            if (success) {
                                UiStyleSettings.setMaterialDynamicColorEnabled(context, enabled)
                                activity?.recreate()
                            } else {
                                Toast.makeText(context, "Failed to update UI settings", Toast.LENGTH_SHORT).show()
                            }
                        }
                    } else {
                        viewModel.toggleMonetSetting(context) { success ->
                            if (success) {
                                activity?.recreate()
                            } else {
                                android.widget.Toast.makeText(context, "Failed to toggle Monet", android.widget.Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                    true
                }

                R.id.action_ui_style -> {
                    showUiStyleOptionsMenu(anchorView)
                    true
                }

                R.id.action_legacy_shizuku_binder_compat -> {
                    val context = requireContext()
                    viewModel.toggleLegacyShizukuBinderCompat { success ->
                        if (!success) {
                            Toast.makeText(
                                context,
                                R.string.toast_legacy_shizuku_binder_compat_failed,
                                Toast.LENGTH_SHORT,
                            ).show()
                        }
                    }
                    true
                }

                R.id.action_ksu_no_escape -> {
                    val context = requireContext()
                    viewModel.toggleKsuNoEscape { success ->
                        Toast.makeText(
                            context,
                            if (success) {
                                R.string.toast_restart_device
                            } else {
                                R.string.toast_ksu_no_escape_failed
                            },
                            Toast.LENGTH_SHORT,
                        ).show()
                    }
                    true
                }

                R.id.action_adb_root -> {
                    showAdbRootOptionsMenu(anchorView)
                    true
                }

                else -> false
            }
        }
        if (materialUi) {
            materialOverflowPopup = popupMenu.showMaterialMenu(anchorView, endInsetDp = 20) {
                anchorView.isActivated = false
                lastPopupDismissTime = SystemClock.elapsedRealtime()
                materialOverflowPopup = null
            }
        } else {
            popupMenu.applyMiuixPopupStyle(setOf(R.id.action_batch_unconfigured, R.id.action_ui_style, R.id.action_adb_root))
        }
    }

    private fun showUiStyleOptionsMenu(anchorView: View) {
        val popupMenu = PopupMenu(popupContext(overflow = true), anchorView, Gravity.END)
        popupMenu.inflate(R.menu.ui_style_options_menu)
        val selectedId = if (materialUi) R.id.action_ui_material else R.id.action_ui_miuix
        if (materialUi) {
            popupMenu.menu.findItem(R.id.action_ui_miuix)?.isCheckable = true
            popupMenu.menu.findItem(R.id.action_ui_material)?.isCheckable = true
            popupMenu.menu.findItem(selectedId)?.isCheckable = true
            popupMenu.menu.findItem(selectedId)?.isChecked = true
        } else {
            val item = requireNotNull(popupMenu.menu.findItem(selectedId))
            item.title = SpannableString(item.title).apply {
                setSpan(ForegroundColorSpan(MiuixTonalColors.primaryForTheme(requireContext())), 0, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
        }
        anchorView.isActivated = true
        if (!materialUi) MiuixPopupDimOverlay.show(requireActivity())
        popupMenu.setOnDismissListener {
            if (!materialUi) MiuixPopupDimOverlay.hide()
            anchorView.isActivated = false
        }
        popupMenu.setOnMenuItemClickListener { item ->
            val style = when (item.itemId) {
                R.id.action_ui_miuix -> UiStyleSettings.MIUIX
                R.id.action_ui_material -> UiStyleSettings.MATERIAL
                else -> return@setOnMenuItemClickListener false
            }
            if (UiStyleSettings.getStyle(requireContext()) != style) {
                val context = requireContext()
                viewModel.saveUiAppearance(context, style, UiStyleSettings.isMaterialDynamicColorEnabled(context)) { success ->
                    if (success) {
                        UiStyleSettings.setStyle(context, style)
                        activity?.recreate()
                    } else {
                        Toast.makeText(context, "Failed to update UI settings", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            true
        }
        popupMenu.showForUi(anchorView, trailingCheckIds = if (materialUi) emptySet() else setOf(selectedId)) {
            anchorView.isActivated = false
        }
    }

    private fun showAdbRootOptionsMenu(anchorView: View) {
        val popupMenu = PopupMenu(popupContext(overflow = true), anchorView, Gravity.END)
        popupMenu.inflate(R.menu.adb_root_options_menu)

        anchorView.isActivated = true
        popupMenu.setOnDismissListener {
            if (!materialUi) MiuixPopupDimOverlay.hide()
            anchorView.isActivated = false
        }
        if (!materialUi) MiuixPopupDimOverlay.show(requireActivity())

        when (viewModel.adbRootMode) {
            ManagementViewModel.ADB_ROOT_ONCE -> popupMenu.menu.findItem(R.id.adb_root_once)?.isChecked = true
            ManagementViewModel.ADB_ROOT_ALWAYS -> popupMenu.menu.findItem(R.id.adb_root_always)?.isChecked = true
            else -> popupMenu.menu.findItem(R.id.adb_root_off)?.isChecked = true
        }

        val highlightColor = if (materialUi) {
            requireContext().theme.resolveColor(R.attr.colorPrimary)
        } else {
            MiuixTonalColors.primaryForTheme(requireContext())
        }
        val menu = popupMenu.menu
        for (i in 0 until menu.size) {
            val item = menu[i]
            if (item.isChecked) {
                val title = item.title?.toString() ?: continue
                val spannableTitle = SpannableString(title)
                spannableTitle.setSpan(
                    ForegroundColorSpan(highlightColor),
                    0,
                    spannableTitle.length,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                item.title = spannableTitle
            }
        }

        popupMenu.setOnMenuItemClickListener { item ->
            val mode = when (item.itemId) {
                R.id.adb_root_once -> ManagementViewModel.ADB_ROOT_ONCE
                R.id.adb_root_always -> ManagementViewModel.ADB_ROOT_ALWAYS
                R.id.adb_root_off -> ManagementViewModel.ADB_ROOT_OFF
                else -> return@setOnMenuItemClickListener false
            }
            val context = requireContext()
            viewModel.setAdbRootMode(mode) { success ->
                Toast.makeText(
                    context,
                    if (success) R.string.toast_restart_device else R.string.toast_adb_root_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
            true
        }
        popupMenu.showForUi(anchorView) { anchorView.isActivated = false }
    }

    private fun showBatchOptionsMenu(anchorView: View) {
        val popupMenu = PopupMenu(popupContext(overflow = true), anchorView, Gravity.END)
        popupMenu.inflate(R.menu.batch_options_menu)

        anchorView.isActivated = true
        popupMenu.setOnDismissListener {
            if (!materialUi) MiuixPopupDimOverlay.hide()
            anchorView.isActivated = false
        }
        if (!materialUi) MiuixPopupDimOverlay.show(requireActivity())

        val currentDefaultMode = viewModel.appList.value?.data?.firstOrNull()?.defaultFlags
            ?.and(SuiConfig.MASK_PERMISSION) ?: 0

        val highlightColor = if (materialUi) {
            requireContext().theme.resolveColor(R.attr.colorPrimary)
        } else {
            MiuixTonalColors.primaryForTheme(requireContext())
        }

        val menu = popupMenu.menu
        for (i in 0 until menu.size) {
            val item = menu[i]

            val isSelected = when (item.itemId) {
                R.id.batch_allow -> currentDefaultMode == SuiConfig.FLAG_ALLOWED
                R.id.batch_allow_shell -> currentDefaultMode == SuiConfig.FLAG_ALLOWED_SHELL
                R.id.batch_deny -> currentDefaultMode == SuiConfig.FLAG_DENIED
                R.id.batch_hidden -> currentDefaultMode == SuiConfig.FLAG_HIDDEN
                R.id.batch_ask -> currentDefaultMode == 0
                else -> false
            }
            if (isSelected) {
                item.isChecked = true
                val spannableTitle = SpannableString(item.title)
                spannableTitle.setSpan(
                    ForegroundColorSpan(highlightColor),
                    0,
                    spannableTitle.length,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                )
                spannableTitle.setSpan(
                    StyleSpan(Typeface.BOLD),
                    0,
                    spannableTitle.length,
                    Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                )

                item.title = spannableTitle
            }
        }
        popupMenu.setOnMenuItemClickListener { item ->
            val targetMode = when (item.itemId) {
                R.id.batch_allow -> SuiConfig.FLAG_ALLOWED
                R.id.batch_allow_shell -> SuiConfig.FLAG_ALLOWED_SHELL
                R.id.batch_deny -> SuiConfig.FLAG_DENIED
                R.id.batch_hidden -> SuiConfig.FLAG_HIDDEN
                R.id.batch_ask -> 0
                else -> -1
            }

            if (targetMode != -1) {
                performBatchUpdate(targetMode)
            }
            true
        }
        popupMenu.showForUi(anchorView) { anchorView.isActivated = false }
    }
    private fun performBatchUpdate(targetMode: Int) {
        if (adapter.itemCount == 0) {
            if (materialUi) {
                setMaterialLoadingCentered(true)
                binding.materialLoadingIndicator.isVisible = true
            } else {
                binding.pullToRefreshIndicator.state = MiuixPullToRefreshView.RefreshState.REFRESHING
            }
        }
        viewModel.batchUpdate(targetMode, requireContext())
    }

    @android.annotation.SuppressLint("StringFormatInvalid")
    private fun showAboutDialog() {
        val versionName = try {
            BuildConfig.VERSION_NAME
        } catch (e: Exception) {
            "Unknown"
        }
        val message = SpannableStringBuilder().apply {
            append(getString(R.string.about_version, versionName))
            val break1 = length
            append("\n\n")
            setSpan(RelativeSizeSpan(0.5f), break1, break1 + 2, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            append(getString(R.string.about_license_part1))
            append(" ")
            val startGithub = length
            append(getString(R.string.about_license_part2))
            setSpan(URLSpan("https://github.com/XiaoTong6666/Sui"), startGithub, length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            append(" ")
            append(getString(R.string.about_license_part3))
            val break2 = length
            append("\n\n")
            setSpan(RelativeSizeSpan(0.5f), break2, break2 + 2, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)

            val githubLinks = mapOf(
                "RikkaW" to "https://github.com/RikkaW",
                "XiaoTong6666" to "https://github.com/XiaoTong6666",
                "yangFenTuoZi" to "https://github.com/yangFenTuoZi",
                "yujincheng08" to "https://github.com/yujincheng08",
                "0xSoul24" to "https://github.com/0xSoul24",
                "Howard20181" to "https://github.com/Howard20181",
                "Kr328" to "https://github.com/Kr328",
                "binyaminyblatt" to "https://github.com/binyaminyblatt",
                "Re*Index.(ot_inc)" to "https://github.com/reindex-ot",
                "IshaParihariya" to "https://github.com/IshaParihariya",
                "soralis0912" to "https://github.com/soralis0912",
            )

            val contributorsNamesString = githubLinks.keys.joinToString(", ")
            val contributorsText = getString(R.string.about_contributors, contributorsNamesString)
            val spannableContributors = SpannableStringBuilder(contributorsText)

            for ((name, link) in githubLinks) {
                val index = contributorsText.indexOf(name)
                if (index != -1) {
                    spannableContributors.setSpan(
                        object : URLSpan(link) {
                            override fun updateDrawState(ds: android.text.TextPaint) {
                            }
                        },
                        index,
                        index + name.length,
                        Spanned.SPAN_EXCLUSIVE_EXCLUSIVE,
                    )
                }
            }
            append(spannableContributors)
        }

        if (materialUi) {
            val dialog = MaterialAlertDialogBuilder(requireContext())
                .setTitle("Sui")
                .setMessage(message)
                .setPositiveButton(R.string.about_button_ok, null)
                .create()
            // Window animations are resolved by the system using the host package.
            // In Settings, Sui's private style IDs do not belong to that package.
            dialog.window?.setWindowAnimations(0)
            val decor = dialog.window?.decorView
            decor?.apply {
                alpha = 0f
                scaleX = 0.94f
                scaleY = 0.94f
            }
            dialog.show()
            decor?.animate()
                ?.alpha(1f)
                ?.scaleX(1f)
                ?.scaleY(1f)
                ?.setDuration(220L)
                ?.setInterpolator(DecelerateInterpolator())
                ?.start()

            dialog.getButton(DialogInterface.BUTTON_POSITIVE)?.setOnClickListener {
                if (decor == null) {
                    dialog.dismiss()
                } else {
                    decor.animate().cancel()
                    decor.animate()
                        .alpha(0f)
                        .scaleX(0.98f)
                        .scaleY(0.98f)
                        .setDuration(160L)
                        .withEndAction { dialog.dismiss() }
                        .start()
                }
            }
            dialog.findViewById<android.widget.TextView>(android.R.id.message)?.movementMethod = LinkMovementMethod.getInstance()
            return
        }

        val contentView = layoutInflater.inflate(R.layout.miuix_about_bottom_sheet, binding.root, false)

        val root = contentView.findViewById<android.widget.LinearLayout>(R.id.miuix_bottom_sheet_root)
        val titleView = contentView.findViewById<android.widget.TextView>(R.id.text_title)
        val textView = contentView.findViewById<android.widget.TextView>(R.id.text_about)
        val buttonOk = contentView.findViewById<android.widget.TextView>(R.id.button_ok)
        val density = requireContext().resources.displayMetrics.density

        val primaryColor = MiuixTonalColors.primaryForTheme(requireContext())
        val isNight = (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        val isMonetEnabled = viewModel.isMonetEnabled
        val sheetColor = if (isMonetEnabled) {
            val accent = requireContext().theme.resolveColor(androidx.appcompat.R.attr.colorAccent)
            MiuixTonalColors.fromAccent(accent, isNight).surfaceContainerHigh
        } else {
            ContextCompat.getColor(requireContext(), R.color.miuix_bottom_sheet_bg_color)
        }
        val baseRadiusPx = MiuixSquircleUtils.getBottomCornerRadius(requireContext())
        val dynamicRadiusPx = baseRadiusPx + 12f * density
        root?.background = MiuixSmoothCardDrawable(dynamicRadiusPx, sheetColor, topCornersOnly = false)

        val btnColor = if (isMonetEnabled) {
            if (isNight) {
                ColorUtils.blendARGB(sheetColor, primaryColor, 0.20f)
            } else {
                ColorUtils.blendARGB(sheetColor, primaryColor, 0.10f)
            }
        } else {
            requireContext().getColor(R.color.miuix_button_bg_color)
        }
        val btnRadiusPx = 16f * density
        buttonOk?.background = MiuixSmoothCardDrawable.createSelectorWithOverlay(
            requireContext(),
            btnColor,
            16f,
            topCornersOnly = false,
        )

        val dialogDiagonalOffset = dynamicRadiusPx * 0.2928f
        val buttonDiagonalOffset = btnRadiusPx * 0.2928f
        val bottomPaddingOffset = (dialogDiagonalOffset - buttonDiagonalOffset).coerceAtLeast(0f)
        val basePaddingBottomPx = 24f * density

        if (root != null) {
            ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
                val navBars = insets.getInsets(WindowInsetsCompat.Type.navigationBars())
                v.setPadding(
                    v.paddingLeft,
                    v.paddingTop,
                    v.paddingRight,
                    (basePaddingBottomPx + bottomPaddingOffset + navBars.bottom).toInt(),
                )
                insets
            }
        }

        titleView?.setText(R.string.about_title)
        textView?.text = message
        textView?.movementMethod = LinkMovementMethod.getInstance()

        val bottomSheetDialog = MiuixBottomSheetDialog(requireContext(), contentView)
        buttonOk?.setOnClickListener {
            bottomSheetDialog.dismiss()
        }

        bottomSheetDialog.show()
    }

    override fun onDestroyView() {
        if (materialUi) {
            binding.list.removeOnItemTouchListener(materialPullToRefresh)
            materialPullToRefresh.finishRefresh()
        }
        super.onDestroyView()
        MiuixPopupDimOverlay.cleanUp()
        _binding = null
    }

    private fun onLoading() {
        if (adapter.itemCount == 0) {
            binding.list.isGone = true
            if (materialUi) {
                setMaterialLoadingCentered(true)
                binding.materialLoadingIndicator.isVisible = true
            }
            if (!materialUi) {
                binding.pullToRefreshIndicator.apply {
                    state = MiuixPullToRefreshView.RefreshState.REFRESHING
                    pullProgress = 1f

                    post {
                        val targetOffset = (parent as? View)?.height?.toFloat() ?: (resources.displayMetrics.heightPixels.toFloat() * 0.8f)
                        thresholdOffset = targetOffset
                        dragOffset = targetOffset
                        invalidate()
                    }
                }
            }
        }
    }

    private fun onError(e: Throwable?) {
        binding.list.isVisible = true
        if (materialUi) materialPullToRefresh.finishRefresh()
        binding.materialLoadingIndicator.isGone = true
        if (!materialUi) {
            bounceEdgeEffectFactory.finishRefresh()
            binding.pullToRefreshIndicator.state = MiuixPullToRefreshView.RefreshState.IDLE
        }
    }

    private fun onSuccess(data: Resource<List<AppInfo>?>) {
        binding.list.isVisible = true
        if (materialUi) materialPullToRefresh.finishRefresh()
        binding.materialLoadingIndicator.isGone = true
        if (!materialUi) {
            bounceEdgeEffectFactory.finishRefresh()
            binding.pullToRefreshIndicator.state = MiuixPullToRefreshView.RefreshState.IDLE
        }

        data.data?.let {
            adapter.updateData(it)

            if (it.isNotEmpty()) {
                binding.list.scheduleLayoutAnimation()
            }
        }
    }
}
