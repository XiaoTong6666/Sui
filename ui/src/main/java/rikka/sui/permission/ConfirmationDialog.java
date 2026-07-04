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

package rikka.sui.permission;

import static rikka.shizuku.ShizukuApiConstants.REQUEST_PERMISSION_REPLY_ALLOWED;
import static rikka.shizuku.ShizukuApiConstants.REQUEST_PERMISSION_REPLY_IS_ONETIME;
import static rikka.shizuku.ShizukuApiConstants.REQUEST_PERMISSION_REPLY_IS_SHELL;

import android.app.Application;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManagerHidden;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.PixelFormat;
import android.os.Binder;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.view.ContextThemeWrapper;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.view.animation.DecelerateInterpolator;
import android.widget.FrameLayout;
import androidx.core.content.res.ResourcesCompat;
import androidx.core.graphics.ColorUtils;
import com.google.android.material.color.DynamicColors;
import dev.rikka.tools.refine.Refine;
import java.util.Objects;
import rikka.html.text.HtmlCompat;
import rikka.sui.R;
import rikka.sui.databinding.ConfirmationDialogBinding;
import rikka.sui.ktx.HandlerKt;
import rikka.sui.ktx.ResourcesKt;
import rikka.sui.ktx.TextViewKt;
import rikka.sui.ktx.WindowKt;
import rikka.sui.util.AppLabel;
import rikka.sui.util.BridgeServiceClient;
import rikka.sui.util.Logger;
import rikka.sui.util.MiuixSmoothCardDrawable;
import rikka.sui.util.MiuixSquircleUtils;
import rikka.sui.util.UserHandleCompat;
import rikka.sui.widget.MiuixBottomSheetLayout;

public class ConfirmationDialog {

    private static final IBinder TOKEN = new Binder();
    private static final Logger LOGGER = new Logger("SuiConfirmationDialog");

    private final Context context;
    private final Resources resources;
    private final LayoutInflater layoutInflater;
    private boolean monetEnabled = false;
    private final boolean isNight;

    @SuppressWarnings("deprecation")
    public ConfirmationDialog(Application application, Resources resources) {
        Configuration hostConfig = application.getResources().getConfiguration();
        resources.updateConfiguration(hostConfig, application.getResources().getDisplayMetrics());

        this.isNight = (hostConfig.uiMode & Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES;
        int themeRes = R.style.Theme_Sui;

        Context wrappedContext = new ContextThemeWrapper(application, themeRes) {
            @Override
            public Resources getResources() {
                return resources;
            }

            @Override
            public ClassLoader getClassLoader() {
                return ConfirmationDialog.class.getClassLoader();
            }
        };

        try {
            int globalSettings = BridgeServiceClient.getGlobalSettings();
            this.monetEnabled = (globalSettings & BridgeServiceClient.FLAG_MONET_DISABLED) == 0;
        } catch (Throwable e) {
            LOGGER.e("getGlobalSettings failed in ConfirmationDialog", e);
        }

        if (monetEnabled) {
            wrappedContext = DynamicColors.wrapContextIfAvailable(wrappedContext);
        }

        this.context = wrappedContext;

        this.resources = resources;
        this.layoutInflater = LayoutInflater.from(this.context);
    }

    public void show(int requestUid, int requestPid, String requestPackageName, int requestCode) {
        HandlerKt.getMainHandler().post(() -> showInternal(requestUid, requestPid, requestPackageName, requestCode));
    }

    private void setResult(
            int requestUid, int requestPid, int requestCode, boolean allowed, boolean onetime, boolean isShell) {
        Bundle data = new Bundle();
        data.putBoolean(REQUEST_PERMISSION_REPLY_ALLOWED, allowed);
        data.putBoolean(REQUEST_PERMISSION_REPLY_IS_ONETIME, onetime);
        data.putBoolean(REQUEST_PERMISSION_REPLY_IS_SHELL, isShell);

        try {
            BridgeServiceClient.getService()
                    .dispatchPermissionConfirmationResult(requestUid, requestPid, requestCode, data);
        } catch (Throwable e) {
            LOGGER.e("dispatchPermissionConfirmationResult");
        }
    }

    @SuppressWarnings("deprecation")
    private void showInternal(int requestUid, int requestPid, String requestPackageName, int requestCode) {

        MiuixBottomSheetLayout sheetLayout = new MiuixBottomSheetLayout(context);

        SystemDialogRootView root = new SystemDialogRootView(context) {

            @Override
            public boolean onBackPressed() {
                sheetLayout.dismiss();
                return false;
            }

            @Override
            public void onClose() {
                setResult(requestUid, requestPid, requestCode, false, true, false);
            }
        };
        root.setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN);

        View dimView = new View(context);
        int dimColor = isNight ? 0x99000000 : 0x4D000000;
        dimView.setBackgroundColor(dimColor);
        dimView.setAlpha(0f);
        root.addView(
                dimView,
                new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        root.addView(
                sheetLayout,
                new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        View view = layoutInflater.inflate(resources.getLayout(R.layout.confirmation_dialog), sheetLayout, false);
        ConfirmationDialogBinding binding = ConfirmationDialogBinding.bind(view);

        FrameLayout.LayoutParams lp =
                new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.gravity = Gravity.BOTTOM;
        sheetLayout.addView(binding.getRoot(), lp);

        sheetLayout.setOnDimAlphaChange(alpha -> {
            dimView.setAlpha(alpha);
            return kotlin.Unit.INSTANCE;
        });
        sheetLayout.setOnDimAlphaAnimate((alpha, duration) -> {
            dimView.animate()
                    .alpha(alpha)
                    .setDuration(duration)
                    .setInterpolator(new DecelerateInterpolator(1.5f))
                    .start();
            return kotlin.Unit.INSTANCE;
        });
        sheetLayout.setOnDismissRequest(() -> {
            root.dismiss();
            return kotlin.Unit.INSTANCE;
        });

        root.addOnAttachStateChangeListener(new View.OnAttachStateChangeListener() {
            @Override
            public void onViewAttachedToWindow(View v) {
                sheetLayout.show();
            }

            @Override
            public void onViewDetachedFromWindow(View v) {}
        });

        String label = requestPackageName;
        int userId = UserHandleCompat.getUserId(requestUid);
        PackageManager pm = context.getPackageManager();
        try {
            ApplicationInfo ai = Objects.requireNonNull(Refine.<PackageManagerHidden>unsafeCast(pm))
                    .getApplicationInfoAsUser(
                            requestPackageName, PackageManagerHidden.MATCH_UNINSTALLED_PACKAGES, userId);
            label = AppLabel.getAppLabel(ai, context);
        } catch (Throwable e) {
            LOGGER.e("getApplicationInfoAsUser");
        }

        binding.icon.setImageDrawable(ResourcesCompat.getDrawable(resources, R.drawable.ic_su_24, context.getTheme()));
        binding.title.setText(HtmlCompat.fromHtml(String.format(
                resources.getString(R.string.permission_warning_template),
                label,
                resources.getString(R.string.permission_description))));
        binding.button1Root.setText(resources.getString(R.string.grant_dialog_button_allow_always));
        binding.button1Shell.setText(resources.getString(R.string.grant_dialog_button_allow_always_shell));
        binding.button2.setText(resources.getString(R.string.grant_dialog_button_allow_one_time));
        binding.button3.setText(resources.getString(R.string.grant_dialog_button_deny_and_dont_ask_again));

        ColorStateList buttonTextColor =
                resources.getColorStateList(R.color.confirmation_dialog_button_text, context.getTheme());
        binding.button1Root.setTextColor(buttonTextColor);
        binding.button1Shell.setTextColor(buttonTextColor);
        binding.button2.setTextColor(buttonTextColor);
        binding.button3.setTextColor(buttonTextColor);

        binding.button1Root.setOnClickListener(v -> {
            if (sheetLayout.isDismissing()) return;
            setResult(requestUid, requestPid, requestCode, true, false, false);
            sheetLayout.dismiss();
        });
        binding.button1Shell.setOnClickListener(v -> {
            if (sheetLayout.isDismissing()) return;
            setResult(requestUid, requestPid, requestCode, true, false, true);
            sheetLayout.dismiss();
        });
        binding.button2.setOnClickListener(v -> {
            if (sheetLayout.isDismissing()) return;
            setResult(requestUid, requestPid, requestCode, true, true, false);
            sheetLayout.dismiss();
        });
        binding.button3.setOnClickListener(v -> {
            if (sheetLayout.isDismissing()) return;
            setResult(requestUid, requestPid, requestCode, false, false, false);
            sheetLayout.dismiss();
        });

        TextViewKt.applyCountdown(binding.button1Root, 1, null, 0);
        TextViewKt.applyCountdown(binding.button1Shell, 1, null, 0);
        TextViewKt.applyCountdown(binding.button2, 1, null, 0);
        TextViewKt.applyCountdown(binding.button3, 1, null, 0);

        float density = context.getResources().getDisplayMetrics().density;
        float dynamicRadiusPx = MiuixSquircleUtils.INSTANCE.getBottomCornerRadius(context) + 12f * density;
        int sheetColor = resources.getColor(R.color.miuix_bottom_sheet_bg_color, context.getTheme());
        binding.getRoot().setBackground(new MiuixSmoothCardDrawable(dynamicRadiusPx, sheetColor, false));

        int primaryColor = -1;
        if (monetEnabled && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                int sysColorId = isNight ? android.R.color.system_accent1_200 : android.R.color.system_accent1_600;
                primaryColor = context.getResources().getColor(sysColorId, context.getTheme());
            } catch (Exception ignored) {
            }
        }
        if (primaryColor == -1) {
            primaryColor = ResourcesKt.resolveColor(context.getTheme(), androidx.appcompat.R.attr.colorPrimary);
        }

        int btnColor;
        if (monetEnabled) {
            btnColor = isNight
                    ? ColorUtils.blendARGB(sheetColor, primaryColor, 0.20f)
                    : ColorUtils.blendARGB(sheetColor, primaryColor, 0.10f);
        } else {
            btnColor = resources.getColor(R.color.miuix_button_bg_color, context.getTheme());
        }

        float btnRadiusPx = 16f * density;
        binding.button1Root.setBackground(
                MiuixSmoothCardDrawable.Companion.createSelectorWithOverlay(context, btnColor, 16f, false));
        binding.button1Shell.setBackground(
                MiuixSmoothCardDrawable.Companion.createSelectorWithOverlay(context, btnColor, 16f, false));
        binding.button2.setBackground(
                MiuixSmoothCardDrawable.Companion.createSelectorWithOverlay(context, btnColor, 16f, false));
        binding.button3.setBackground(
                MiuixSmoothCardDrawable.Companion.createSelectorWithOverlay(context, btnColor, 16f, false));

        float dialogDiagonalOffset = dynamicRadiusPx * 0.2928f;
        float buttonDiagonalOffset = btnRadiusPx * 0.2928f;
        float bottomPaddingOffset = Math.max(0f, dialogDiagonalOffset - buttonDiagonalOffset);

        androidx.core.view.ViewCompat.setOnApplyWindowInsetsListener(binding.getRoot(), (v, insets) -> {
            androidx.core.graphics.Insets navBars =
                    insets.getInsets(androidx.core.view.WindowInsetsCompat.Type.navigationBars());

            float basePadding = navBars.bottom > 0 ? (32f * density) : (16f * density);
            int extraPadding = (int) Math.max(0, navBars.bottom - basePadding);

            v.setPadding(v.getPaddingLeft(), v.getPaddingTop(), v.getPaddingRight(), (int)
                    (basePadding + bottomPaddingOffset + extraPadding));
            return insets;
        });

        WindowManager.LayoutParams attr = new WindowManager.LayoutParams();
        attr.width = ViewGroup.LayoutParams.MATCH_PARENT;
        attr.height = ViewGroup.LayoutParams.MATCH_PARENT;
        attr.flags =
                WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN;
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            attr.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
        }
        attr.type = WindowManager.LayoutParams.TYPE_SYSTEM_DIALOG;
        attr.token = TOKEN;
        attr.format = PixelFormat.TRANSLUCENT;
        WindowKt.setPrivateFlags(
                attr, WindowKt.getPrivateFlags(attr) | WindowKt.getSYSTEM_FLAG_HIDE_NON_SYSTEM_OVERLAY_WINDOWS());

        root.show(attr);
    }
}
