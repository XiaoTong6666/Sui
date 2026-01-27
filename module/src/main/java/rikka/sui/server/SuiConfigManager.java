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

package rikka.sui.server;

import androidx.annotation.Nullable;
import java.util.List;
import rikka.shizuku.server.ConfigManager;

public class SuiConfigManager extends ConfigManager {

    public static final int DEFAULT_UID = -1;

    public static SuiConfig load() {
        SuiConfig config = SuiDatabase.readConfig();
        if (config == null) {
            LOGGER.e("SuiConfigManager: failed to read database, starting empty");
            return new SuiConfig();
        }
        LOGGER.i("SuiConfigManager: Loaded " + config.packages.size() + " packages from database.");
        return config;
    }

    private static SuiConfigManager instance;

    public static SuiConfigManager getInstance() {
        if (instance == null) {
            instance = new SuiConfigManager();
        }
        return instance;
    }

    private final SuiConfig config;

    public SuiConfigManager() {
        this.config = load();
    }

    private SuiConfig.PackageEntry findLocked(int uid) {
        for (SuiConfig.PackageEntry entry : config.packages) {
            if (uid == entry.uid) {
                return entry;
            }
        }
        return null;
    }

    @Nullable public SuiConfig.PackageEntry findExplicit(int uid) {
        synchronized (this) {
            return findLocked(uid);
        }
    }

    @Nullable public SuiConfig.PackageEntry find(int uid) {
        synchronized (this) {
            if (uid == 0 || uid == 1000) {
                return new SuiConfig.PackageEntry(uid, SuiConfig.FLAG_ALLOWED);
            }
            SuiConfig.PackageEntry entry = findLocked(uid);
            if (uid == DEFAULT_UID) {
                return entry;
            }
            if (entry != null && entry.flags != 0) {
                LOGGER.i("SuiConfigManager: Found explicit flags for uid " + uid + ": " + entry.flags);
                return entry;
            }
            SuiConfig.PackageEntry defaultEntry = findLocked(DEFAULT_UID);
            if (defaultEntry == null || defaultEntry.flags == 0) {
                return null;
            }
            LOGGER.i("SuiConfigManager: Using DEFAULT flags for uid " + uid + ". Flags: " + defaultEntry.flags);
            return new SuiConfig.PackageEntry(uid, defaultEntry.flags);
        }
    }

    @Override
    public void update(int uid, List<String> packages, int mask, int values) {
        update(uid, mask, values);
    }

    public void update(int uid, int mask, int values) {
        LOGGER.i("SuiConfigManager: update uid=" + uid + " mask=" + mask + " val=" + values);
        boolean needRemove = false;
        boolean needUpdate = false;
        int finalFlags = 0;

        synchronized (this) {
            SuiConfig.PackageEntry entry = findLocked(uid);
            if (entry == null) {
                int newValue = mask & values;
                if (newValue == 0) {
                    return;
                }
                entry = new SuiConfig.PackageEntry(uid, newValue);
                config.packages.add(entry);
                needUpdate = true;
                finalFlags = newValue;
                LOGGER.i("SuiConfigManager: Added new entry for uid " + uid);
            } else {
                int newValue = (entry.flags & ~mask) | (mask & values);
                if (newValue == entry.flags) {
                    return;
                }
                if (newValue == 0) {
                    config.packages.remove(entry);
                    needRemove = true;
                    LOGGER.i("SuiConfigManager: Removed entry for uid " + uid);
                } else {
                    entry.flags = newValue;
                    needUpdate = true;
                    finalFlags = newValue;
                    LOGGER.i("SuiConfigManager: Updated entry for uid " + uid);
                }
            }
        }
        if (needRemove) {
            SuiDatabase.removeUid(uid);
        } else if (needUpdate) {
            SuiDatabase.updateUid(uid, finalFlags);
        }
    }

    @Override
    public void remove(int uid) {
        boolean needRemove = false;
        synchronized (this) {
            SuiConfig.PackageEntry entry = findLocked(uid);
            if (entry != null) {
                config.packages.remove(entry);
                needRemove = true;
            }
        }
        if (needRemove) {
            SuiDatabase.removeUid(uid);
        }
    }

    public boolean isHidden(int uid) {
        SuiConfig.PackageEntry entry = find(uid);
        if (entry == null) {
            return false;
        }
        return (entry.flags & SuiConfig.FLAG_HIDDEN) != 0;
    }

    public int getDefaultPermissionFlags() {
        synchronized (this) {
            SuiConfig.PackageEntry entry = findLocked(DEFAULT_UID);
            if (entry == null) {
                return 0;
            }
            return entry.flags & SuiConfig.MASK_PERMISSION;
        }
    }

    public void setDefaultPermissionFlags(int flags) {
        LOGGER.i("SuiConfigManager: Setting default permission flags: " + flags);
        int value = flags & SuiConfig.MASK_PERMISSION;
        if (value == 0) {
            remove(DEFAULT_UID);
        } else {
            update(DEFAULT_UID, SuiConfig.MASK_PERMISSION, value);
        }
    }
}
