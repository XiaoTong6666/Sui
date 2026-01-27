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

package rikka.sui.server;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import androidx.annotation.Nullable;
import java.io.File;
import rikka.sui.server.SuiConfig.PackageEntry;
import rikka.sui.util.SQLiteDataBaseRemoteCompat;

public class SuiDatabase {

    private SuiDatabase() {}

    static {
        DATABASE_PATH = (new File("/data/adb/sui/sui.db")).getPath();
    }

    private static final String DATABASE_PATH;
    private static final String UID_CONFIG_TABLE = "uid_configs";
    private static SQLiteDatabase databaseInternal;

    private static SQLiteDatabase createDatabase(boolean allowRetry) {
        SQLiteDatabase database;
        try {
            database = SQLiteDataBaseRemoteCompat.openDatabase(DATABASE_PATH, null);
            database.execSQL("CREATE TABLE IF NOT EXISTS uid_configs(uid INTEGER PRIMARY KEY, flags INTEGER);");
        } catch (Throwable e) {
            ServerConstants.LOGGER.e(e, "create database");
            if (allowRetry && (new File(DATABASE_PATH)).delete()) {
                ServerConstants.LOGGER.i("delete database and retry");
                database = createDatabase(false);
            } else {
                database = null;
            }
        }

        return database;
    }

    private static SQLiteDatabase getDatabase() {
        if (databaseInternal == null) {
            databaseInternal = createDatabase(true);
        }
        return databaseInternal;
    }

    @Nullable public static SuiConfig readConfig() {
        SQLiteDatabase database = getDatabase();
        if (database == null) {
            return null;
        }

        try (Cursor cursor = database.query(
                UID_CONFIG_TABLE,
                (String[]) null,
                (String) null,
                (String[]) null,
                (String) null,
                (String) null,
                (String) null,
                (String) null)) {
            if (cursor == null) {
                return null;
            }
            SuiConfig res = new SuiConfig();
            int cursorIndexOfUid = cursor.getColumnIndexOrThrow("uid");
            int cursorIndexOfFlags = cursor.getColumnIndexOrThrow("flags");
            if (cursor.moveToFirst()) {
                do {
                    res.packages.add(
                            new PackageEntry(cursor.getInt(cursorIndexOfUid), cursor.getInt(cursorIndexOfFlags)));
                } while (cursor.moveToNext());
            }
            return res;
        }
    }

    public static void updateUid(int uid, int flags) {
        SQLiteDatabase database = getDatabase();
        if (database == null) {
            return;
        }

        ContentValues values = new ContentValues();
        values.put("uid", uid);
        values.put("flags", flags);
        String selection = "uid=?";
        String[] selectionArgs = new String[] {String.valueOf(uid)};
        if (database.update(UID_CONFIG_TABLE, values, selection, selectionArgs) <= 0) {
            database.insertWithOnConflict(UID_CONFIG_TABLE, (String) null, values, SQLiteDatabase.CONFLICT_IGNORE);
        }
    }

    public static void removeUid(int uid) {
        SQLiteDatabase database = getDatabase();
        if (database == null) {
            return;
        }

        String selection = "uid=?";
        String[] selectionArgs = new String[] {String.valueOf(uid)};
        database.delete(UID_CONFIG_TABLE, selection, selectionArgs);
    }
}
