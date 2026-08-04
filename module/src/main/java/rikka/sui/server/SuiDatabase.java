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
import android.database.sqlite.SQLiteDatabaseCorruptException;
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
    private static final String[] DATABASE_FILE_SUFFIXES = {"", "-journal", "-shm", "-wal"};
    private static final String UID_CONFIG_TABLE = "uid_configs";
    private static SQLiteDatabase databaseInternal;

    private static void checkDatabase(SQLiteDatabase database) {
        String result;
        try (Cursor cursor = database.rawQuery("PRAGMA quick_check(1)", null)) {
            result = cursor.moveToFirst() ? cursor.getString(0) : null;
        }
        if (!"ok".equalsIgnoreCase(result)) {
            throw new SQLiteDatabaseCorruptException("quick_check failed: " + result);
        }
    }

    private static boolean isDatabaseCorrupt(Throwable error) {
        while (error != null) {
            if (error instanceof SQLiteDatabaseCorruptException) {
                return true;
            }
            error = error.getCause();
        }
        return false;
    }

    private static void closeDatabase(SQLiteDatabase database) {
        if (database == null) {
            return;
        }
        try {
            database.close();
        } catch (Throwable e) {
            ServerConstants.LOGGER.w(e, "close database after failed initialization");
        }
    }

    private static boolean hasOrphanedDatabaseFiles() {
        if ((new File(DATABASE_PATH)).exists()) {
            return false;
        }
        for (int i = 1; i < DATABASE_FILE_SUFFIXES.length; ++i) {
            if ((new File(DATABASE_PATH + DATABASE_FILE_SUFFIXES[i])).exists()) {
                return true;
            }
        }
        return false;
    }

    @Nullable private static File createBackupDirectory(String reason) {
        File parent = (new File(DATABASE_PATH)).getParentFile();
        if (parent == null) {
            return null;
        }

        String name = "database-" + reason + "-" + System.currentTimeMillis();
        File directory = new File(parent, name);
        for (int index = 1; directory.exists(); ++index) {
            directory = new File(parent, name + "-" + index);
        }
        return directory.mkdir() ? directory : null;
    }

    private static void quarantineDatabaseFiles(String reason) {
        File databaseFile = new File(DATABASE_PATH);
        File backupDirectory = createBackupDirectory(reason);
        for (String suffix : DATABASE_FILE_SUFFIXES) {
            File source = new File(DATABASE_PATH + suffix);
            if (!source.exists()) {
                continue;
            }
            if (backupDirectory == null || !source.renameTo(new File(backupDirectory, source.getName()))) {
                ServerConstants.LOGGER.w("Cannot back up database file %s", source);
            }
        }

        if (backupDirectory != null) {
            ServerConstants.LOGGER.w("Quarantined database files to %s", backupDirectory);
        }
        SQLiteDatabase.deleteDatabase(databaseFile);
    }

    private static SQLiteDatabase createDatabase(boolean allowRecovery) {
        if (allowRecovery && hasOrphanedDatabaseFiles()) {
            ServerConstants.LOGGER.w("Main database is missing; quarantining orphaned auxiliary files");
            quarantineDatabaseFiles("orphaned");
        }

        SQLiteDatabase database = null;
        try {
            database = SQLiteDataBaseRemoteCompat.openDatabase(DATABASE_PATH, null);
            checkDatabase(database);
            database.execSQL("CREATE TABLE IF NOT EXISTS uid_configs(uid INTEGER PRIMARY KEY, flags INTEGER);");
        } catch (Throwable e) {
            boolean corrupt = isDatabaseCorrupt(e);
            ServerConstants.LOGGER.e(e, corrupt ? "database corrupted" : "create database");
            closeDatabase(database);
            if (allowRecovery && corrupt) {
                quarantineDatabaseFiles("corrupt");
                return createDatabase(false);
            }
            return null;
        }

        return database;
    }

    private static synchronized SQLiteDatabase getDatabase() {
        if (databaseInternal == null) {
            databaseInternal = createDatabase(true);
        }
        return databaseInternal;
    }

    static boolean initialize() {
        return getDatabase() != null;
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
