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

package rikka.sui.model;

import android.content.pm.PackageInfo;
import android.os.Parcel;
import android.os.Parcelable;

public class AppInfo implements Parcelable {

    public PackageInfo packageInfo;
    public int flags;
    public int defaultFlags;
    public CharSequence label = null;

    public AppInfo() {}

    protected AppInfo(Parcel in) {
        packageInfo = in.readParcelable(PackageInfo.class.getClassLoader());
        flags = in.readInt();
        defaultFlags = in.readInt();
    }

    public static final Creator<AppInfo> CREATOR = new Creator<AppInfo>() {
        @Override
        public AppInfo createFromParcel(Parcel in) {
            return new AppInfo(in);
        }

        @Override
        public AppInfo[] newArray(int size) {
            return new AppInfo[size];
        }
    };

    @Override
    public int describeContents() {
        return 0;
    }

    @Override
    public void writeToParcel(Parcel dest, int flags) {
        dest.writeParcelable(packageInfo, flags);
        dest.writeInt(this.flags);
        dest.writeInt(defaultFlags);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppInfo appInfo = (AppInfo) o;
        return flags == appInfo.flags
                && defaultFlags == appInfo.defaultFlags
                && java.util.Objects.equals(packageInfo.packageName, appInfo.packageInfo.packageName)
                && java.util.Objects.equals(label, appInfo.label);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(packageInfo.packageName, flags, defaultFlags, label);
    }
}
