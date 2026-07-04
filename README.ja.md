# Sui

[🇺🇸English README](https://github.com/XiaoTong6666/Sui/blob/main/README.md) | [🇨🇳中文README](https://github.com/XiaoTong6666/Sui/blob/main/README.zh-CN.md)

Android 向けのモダンなスーパーユーザーインターフェース (SUI) 実装です。

## 概要

Sui は Java API（具体的には [Shizuku API](https://github.com/RikkaApps/Shizuku-API)）を提供し、root / shell アプリから利用できます。主に次の 2 つの機能を提供します。

1. Android フレームワーク API を直接呼び出すことができ、まるで Java からシステム API を root または shell として実行しているかのように利用できます。  
2. アプリ側で定義した AIDL 形式の Java サービスを root または shell 上で起動できます。

この仕組みにより、特権 Android アプリの開発が格段に楽になります。

もう一つの利点は、Sui が `PATH` にバイナリを追加したり、スタンドアロンのマネージャーアプリをインストールしたりしない点です。そのため、検出を行うアプリとの衝突を大幅に減らすことができます。

**注意** 「root」の完全実装は単なる `su` よりもはるかに大規模です。Sui はフルな root ソリューションではなく、既存の root 環境（Zygisk モジュール）上で動作します。

<details>
  <summary>なぜ「su」はアプリ開発に不向きなのか</summary>

`su` は root 権限で実行される「シェル」ですが、Android の世界からは遠く離れています。

その理由を簡単に説明すると、システム API は **IPC**（プロセス間通信）を通して `system_server` とやり取りしています。たとえば `PackageManager#getInstalledApplications` を呼び出すと、実際にはアプリ側プロセスと `system_server` プロセス間で Binder を使った通信が行われます。Android フレームワークはこの手順を隠蔽しています。

一方、`su` 環境では Android が提供するコマンドだけしか利用できません。先ほどの例でアプリリストを取得したい場合は `pm list` を実行しなければならず、次のような問題があります。

1. **テキストベース出力** `PackageInfo` のような構造化データが得られず、文字列を自前で解析する必要があります。  
2. **遅い** コマンド実行ごとに新しいプロセスが起動し、`pm list` の内部でも `PackageManager#getInstalledApplications` が呼び出されます。  
3. **機能が限定的** コマンドは Android API のごく一部しかカバーできません。

`app_process` 経由で `libsu` や `librootjava` を利用して Java API を root で呼び出す手段もありますが、アプリプロセスと root プロセス間で Binder オブジェクトをやり取りするのは非常に手間がかかります。さらに、root プロセスをデーモン化しても、アプリが再起動した際に Binder を再取得する簡単な方法がありません。

実際、Magisk などの root ソリューションで `su` を動作させるのは意外と大変です。`su` 本体とマネージャアプリ間の通信にも多くの裏工作が必要になります。
</details>

## ユーザーガイド

> 既存の `su` のみをサポートするアプリの動作は変更されません。

### インストール

Sui は KernelSU、Magisk、APatch などの対応する root 管理アプリから直接インストールできます。あるいは [release](https://github.com/XiaoTong6666/Sui/releases) から zip をダウンロードし、root 管理アプリの「ストレージからインストール」でインストールしてください。

Sui の動作には対応した root 環境が必要です。Magisk の場合は **Magisk 24.0 以上で Zygisk が有効** であることが条件です。KernelSU や APatch を利用する場合は、別途 Zygisk 実装（例: [Zygisk Next](https://github.com/Dr-TSNG/ZygiskNext)、[ReZygisk](https://github.com/PerformanC/ReZygisk)、[NeoZygisk](https://github.com/JingMatrix/NeoZygisk)）が必要です。`SystemUI` や `Settings` を Zygisk の DenyList に入れないようにしてください。そうしないと、注入された管理 UI が正しく動作しなくなります。

### 管理 UI

- ホーム画面の **設定** アイコンを長押しすると Sui のショートカットが表示されます。  
- Sui 管理画面で右上のメニューから **ショートカットをホーム画面に追加** を選択できます。  
- デフォルトのダイヤラーアプリで `*#*#784784#*#*` と入力すると Sui が起動します。  
- KernelSU / Magisk 管理アプリの **Action** ボタンからも Sui 管理画面を開くことができます。

> **注** 一部の端末では設定アプリの長押しでショートカットが表示されない場合があります。  
> また、ユーザーへの過度な干渉を防ぐため、最近のバージョンでは **開発者オプション** へ入った際に自動でショートカットを作成する機能は削除されています。

### 権限モード

Sui は UID ごとに権限状態を保持します。主なモードは次の通りです。

* **Ask / default** アプリは Sui に接続でき、通常のフローで権限要求が行われます。  
* **Allow root** アプリは root バックエンドへルーティングされます。  
* **Allow shell** アプリは shell バックエンドへルーティングされます。  
* **Deny** アプリは Sui の利用が拒否されます。  
* **Hide** 対象アプリから Sui が完全に隠蔽されます。`Hide` が有効になると、Native Binder の `execTransact` 段階で対象 UID の Sui Bridge トランザクションが遮断され、`BridgeService` へ到達しません。

権限状態が変わると、Sui は影響を受けたアプリを強制停止し、次回起動時に正しいバックエンドが取得されるようにします。

### インタラクティブシェル

Sui にはインタラクティブシェルが用意されています。

`PATH` にファイルを追加しないため、必要なファイルは手動でコピーする必要があります。自動コピーの手順は `/data/adb/sui/post-install.example.sh` を参照してください。

ファイルが正しく配置されたら、`rish` を `sh` として実行し、シェルを起動します。

### adb root

Sui はオプションで `adb root` をサポートしています。有効化すると、`adbd` 用のラッパーと preload フックが設定され、`adbd` が現在の root 実装の SELinux ドメインで動作しつつ、期待通りの `adbd` ソケットラベルが保たれます。

この機能はデフォルトで無効です。以下のマーカー ファイルを root シェルから作成し、再起動すると `post-fs-data` 段階で有効になります。

* **次回起動だけ有効にする**  

  ```sh
  touch /data/adb/sui/enable_adb_root_once
  ```

* **永続的に有効にする**  

  ```sh
  touch /data/adb/sui/enable_adb_root
  ```

再起動後は通常通り `adb root` が使用可能です。

永続モードを無効にする場合は次のコマンドを実行します。

```sh
rm /data/adb/sui/enable_adb_root
```

> この機能は使用している root 実装や SELinux ポリシーに依存します。Sui は必要な `setcurrent`、`dyntransition`、`setsockcreate` 権限があるかを確認した上で有効化します。  
> 既存アプリの動作は変更されません。影響するのはデバイス上の `adbd` パスだけです。  
> カスタマイズされた `adbd` 実装を搭載した端末では互換性が異なる場合があります。

## アプリ開発ガイド

Sui アプリの開発は、上流の Shizuku API ドキュメントに従うことが基本です。

https://github.com/RikkaApps/Shizuku-API

アプリ側では `rikka.shizuku.Shizuku` を統一的な互換レイヤーとして使用することが推奨されます。Sui 固有のコードパスを保持しないようにしてください。こうすることで、1 つのラッパーで Shizuku と Sui の両方をサポートできます。

通常の統合パターンでは `ShizukuProvider` と標準の Shizuku API フローだけが必要です。`ShizukuProvider` は自動的に Sui の初期化を試みるため、アプリ側で `rikka.sui.Sui` を直接インポートしたり呼び出したりする必要はありません。

以下は自動初期化フローの例です。

```kotlin
import android.content.pm.PackageManager
import android.content.pm.IPackageManager
import rikka.shizuku.Shizuku
import rikka.shizuku.ShizukuBinderWrapper
import rikka.shizuku.SystemServiceHelper

fun initPrivilegedApi() {
    Shizuku.addBinderReceivedListener {
        checkShizukuPermission()
    }

    if (Shizuku.pingBinder()) {
        checkShizukuPermission()
    }
}

fun checkShizukuPermission() {
    if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
        val binder = SystemServiceHelper.getSystemService("package") ?: return
        val pm = IPackageManager.Stub.asInterface(ShizukuBinderWrapper(binder))
        pm.isPackageAvailable("android", 0)
    } else {
        Shizuku.requestPermission(0)
    }
}
```

自動初期化を意図的に無効化したい場合は、ラッパー内部で次のように手動で初期化できます。

```kotlin
Sui.init(packageName)
```

### 主な API

* `Shizuku.pingBinder()`
* `Shizuku.checkSelfPermission()`
* `Shizuku.requestPermission(requestCode)`
* `Shizuku.getUid()` （例: `0` が root、`2000` が shell）
* `SystemServiceHelper.getSystemService(name)`
* `ShizukuBinderWrapper` Android Framework のサービスバインダーをラップ
* `bindUserService()` root または shell で動作する Java サービスを起動

## ビルド

> **注:** 必要な API サブプロジェクトを含めるため、submodule 付きでリポジトリを clone してください。

```bash
git clone --recurse-submodules https://github.com/XiaoTong6666/Sui.git
```

Gradle タスク例（`BuildType` は `Debug` か `Release`）:

* `:module:assemble<BuildType>` モジュールをビルドし、`out/` にフラッシュ可能な zip が生成されます。  
* `:module:zip<BuildType>` フラッシュ用 zip を生成します。  
* `:module:push<BuildType>` `adb` で zip を `/data/local/tmp` に転送します。  
* `:module:flash<BuildType>` `adb shell su -c magisk --install-module` でインストールします。  
* `:module:flashWithKsud<BuildType>` `adb shell su -c ksud module install` でインストールします。  
* `:module:flashAndReboot<BuildType>` インストール後にデバイスを再起動します。  
* `:module:flashWithKsudAndReboot<BuildType>` ksud 経由でインストールし、再起動します。

**例**

```bash
./gradlew :module:assembleRelease
./gradlew :module:zipRelease
./gradlew :module:flashRelease
```

## トラブルシューティング

### Sui のログ取得

```sh
adb logcat -v time | grep -i sui
```

### 問題を報告する方法

問題を報告する場合は、**debug** ビルドで再現したログを添付してください。

- まず **debug** 版の Sui をインストールまたはフラッシュし、問題を再現する。
- **KernelSU** または **APatch** を使っている場合は、先に root マネージャー側のログを書き出してください。モジュールのマウント、Zygisk 注入、SELinux、起動初期段階の問題についてはこちらの方が情報量が多いことがあります。
- 併せて [Sui のログ取得](#sui-のログ取得) を参照してください。
- さらに以下の環境情報も添えてください:
  - root 実装とそのバージョン
  - Zygisk 実装とそのバージョン
  - Android バージョン / ROM
  - `SystemUI` や `Settings` を DenyList に入れているかどうか
  - 正確な再現手順

debug ビルドでは再現せず、release ビルドでのみ発生する場合は、release 固有の症状と正確な再現手順を補足してください。

### Sui 管理画面を開けない

- root 環境が対応していること（Magisk + Zygisk、または KernelSU / APatch + 互換 Zygisk 実装）。
- `SystemUI` と `Settings` が Zygisk DenyList に入っていないこと。
- Sui のインストールまたは更新後に端末を再起動していること。

### オプション機能が期待通り動かない

- Sui のモジュールファイルや marker ファイルを変更した後は、一度端末を再起動してください。
- 必要に応じて KernelSU / APatch のログを書き出し、併せて [Sui のログ取得](#sui-のログ取得) を参照してください。
- 必要に応じて `/data/adb/sui/` 配下の marker ファイルや生成ファイルが存在するかも確認してください。

## 内部構成

Sui は [Zygisk](https://github.com/topjohnwu/zygisk-module-sample) に依存しています。Zygisk により `system_server`、`SystemUI`、`Settings`、および関連アプリプロセスへのインジェクションが可能になります。

**全体で 5 つの主要パートと、オプションの `adb root` パス** が存在します。

* **Root プロセス**  
  `post-fs-data` 段階で起動される root プロセスです。Java サーバーを起動し、Shizuku API とその他プライベート API を提供します。  
  ルートサーバーは権限設定の中心で、UID の権限データベースを管理し、`system_server` に hidden / root allowed / shell allowed / denied / default mode の状態を同期します。

* **Shell プロセス**  
  `shell` 権限で動作し、shell 権限が付与されたアプリにサービスを提供します。  
  ルートサーバーがミラーした設定ファイルから UID 権限を読み込み、権限確認ウィンドウが必要な場合はルートサーバーへ委譲し、SystemUI の確認 UI を起動させます。

* **SystemServer インジェクト**  
  * `Binder#execTransact` をフックし、Sui が利用する専用 Binder トランザクションを `system_server` 内で捕捉。  
  * hidden / root allowed / shell allowed / denied / default mode 各種権限キャッシュを保持。  
  * UID の有効権限に応じて返す Binder を選択：root → root バインダー、shell → shell バインダー。  
  * hidden UID は Sui Bridge リクエストを直接遮断し、ask / deny の場合は root バインダーを返して通常フローへ遷移させます。

* **SystemUI インジェクト**  
  * Sui サービスから APK のファイルディスクリプタを取得し、`Resources` と権限ダイアログクラスをロード。  
  * コールバック時に権限確認ダイアログを表示。  
  * secret‑code 形式のエントリーポイントを登録し、トリガーされると Settings プロセス内でホストされている Sui 管理 UI を起動。

* **Settings インジェクト**  
  * Sui サービスから APK FD を取得し、`Resources` と `SuiActivity` をロード。  
  * `ActivityThread` の `Instrumentation` を差し替え、Settings プロセス起動時に注入。  
  * 動的／固定ショートカットを管理し、SystemUI からのショートカット要求に応答。  
  * 対象 `Activity` の `Intent` に Sui の extra と token が含まれている場合、`SuiActivity` をインスタンス化して表示。

* **adbd wrapper / preload（オプション）**  
  * `adb root` が有効な場合、`post-fs-data` で `/apex/com.android.adbd/bin/adbd` または `/system/bin/adbd` 用のラッパーと preload ライブラリを準備。  
  * ラッパーは `--root_seclabel=…` を現在の root 実装に対応した SELinux ドメインに書き換え、`LD_PRELOAD` を注入。  
  * preload フックは `selinux_android_setcon()`／`setcon()` を捕捉し、`adbd` が root ドメインに切り替わりつつ `sockcreate` ラベルは期待通りの `adbd` ラベルに復元されます。

## ライセンス

Sui は GPL-3.0-or-later の下でライセンスされています。
