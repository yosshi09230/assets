# 資産ダッシュボード

自分専用の資産推移ページです。データ（data/db.enc）はパスワードで暗号化されています。

- index.html … ページ本体
- scripts/update.py … 1時間ごとの自動更新（GitHub Actionsで実行）
- .github/workflows/update.yml … 自動更新のスケジュール
- data/db.enc … 暗号化されたデータ（ページの初期設定で作られます）

使い方は別紙の「手順書」を見てください。
