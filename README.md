# Terarprise

Cloudflare Workers と D1 で Enterprise IAM の連携を検証するアプリケーションです。企業 IdP は外部サービスを使い、Keycloak の常設は必要ありません。

## ローカル開発

Node.js 22 以降と npm を使用します。

```sh
npm ci
npm run db:migrate
npm run db:seed
npm run dev
```

ブラウザで開くと組織 ID を指定するサインイン画面になります。seed は `acme` と `globex` の組織のみを作ります。実 IdP の設定がない状態では SSO は利用できません。

```sh
npm run typecheck
npm test
npm run build
# dev サーバー起動後、別ターミナルで
npm run test:smoke
```

自動テストは一時的なローカル D1 と署名付き ID トークンを返す模擬 IdP を使います。外部 IdP や Cloudflare アカウントは不要です。模擬 IdP はテスト内だけにあり、アプリに認証を迂回するルートはありません。

## 実 IdP との接続

1. IdP に OIDC アプリを登録します。Authorization Code Flow、PKCE S256、RS256 または ES256 を使用します。リダイレクト URI は `http://localhost:8787/auth/callback`、本番では `https://<ホスト>/auth/callback` です。
2. D1 の `oidc_providers` に組織 ID、正確な issuer（末尾スラッシュも含め一致）、client ID を登録します。issuer と discovery の各 endpoint は HTTPS 必須です。これらは信頼する管理者だけが設定します。
3. `users` に内部 ID・issuer・IdP の不変な subject (`sub`) を登録し、`memberships` に組織 ID・内部ユーザー ID・`admin` または `member` を登録します。メールドメインや自己申告による自動所属は行いません。
4. confidential client の場合、ローカルの `.dev.vars` に `OIDC_CLIENT_SECRETS='{"acme":"<client secret>"}'` を設定します。ファイルをコミットしないでください。本番は `npx wrangler secret put OIDC_CLIENT_SECRETS` を利用します。client_secret_basic / client_secret_post に対応し、秘密鍵 JWT 方式は未対応です。
5. `/auth/login?organization=acme` からログインします。

設定 SQL の例（値は自分の IdP の値に置き換えてください）:

```sql
INSERT INTO oidc_providers VALUES ('acme', 'https://your-idp.example', 'your-client-id');
INSERT INTO users VALUES ('alice', 'https://your-idp.example', 'actual-idp-subject');
INSERT INTO memberships VALUES ('acme', 'alice', 'admin', 1);
```

SQL はローカルで `npx wrangler d1 execute terarprise --local --file=<SQLファイル>` を使って適用します。秘密情報を SQL に含めないでください。

## API とセキュリティ境界

- `GET /health`: D1 のマイグレーション済みテーブルへの読み取りを確認。
- `GET /api/organizations/:id/me`: 現在のユーザーと役割。対象組織に紐づくセッションが必要。
- `GET /api/organizations/:id/admin`: 管理者権限の検証。成功時に監査イベントを記録。
- `GET /api/organizations/:id/audit`: 管理者のみ、当該組織の直近100件を取得。
- `POST /auth/logout`: `Origin` が APP_ORIGIN と一致する場合のみセッション削除。

OIDC は state とブラウザ Cookie の照合、PKCE、nonce、署名・issuer・audience・有効期限の検証を実施します。state は10分間有効で単回利用。セッションは8時間で期限切れになり、D1 にはトークンの SHA-256 ハッシュのみを保存します。本番 HTTPS では `__Host-`、Secure、HttpOnly、SameSite=Lax Cookie を使用します。組織所属・有効状態・役割を毎リクエスト確認し、`memberships.active = 0` の変更は既存セッションにも即時反映されます。

## Cloudflare に配置

1. 自分の Cloudflare アカウントで `npx wrangler d1 create terarprise` を実行。
2. `wrangler.jsonc` の仮 database_id を実 ID に置き換え、APP_ORIGIN を実際の HTTPS origin に設定（末尾 `/` なし）。
3. `npx wrangler d1 migrations apply terarprise --remote` を実行し、組織・IdP・所属を登録。
4. 必要な client secret を登録し、`npm run deploy` を実行。
5. 実 IdP のログイン・組織境界・ログアウト・ユーザー停止を配置先で確認。

アカウント作成、リモート DB 作成、本番デプロイは自動では実行しません。

## 検証計画

この初期実装は OIDC、組織分離、RBAC、セッション、最小限の監査 API が対象です。本番 IAM 製品としての完成を意味しません。

次に、実際の Entra ID / Okta との相互運用性を確認し、SCIM 2.0（ユーザー作成・変更・停止）、監査イベントの拡充・保持・ページング、SSO 管理画面を追加します。続いて SAML、MFA / ステップアップ、ABAC を個別に検証します。IdP ログアウト連携、レート制限、設定変更の運用設計も今後の対象です。
