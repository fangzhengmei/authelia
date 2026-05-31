# Authelia WebAuthn 凭据撤销代码分析

## 1. 凭据元数据存储结构

### 1.1 数据库表结构

凭据存储在 `webauthn_credentials` 表中，核心字段如下：

| 字段 | 类型 | 说明 |
|------|------|------|
| id | INTEGER | 主键自增ID |
| created_at | TIMESTAMP | 创建时间 |
| last_used_at | TIMESTAMP | 最后使用时间 |
| rpid | TEXT | 依赖方 ID (Relying Party ID) |
| username | VARCHAR(100) | 用户名 |
| description | VARCHAR(30) | 凭据描述（用户自定义） |
| kid | VARCHAR(512) | 公钥 ID（Base64 编码），**唯一索引** |
| public_key | BLOB | 公钥数据（加密存储） |
| attestation_type | VARCHAR(32) | 证明类型 |
| transport | VARCHAR(64) | 传输方式（逗号分隔） |
| aaguid | CHAR(36) | 认证器 AAGUID |
| sign_count | INTEGER | 签名计数器 |
| clone_warning | BOOLEAN | 克隆警告标志 |
| discoverable | BOOLEAN | 是否可发现（Passkey） |
| present | BOOLEAN | 用户存在标志 |
| verified | BOOLEAN | 用户验证标志 |
| backup_eligible | BOOLEAN | 可备份标志 |
| backup_state | BOOLEAN | 备份状态 |
| attestation | BLOB | 证明数据（加密存储） |

**关键索引**：
- `UNIQUE (username, description)`：同一用户下描述唯一
- `UNIQUE (kid)`：公钥 ID 全局唯一

### 1.2 Go 数据结构

核心结构体定义在 `internal/model/webauthn.go:135-159`：

```go
type WebAuthnCredential struct {
    ID                int           `db:"id"`
    CreatedAt         time.Time     `db:"created_at"`
    LastUsedAt        sql.NullTime  `db:"last_used_at"`
    RPID              string        `db:"rpid"`
    Username          string        `db:"username"`
    Description       string        `db:"description"`
    KID               Base64        `db:"kid"`
    AAGUID            uuid.NullUUID `db:"aaguid"`
    AttestationType   string        `db:"attestation_type"`
    AttestationFormat string        `db:"attestation_format"`
    Attachment        string        `db:"attachment"`
    Transport         string        `db:"transport"`
    SignCount         uint32        `db:"sign_count"`
    CloneWarning      bool          `db:"clone_warning"`
    Legacy            bool          `db:"legacy"`
    Discoverable      bool          `db:"discoverable"`
    Present           bool          `db:"present"`
    Verified          bool          `db:"verified"`
    BackupEligible    bool          `db:"backup_eligible"`
    BackupState       bool          `db:"backup_state"`
    PublicKey         []byte        `db:"public_key"`
    Attestation       []byte        `db:"attestation"`
}
```

### 1.3 加密存储

敏感字段 `public_key` 和 `attestation` 在数据库中通过加密存储，相关结构体在 `internal/storage/types.go:90-94`：

```go
type encWebAuthnCredential struct {
    ID          int    `db:"id"`
    PublicKey   []byte `db:"public_key"`
    Attestation []byte `db:"attestation"`
}
```

---

## 2. discoverable / backup_eligible / backup_state 的状态变化路径

### 2.1 注册写入时的赋值路径

注册流程位于 `internal/handlers/handler_register_webauthn.go:136-252`，分两步完成：

**步骤 1：WebAuthnRegistrationPUT**（发起注册挑战）
- 请求扩展 `credProps: true`（第 99 行），为后续判断 discoverable 做准备
- 调用 `w.BeginRegistration(user, opts...)` 生成挑战

**步骤 2：WebAuthnRegistrationPOST**（完成注册）

标志位的赋值分为三个阶段，代码路径如下：

```
w.CreateCredential(user, sessionData, response)  ← go-webauthn 库解析认证器响应
    │
    │  返回 *webauthn.Credential，其中包含：
    │    credential.Flags.BackupEligible  ← 认证器硬件直接报告
    │    credential.Flags.BackupState     ← 认证器硬件直接报告
    │    credential.Flags.UserPresent     ← 认证器硬件直接报告
    │    credential.Flags.UserVerified    ← 认证器硬件直接报告
    │
    ↓
model.NewWebAuthnCredential(ctx, rpid, username, description, credential)
    │  (internal/model/webauthn.go:98-133)
    │
    │  赋值结果：
    │    BackupEligible = credential.Flags.BackupEligible    ← 来自认证器
    │    BackupState    = credential.Flags.BackupState       ← 来自认证器
    │    Present        = credential.Flags.UserPresent       ← 来自认证器
    │    Verified       = credential.Flags.UserVerified      ← 来自认证器
    │    Discoverable   = false                              ← 硬编码为 false！
    │
    ↓
credential.Discoverable = iwebauthn.IsCredentialCreationDiscoverable(logger, response)
    │  (internal/handlers/handler_register_webauthn.go:222)
    │  (internal/webauthn/util.go:16-45)
    │
    │  判断逻辑：读取 response.ClientExtensionResults["credProps"]["rk"]
    │    ├─ credProps 扩展存在且 rk=true  → Discoverable = true  (Passkey)
    │    └─ 其他所有情况                   → Discoverable = false (安全密钥)
    │
    ↓
iwebauthn.ValidateCredentialAllowed(&config.WebAuthn, &credential)
    │  (internal/webauthn/util.go:47-69)
    │
    │  过滤检查（仅注册阶段执行，断言阶段不执行）：
    │    ├─ config.Filtering.ProhibitBackupEligibility && credential.BackupEligible
    │    │   → 返回错误，拒绝注册 backup_eligible 的凭据
    │    ├─ AAGUID 不在 PermittedAAGUIDs 列表中
    │    │   → 返回错误，拒绝注册
    │    └─ AAGUID 在 ProhibitedAAGUIDs 列表中
    │        → 返回错误，拒绝注册
    │
    ↓
SaveWebAuthnCredential(ctx, credential)
    │  INSERT INTO webauthn_credentials (..., discoverable, ..., backup_eligible, backup_state, ...)
    │  VALUES (..., ?, ..., ?, ?, ...)
```

**三个标志位的初始值来源**：

| 标志位 | 来源 | 含义 |
|--------|------|------|
| `discoverable` | 浏览器 `credProps` 扩展中的 `rk` 字段，**非认证器直接报告** | 凭据是否存储在认证器上（可免用户名登录） |
| `backup_eligible` | 认证器硬件的 `Flags.BackupEligible` | 认证器是否支持凭据备份（如 iCloud Keychain、Google Password Manager） |
| `backup_state` | 认证器硬件的 `Flags.BackupState` | 凭据当前是否已被备份到云端 |

### 2.2 凭据删除时的状态变化

**关键结论：删除是物理删除（DELETE FROM），三个标志位随整行数据一起消失，不存在独立的标志位变更或级联更新。**

删除 SQL（`internal/storage/sql_provider_queries.go:220-230`）：

```sql
-- 按 KID 删除
DELETE FROM webauthn_credentials WHERE kid = ?;

-- 按用户名删除所有
DELETE FROM webauthn_credentials WHERE username = ?;

-- 按用户名+描述删除
DELETE FROM webauthn_credentials WHERE username = ? AND description = ?;
```

**级联影响分析**：

1. **`webauthn_credentials` 行被删除** → 三个标志位随行消失
2. **`LoadUserInfo` 查询的 `has_webauthn` 字段**（`internal/storage/sql_provider_queries.go:37-40`）：
   ```sql
   SELECT ... (SELECT EXISTS (SELECT id FROM webauthn_credentials WHERE username = ?)) AS has_webauthn ...
   ```
   删除后 `has_webauthn` 自动变为 `false`，影响用户偏好 2FA 方法的自动降级逻辑（`internal/model/user_info.go:52-57`）。
3. **无其他表引用这些标志位**，不存在级联更新需求。

### 2.3 断言校验拒绝中标志位的读取与判断

断言（Assertion）阶段涉及两次数据库查询和一次写入，标志位在不同环节的作用：

#### 环节 A：WebAuthnAssertionGET（生成挑战）

**代码位置**：`internal/handlers/handler_sign_webauthn.go:20-124`

```
handleGetWebAuthnUserByRPID(ctx, username, displayname, rpid)
    │
    ├─ LoadWebAuthnUser(ctx, rpid, username)
    │     → 加载 WebAuthnUser（不含凭据）
    │
    └─ LoadWebAuthnCredentialsByUsername(ctx, rpid, username)
          │ (internal/storage/sql_provider_queries.go:189-192)
          │
          │ SQL: SELECT ... discoverable, ..., backup_eligible, backup_state, ...
          │      FROM webauthn_credentials
          │      WHERE username = ? AND (? = FALSE OR discoverable = TRUE)
          │                                          ↑___________________↑
          │                                          第三个参数为布尔值，
          │                                          为 FALSE 时忽略 discoverable 过滤，
          │                                          为 TRUE 时只返回 discoverable=TRUE 的凭据
          │
          └─ 此处 LoadWebAuthnCredentialsByUsername 传入的第三参数固定为 FALSE
             → 返回该用户在当前 rpid 下的所有凭据（无论 discoverable 值）
```

**discoverable 在此环节的影响**：
- `user.HasFIDOU2F()` 检查（`internal/model/webauthn.go:34-42`）：如果任何凭据的 `AttestationType == "fido-u2f"`，则在 assertion 扩展中附加 `appid`
- `user.WebAuthnCredentialDescriptors()` 将所有凭据转为 `allowedCredentials` 列表返回浏览器
- **如果凭据已被删除**，它根本不会出现在查询结果中，浏览器收到的 `allowedCredentials` 不包含已删除凭据的 KID

**backup_eligible / backup_state 在此环节**：仅作为数据字段被 SELECT 出来，不参与任何判断逻辑。

#### 环节 B：WebAuthnAssertionPOST（验证签名）

**代码位置**：`internal/handlers/handler_sign_webauthn.go:129-283`

**关键修正：UpdateSignInInfo 实际更新范围**

```go
// internal/model/webauthn.go:162-178
func (c *WebAuthnCredential) UpdateSignInInfo(config *webauthn.Config, now time.Time, credential *webauthn.Credential) {
    c.LastUsedAt = sql.NullTime{Time: now, Valid: true}
    c.SignCount, c.CloneWarning = credential.Authenticator.SignCount, credential.Authenticator.CloneWarning

    c.UpdateAttestationType(credential)  // 仅当 AttestationType 为空时才更新

    if c.RPID != "" || config == nil {
        return  // ← 直接 return，后续 RPID 设置仅对遗留凭据生效
    }

    // RPID 设置（仅对 RPID 为空的老凭据执行）
    switch c.AttestationType {
    case attestationTypeFIDOU2F:
        c.RPID = config.RPOrigins[0]
    default:
        c.RPID = config.RPID
    }
}
```

**UpdateSignInInfo 实际只更新以下字段**：
| 字段 | 是否更新 | 备注 |
|------|---------|------|
| `LastUsedAt` | ✅ 是 | 登录时间戳 |
| `SignCount` | ✅ 是 | 签名计数器，用于克隆检测 |
| `CloneWarning` | ✅ 是 | 克隆警告标志 |
| `AttestationType` | ⚠️ 条件 | 仅当数据库中为空时更新 |
| `RPID` | ⚠️ 条件 | 仅当数据库中为空时更新 |
| `Discoverable` | ❌ 否 | **不更新**，保持数据库原值 |
| `Present` | ❌ 否 | **不更新**，保持数据库原值 |
| `Verified` | ❌ 否 | **不更新**，保持数据库原值 |
| `BackupEligible` | ❌ 否 | **不更新**，保持数据库原值 |
| `BackupState` | ❌ 否 | **不更新**，保持数据库原值 |

> **重要**：尽管 `UpdateWebAuthnCredentialSignIn` 的 SQL UPDATE 语句包含所有这些字段（`internal/storage/sql_provider_queries.go:209-214`），但由于 `UpdateSignInInfo` 不修改后五个字段，数据库中会写回 SELECT 时的原值。

**2FA 断言成功后的写回逻辑**：
```
w.ValidateLogin(user, sessionData, response)
    │ → go-webauthn 库验证签名
    │ → 如果 KID 不在 user.Credentials 中 → 返回错误
    │
    ↓  验证成功后：
for _, credential := range user.Credentials {
    if bytes.Equal(credential.KID.Bytes(), c.ID) {
        credential.UpdateSignInInfo(w.Config, now, c)
            │ → 仅更新 LastUsedAt、SignCount、CloneWarning
            │ → Present/Verified/BackupEligible/BackupState/Discoverable 保持不变
            │
        UpdateWebAuthnCredentialSignIn(ctx, credential)
            │ → SQL UPDATE 写回所有字段，但上述字段为原值
    }
}
```

**backup_eligible / backup_state 在断言校验拒绝中的角色**：

这两个标志位**完全不参与 2FA 断言的拒绝判定**。它们的唯一用途是：
1. 注册时写入数据库，记录认证器硬件能力
2. 在 `VerifyCredential`（MDS 元数据验证 CLI）中标记违反策略的凭据（如 `ProhibitBackupEligibility`）
3. **不影响任何登录验证流程**

**discoverable 在 2FA 断言阶段的影响**：
- 2FA 断言加载凭据时不按 discoverable 过滤（第三参数为 FALSE），所有凭据都返回
- `UpdateSignInInfo` 不修改 Discoverable 字段
- 只有在 Passkey 第一因子登录时才会触发 discoverable 的被动升级（见第 5 章）

---

## 3. 凭据撤销方式

### 3.1 用户主动删除（Web UI）

#### API 端点
- **路由**：`DELETE /api/secondfactor/webauthn/credential/{credentialID}`
- **中间件**：`middlewareElevated1FA`（需要已认证的 1FA 会话提升）
- **代码位置**：`internal/server/handlers.go:335`

#### 处理流程
Handler 实现在 `internal/handlers/handler_webauthn_credentials.go:204-275`：

```
1. 验证用户会话
   ↓
2. 从 URL 路径解析 credentialID
   ↓
3. 按 ID 从数据库加载凭据
   ↓
4. 权限校验：凭据.Username == 当前会话.Username
   ↓
5. 调用存储层 DeleteWebAuthnCredential(凭据.KID.String())
   ↓
6. 记录审计日志（event_log_action2FARemoved）
   ↓
7. 返回 200 OK
```

#### 关键代码点
```go
if credential.Username != userSession.Username {
    ctx.SetStatusCode(fasthttp.StatusForbidden)
    return
}

if err = ctx.Providers.StorageProvider.DeleteWebAuthnCredential(
    ctx, credential.KID.String()); err != nil {
    // 错误处理
}
```

### 3.2 管理员强制清理（CLI 命令）

#### 命令格式
```bash
authelia storage user webauthn delete john --all
authelia storage user webauthn delete john --description "YubiKey 5"
authelia storage user webauthn delete --kid "AAECAwQFBgcICQoLDA0ODw"
```

#### 代码入口
- 命令定义：`internal/commands/storage.go:412` → `newStorageUserWebAuthnCmd`
- RunE 函数：`internal/commands/storage_run.go:1444-1465` → `StorageUserWebAuthnDeleteRunE`

#### 存储层删除函数

**按 KID 删除**（`internal/storage/sql_provider.go:774-781`）：
```go
func (p *SQLProvider) DeleteWebAuthnCredential(ctx context.Context, kid string) error {
    _, err := p.db.ExecContext(ctx, p.sqlDeleteWebAuthnCredential, kid)
    // DELETE FROM webauthn_credentials WHERE kid = ?
}
```

**按用户名/描述删除**（`internal/storage/sql_provider.go:783-801`）：
```go
func (p *SQLProvider) DeleteWebAuthnCredentialByUsername(
    ctx context.Context, username, displayname string) error {
    if len(displayname) == 0 {
        // DELETE FROM webauthn_credentials WHERE username = ?
    } else {
        // DELETE FROM webauthn_credentials WHERE username = ? AND description = ?
    }
}
```

---

## 4. 与活跃会话的关系

### 4.1 会话数据结构
**位置**：`internal/session/types.go:20-48`

```go
type UserSession struct {
    Username    string
    FirstFactorAuthnTimestamp  int64
    SecondFactorAuthnTimestamp int64
    AuthenticationMethodRefs   authorization.AuthenticationMethodsReferences
    // 会话中只记录认证时间戳和认证方法引用，不绑定具体的凭据 ID 或 KID
}
```

### 4.2 关键发现：**撤销不会立即使已有会话失效**

会话认证状态是**一次性的**，在登录时验证通过后就不再检查凭据是否仍然存在。

#### 授权中间件行为
**位置**：`internal/middlewares/require_auth.go:11-21`

```go
func Require1FA(next RequestHandler) RequestHandler {
    return func(ctx *AutheliaCtx) {
        // 只检查认证级别，不检查凭据是否存在
        if s.AuthenticationLevel(...) < authentication.OneFactor {
            ctx.ReplyForbidden()
            return
        }
        next(ctx)
    }
}
```

**影响**：
- 用户删除硬件密钥后，**已登录的会话仍然有效**
- 直到会话过期、用户主动登出、或需要重新认证时才会被拒绝

#### 例外：需要会话提升的操作
删除凭据本身需要 **Elevated Session**（会话提升）：
- **位置**：`internal/server/handlers.go:335` → `middlewareElevated1FA`
- 删除凭据时会检查提升会话是否有效
- 但删除成功后，对其他已存在的普通会话没有影响

---

## 5. Passkey 第一因子登录与 discoverable 被动升级

### 5.1 Passkey 第一因子登录入口

**端点**（需 `EnablePasskeyLogin: true`）：
- GET `/api/firstfactor/passkey` - 生成 Passkey 断言挑战
- POST `/api/firstfactor/passkey` - 验证 Passkey 断言

**路由注册**：`internal/server/handlers.go:321-324`
```go
if config.WebAuthn.EnablePasskeyLogin {
    r.GET("/api/firstfactor/passkey", middlewareAPI(handlers.FirstFactorPasskeyGET))
    r.POST("/api/firstfactor/passkey", middlewareAPI(handlers.FirstFactorPasskeyPOST))
    r.POST("/api/secondfactor/password", middleware1FA(handlers.SecondFactorPasswordPOST(funcDelayPassword)))
}
```

### 5.2 discoverable 被动升级机制

**关键代码**：`internal/handlers/handler_firstfactor_passkey.go:220-244`

```go
for _, credential := range user.Credentials {
    if bytes.Equal(credential.KID.Bytes(), c.ID) {
        credential.UpdateSignInInfo(w.Config, ctx.GetClock().Now().UTC(), c)

        // ┌─────────────────────────────────────────────────────────────┐
        // │  discoverable 被动升级：                                      │
        // │  如果一个非 Passkey 的凭据被用于 Passkey 第一因子登录，         │
        // │  自动升级为 discoverable=true                                 │
        // └─────────────────────────────────────────────────────────────┘
        if !credential.Discoverable {
            credential.Discoverable = true

            ctx.Logger.WithFields(map[string]any{
                "kid": credential.KID.String(),
                "rpid": credential.RPID,
                "aaguid": credential.AAGUID.UUID.String(),
                "username": credential.Username,
                "description": credential.Description,
            }).Debug("WebAuthn Credential Passively Upgraded to a Passkey")
        }

        ok = true

        // UPDATE 写回：discoverable 已被上述代码改为 true
        if err = ctx.Providers.StorageProvider.UpdateWebAuthnCredentialSignIn(ctx, credential); err != nil {
            // 错误处理
        }

        break
    }
}
```

**被动升级触发条件**：
1. 用户使用 **Passkey 第一因子** 登录（不是 2FA WebAuthn）
2. 凭据在数据库中 `discoverable = false`（注册时非 Passkey）
3. 该凭据实际上能被 Passkey 流程发现和使用（认证器支持）
4. → 自动将 `discoverable` 设为 `true` 并写回数据库

**设计意图**：将旧版安全密钥"升级"为 Passkey，支持后续免用户名登录。

### 5.3 凭据加载的 discoverable 过滤

Passkey 登录时的凭据加载回调：`internal/handlers/webauthn.go:48-69`

```go
func handlerWebAuthnDiscoverableLogin(ctx *middlewares.AutheliaCtx, rpid string) webauthn.DiscoverableUserHandler {
    return func(rawID, userHandle []byte) (user webauthn.User, err error) {
        // ... 加载 WebAuthnUser ...

        if ctx.Configuration.WebAuthn.EnablePasskeyUpgrade {
            // 升级模式：加载所有凭据，允许被动升级
            u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnCredentialsByUsername(...)
        } else {
            // 非升级模式：只加载 discoverable=true 的 Passkey 凭据
            u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnPasskeyCredentialsByUsername(...)
        }
        // LoadWebAuthnPasskeyCredentialsByUsername 传入第三参数为 TRUE
        // → SQL: WHERE ... AND (? = FALSE OR discoverable = TRUE)
        // → 只返回 discoverable=TRUE 的凭据
    }
}
```

**配置对凭据加载的影响**：
| `EnablePasskeyUpgrade` | 凭据加载范围 | 被动升级？ |
|------------------------|-------------|-----------|
| `true` | 该用户所有 WebAuthn 凭据 | 可能触发 |
| `false` | 仅 `discoverable=true` 的凭据 | 不可能（非 Passkey 凭据不加载） |

---

## 6. ValidatePasskeyLogin 拒绝分支完整路径

### 6.1 Passkey 第一因子登录拒绝分支

**代码位置**：`internal/handlers/handler_firstfactor_passkey.go:94-271`

Passkey 1FA 登录的完整拒绝链路（从上到下按优先级排列）：

```
FirstFactorPasskeyPOST
    │
    ├─ 拒绝分支 1：获取 Session Provider 失败
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志：errStrUserSessionData
    │
    ├─ 拒绝分支 2：获取会话失败
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志：errStrUserSessionData
    │
    ├─ 拒绝分支 3：用户已认证（非匿名）
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志：errUserIsAlreadyAuthenticated
    │   → doMarkAuthenticationAttempt（AuthTypePasskey）
    │
    ├─ 拒绝分支 4：请求体解析失败
    │   → HTTP 400 + "Authentication failed, please retry later."
    │   → 日志：errStrReqBodyParse
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 5：解析断言响应失败
    │   → HTTP 400 + "Authentication failed, please retry later."
    │   → 日志：errStrReqBodyParse
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 6：会话中无 WebAuthn 挑战数据
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志："challenge session data is not present"
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 7：获取 WebAuthn Provider 失败
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志："error occurred provisioning the configuration"
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 8：ValidatePasskeyLogin 密码学验证失败（核心！）
    │   │
    │   ├─ 子分支 8a：凭据已被删除
    │   │   → handlerWebAuthnDiscoverableLogin 加载凭据时返回空列表
    │   │   → go-webauthn 库找不到匹配公钥
    │   │
    │   ├─ 子分支 8b：签名验证失败
    │   │   → 用数据库公钥验证浏览器签名不通过
    │   │
    │   ├─ 子分支 8c：RPID/Origin 不匹配
    │   │
    │   └─ 子分支 8d：签名计数器倒退（克隆检测）
    │
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志："error performing the login validation"
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 9：返回的 User 对象类型错误
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志："the user object was not of the correct type"
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 10：凭据在数据库中找不到（冗余安全网）
    │   → 遍历 user.Credentials 无匹配 KID → ok=false
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志："credential was not found"
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 11：CloneWarning 检测
    │   → c.Authenticator.CloneWarning = true
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志："authenticator sign count indicates that it is cloned"
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 12：获取用户详情失败（LDAP/文件 backend）
    │   → HTTP 403 + "Authentication failed, please retry later."
    │   → 日志："error retrieving user details"
    │   → doMarkAuthenticationAttempt
    │
    ├─ 拒绝分支 13：用户被封禁
    │   → HTTP 401 + "Authentication failed, please retry later."
    │   → regulation.ErrUserIsBanned
    │   → doMarkAuthenticationAttempt
    │
    └─ 拒绝分支 14：会话重新生成失败
        → HTTP 403 + "Authentication failed, please retry later."
        → 日志："error regenerating the user session"
        → doMarkAuthenticationAttempt
```

---

## 7. 1FA Passkey 与 2FA Assertion 拒绝链路对比与排查优先级

### 7.1 拒绝链路核心差异对比

| 对比项 | 2FA WebAuthn Assertion | 1FA Passkey Login |
|--------|-----------------------|-------------------|
| **端点** | `/api/secondfactor/webauthn` | `/api/firstfactor/passkey` |
| **前置条件** | 需要已完成 1FA（有会话） | 匿名会话 |
| **Validate 函数** | `w.ValidateLogin()` | `w.ValidatePasskeyLogin()` |
| **凭据加载方式** | 按用户名加载所有凭据 | 通过 userHandle 回调发现用户，再加载凭据 |
| **discoverable 过滤** | 不过滤（全部加载） | 非升级模式下只加载 discoverable=true |
| **discoverable 被动升级** | ❌ 无 | ✅ 有（`FirstFactorPasskeyPOST:224`） |
| **凭据删除后失败点** | ValidateLogin + found=false 双重检查 | ValidatePasskeyLogin + ok=false 双重检查 |
| **失败后会话状态** | 保留 1FA 会话 | 保持匿名 |
| **失败日志关键词** | "validating a WebAuthn authentication challenge" | "validating a WebAuthn passkey authentication challenge" |
| **AuthType** | `AuthTypeWebAuthn` | `AuthTypePasskey` |

### 7.2 排查优先级指南

当收到"认证失败"但需要区分原因时，按以下优先级排查：

#### 优先级 1：高风险（优先排查）

| 场景 | 排查方法 | 特征 |
|------|---------|------|
| **凭据已被管理员删除** | 搜索日志中 `"credential was not found"` | 同时出现于拒绝分支 10（Passkey）或拒绝分支 B（2FA） |
| **签名验证失败** | 搜索日志中 `"error performing the login validation"` 或 `"error comparing the response"` | go-webauthn 库返回的详细错误，可能表示凭据被篡改或冒用 |
| **CloneWarning 克隆检测** | 搜索日志中 `"authenticator sign count indicates that it is cloned"` | 明确表示凭据可能被克隆 |

#### 优先级 2：配置/环境问题

| 场景 | 排查方法 | 特征 |
|------|---------|------|
| **Session Provider 故障** | 搜索日志中 `errStrUserSessionData` | 通常伴随 Redis/数据库连接问题 |
| **WebAuthn Provider 配置错误** | 搜索日志中 `"error occurred provisioning the configuration"` | RPID/Origin 配置不匹配 |
| **用户被封禁** | 搜索日志中 `ErrUserIsBanned` | HTTP 401 而非 403 |

#### 优先级 3：请求/会话问题

| 场景 | 排查方法 | 特征 |
|------|---------|------|
| **会话中无挑战数据** | 搜索日志中 `"challenge session data is not present"` | 会话超时或浏览器清理 Cookie |
| **请求体解析失败** | 搜索日志中 `errStrReqBodyParse` | 浏览器端 JS 错误或网络传输问题 |
| **用户已认证** | 搜索日志中 `errUserIsAlreadyAuthenticated` | 用户刷新页面导致重复提交 |

### 7.3 凭据删除后的排查路径

**管理员删除凭据后，用户登录失败的排查顺序**：

```
1. 确认删除操作已执行
   ├─ 运行: authelia storage user webauthn list <username>
   └─ 确认目标凭据不在列表中

2. 检查 Authelia 日志
   ├─ Passkey 登录失败 → 搜索 "validating a WebAuthn passkey"
   │   └─ 关键词: "credential was not found" 或 "error performing the login validation"
   └─ 2FA 登录失败 → 搜索 "validating a WebAuthn authentication challenge"
       └─ 关键词: "credential was not found" 或 "error comparing the response"

3. 验证数据库状态
   └─ 直接查询: SELECT * FROM webauthn_credentials WHERE username = '<username>';
       └─ 确认行已物理删除

4. 检查用户会话状态
   ├─ 如果用户已登录 → 会话仍然有效，需等待过期或手动登出
   └─ 如果用户未登录 → 下次登录时直接被拒绝
```

---

## 8. 管理员执行 `storage user webauthn delete` 后 assertion 拒绝的完整分支

### 8.1 删除操作执行

```bash
authelia storage user webauthn delete john --all
```

**代码路径**：
```
internal/commands/storage_run.go:1445  StorageUserWebAuthnDeleteRunE
    ↓ 解析参数：all=true, byKID=false, user="john"
internal/commands/storage_run.go:1468  runStorageUserWebAuthnDelete
    ↓ all=false (按用户名), description=""
internal/storage/sql_provider.go:783  DeleteWebAuthnCredentialByUsername(ctx, "john", "")
    ↓
SQL: DELETE FROM webauthn_credentials WHERE username = 'john'
    ↓
整行删除，包括 kid、public_key、discoverable、backup_eligible、backup_state 全部消失
```

### 8.2 被删除用户下次登录时的拒绝分支

#### 场景 A：用户仍持有 1FA 会话，尝试 2FA WebAuthn 断言

**步骤 1：GET /api/secondfactor/webauthn/assertion**

```
WebAuthnAssertionGET (handler_sign_webauthn.go:20)
    ↓
handleGetWebAuthnUserByRPID(ctx, "john", ...)
    ↓
LoadWebAuthnCredentialsByUsername(ctx, rpid, "john")
    ↓ SQL: SELECT ... FROM webauthn_credentials WHERE rpid=? AND username='john' AND (FALSE OR discoverable=TRUE)
    ↓ 返回：空列表 []（所有凭据已删除）
    ↓
user.Credentials = []
    ↓
user.HasFIDOU2F() → false（无凭据）
    ↓
w.BeginLogin(user, opts...)
    ↓ go-webauthn 库：user.WebAuthnCredentials() 返回空列表
    ↓ go-webauthn 库：user.WebAuthnCredentialDescriptors() 返回空 allowedCredentials
    ↓
    │ ┌─────────────────────────────────────────────────────────┐
    │ │  关键分支：当 allowedCredentials 为空时                    │
    │ │  go-webauthn 库的 BeginLogin 行为：                       │
    │ │    - 如果用户没有任何凭据，BeginLogin 可能返回错误          │
    │ │    - 或者返回一个不含 allowCredentials 的 assertion       │
    │ │    - 浏览器收到后无法匹配任何认证器                         │
    │ └─────────────────────────────────────────────────────────┘
    ↓
如果 BeginLogin 返回错误：
    → HTTP 403
    → JSON: {"status": "KO", "message": "Authentication failed, please retry later."}
    → 日志: "Error occurred generating a WebAuthn authentication challenge for user 'john':
             error occurred starting the authentication session"

如果 BeginLogin 成功（返回空 allowedCredentials 的 assertion）：
    → 浏览器无法匹配认证器，用户看到浏览器原生的"没有可用的安全密钥"提示
```

**步骤 2：POST /api/secondfactor/webauthn/assertion**（假设浏览器仍尝试提交签名）

```
WebAuthnAssertionPOST (handler_sign_webauthn.go:129)
    ↓
handleGetWebAuthnUserByRPID(ctx, "john", ...)
    ↓
LoadWebAuthnCredentialsByUsername → 返回空列表
    ↓
user.Credentials = []
    ↓
w.ValidateLogin(user, sessionData, response)
    ↓ go-webauthn 库：在 user.WebAuthnCredentials() 中找不到匹配的公钥
    ↓ 返回错误：credential not found 或类似错误
    ↓
    │ ┌─────────────────────────────────────────────────────────────┐
    │ │  拒绝分支 A（主要路径）                                       │
    │ │  代码: handler_sign_webauthn.go:206-212                      │
    │ │                                                              │
    │ │  if c, err = w.ValidateLogin(user, ...); err != nil {        │
    │ │      doMarkAuthenticationAttempt(ctx, false, ban,            │
    │ │          regulation.AuthTypeWebAuthn, iwebauthn.FormatError(err)) │
    │ │          ↓                                                   │
    │ │          regulation.HandleAttempt(ctx, false, ...)            │
    │ │          → 记录失败尝试，可能触发速率限制封禁                   │
    │ │                                                              │
    │ │      ctx.SetStatusCode(fasthttp.StatusForbidden)              │
    │ │      ctx.SetJSONError(messageMFAValidationFailed)             │
    │ │          ↓                                                   │
    │ │          "Authentication failed, please retry later."         │
    │ │                                                              │
    │ │      return  ← 终止处理                                      │
    │ │  }                                                           │
    │ └─────────────────────────────────────────────────────────────┘
    ↓
（如果 ValidateLogin 意外通过，进入拒绝分支 B）
    ↓
for _, credential := range user.Credentials {  ← 空列表，不进入循环
    ...
}
found = false
    ↓
    │ ┌─────────────────────────────────────────────────────────────┐
    │ │  拒绝分支 B（冗余安全网）                                     │
    │ │  代码: handler_sign_webauthn.go:244-251                      │
    │ │                                                              │
    │ │  if !found {                                                 │
    │ │      ctx.Logger.WithError(fmt.Errorf("credential was not found")) │
    │ │          .Errorf("Error occurred validating a WebAuthn       │
    │ │                   authentication challenge for user '%s':    │
    │ │                   error occurred saving the credential       │
    │ │                   sign-in information to storage",           │
    │ │                   userSession.Username)                      │
    │ │                                                              │
    │ │      ctx.SetStatusCode(fasthttp.StatusForbidden)              │
    │ │      ctx.SetJSONError(messageMFAValidationFailed)             │
    │ │          ↓                                                   │
    │ │          "Authentication failed, please retry later."        │
    │ │                                                              │
    │ │      return  ← 终止处理                                      │
    │ │  }                                                           │
    │ └─────────────────────────────────────────────────────────────┘
```

#### 场景 B：用户完全没有会话，从登录页开始

```
1FA 登录成功 → 进入 2FA 选择页面
    ↓
前端调用 /api/user/info 或 /api/secondfactor/webauthn/credentials
    ↓
LoadUserInfo(ctx, "john")
    ↓ SQL: SELECT ... (SELECT EXISTS (SELECT id FROM webauthn_credentials WHERE username='john')) AS has_webauthn ...
    ↓ has_webauthn = false（凭据已删除）
    ↓
前端 UI：WebAuthn 选项不显示或标记为不可用
    ↓
用户只能选择其他 2FA 方式（TOTP / Duo）
    ↓
如果没有其他 2FA 方式 → 用户被锁定，无法完成 2FA
```

### 8.3 断言拒绝返回给客户端的信息

**HTTP 响应格式**：

```json
// 所有拒绝分支统一返回相同格式
{
    "status": "KO",
    "message": "Authentication failed, please retry later."
}
```

**服务端日志差异**（区分不同拒绝原因）：

| 拒绝分支 | 日志关键词 | 日志级别 |
|----------|-----------|---------|
| ValidateLogin 失败（凭据已删除，公钥不存在） | `error comparing the response to the WebAuthn session data` | ERROR |
| found=false（冗余检查） | `credential was not found` | ERROR |
| CloneWarning 检测 | `authenticator sign count indicates that it is cloned` | ERROR |
| 会话数据缺失 | `challenge session data is not present` | ERROR |

**注意**：客户端无法区分"凭据已删除"和"签名验证失败"，这是一个安全设计——不向攻击者泄露凭据是否存在的具体信息。

---

## 9. 多设备/多域名同步状态

### 9.1 凭据撤销的跨设备影响

| 场景 | 影响 |
|------|------|
| **同一设备不同域名** | 共享同一个会话，撤销不影响已登录状态 |
| **不同设备** | 各有各的会话，撤销不影响对方已登录状态 |
| **Passkey 同步** | 硬件密钥内部的跨设备同步由厂商管理，Authelia 只在验证时检查凭据是否存在于数据库 |

### 9.2 关键边界：Passkey 升级
**位置**：`internal/handlers/webauthn.go:58-66`

```go
if ctx.Configuration.WebAuthn.EnablePasskeyUpgrade {
    u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnCredentialsByUsername(...)
} else {
    u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnPasskeyCredentialsByUsername(...)
}
```

**注意**：删除 Passkey 凭据会影响免用户名登录流程，但已登录的会话仍然有效。

---

## 10. 丢失硬件密钥后的立即处置清单

### 10.1 第一步：删除凭据（立刻执行）

```bash
# 方式 A：删除该用户所有 WebAuthn 凭据（推荐，最安全）
authelia storage user webauthn delete <username> --all \
    --config /etc/authelia/configuration.yml

# 方式 B：如果知道丢失密钥的描述，精确删除
authelia storage user webauthn delete <username> --description "YubiKey 5C" \
    --config /etc/authelia/configuration.yml

# 方式 C：如果知道丢失密钥的 KID，按 KID 删除
authelia storage user webauthn delete --kid "<base64-kid>" \
    --config /etc/authelia/configuration.yml
```

**验证删除结果**：
```bash
authelia storage user webauthn list <username> --config /etc/authelia/configuration.yml
# 确认输出中不包含已删除的凭据
```

**注意**：
- 此操作直接操作数据库，**无需重启 Authelia 服务**
- 删除是物理删除（DELETE FROM），**不可恢复**（除非有数据库备份）
- 如果删除了用户的**唯一 2FA 方式**，用户将无法完成 2FA 登录

### 10.2 第二步：处理活跃会话

**风险**：凭据删除后，用户在已登录设备上的会话仍然有效。

| 处置方式 | 操作 | 效果 |
|----------|------|------|
| **等待会话自然过期** | 无需操作 | 会话在配置的 `session.expiration` 或 `session.inactivity` 到期后自动失效 |
| **用户主动登出** | 用户访问 `/api/logout` | 仅销毁当前设备的会话，其他设备不受影响（`internal/handlers/handler_logout.go:28`：`ctx.DestroySession()`） |
| **全局会话销毁** | 重启 Authelia 实例（如果 session provider 使用内存） | 所有用户会话全部失效 |
| **Redis 会话销毁** | `redis-cli FLUSHDB`（如果使用 Redis session store） | 所有用户会话全部失效，但需确认 Redis 仅用于 session |
| **数据库会话销毁** | 删除对应 session 表中的行 | 需要精确匹配用户，Authelia 当前不提供内置 API |

**推荐做法**：
- 如果丢失的密钥有被冒用的高风险（如无 PIN 保护的 U2F 密钥），建议重启 Authelia 或清空 session store
- 如果密钥有 PIN/生物识别保护，等待会话自然过期即可

### 10.3 第三步：风险评估与后续处理

#### 风险评估检查项

| 检查项 | 判断依据 | 风险等级 |
|--------|---------|---------|
| **密钥是否有 PIN/生物识别保护** | `verified` 字段为 `true` 表示认证器支持用户验证 | 低（有保护）/ 高（无保护） |
| **密钥是否为 Passkey（可同步）** | `discoverable=true` 且 `backup_eligible=true` | 高（可能已同步到云端/其他设备） |
| **密钥是否已被备份** | `backup_state=true` | 高（凭据副本存在于云端） |
| **丢失到报告的时间窗口** | 越长风险越高 | 取决于时间 |
| **该用户是否具有高权限** | 管理员/特权账户 | 高 |

#### 高风险场景追加操作

1. **如果是 Passkey 且 backup_state=true**：
   - 密钥可能已同步到攻击者设备
   - 建议清空所有 session store
   - 考虑重置用户密码

2. **如果用户无其他 2FA 方式**：
   - 删除 WebAuthn 凭据后用户将无法登录
   - 需要同时为用户配置替代 2FA（TOTP 或 Duo）
   - 或临时降低该用户的策略要求

3. **审计日志检查**：
   - 查看 Authelia 日志中该用户在丢失窗口期内的认证记录
   - 确认无异常登录行为
   - 检查 `regulation` 表中是否有被拦截的尝试

4. **注册新密钥**：
   - 用户登录后（通过替代 2FA），在设置页面注册新的硬件密钥
   - 注册时确认 `backup_eligible` 和 `backup_state` 的值符合安全策略
   - 如果组织策略禁止云端同步密钥，配置 `webauthn.filtering.prohibit_backup_eligibility: true`

---

## 11. 代码调用链总结

### 11.1 用户删除流程
```
前端 WebAuthnCredentialsPanel.tsx
    ↓ DELETE /api/secondfactor/webauthn/credential/{id}
internal/server/handlers.go:335 (路由注册)
    ↓ middlewareElevated1FA
internal/handlers/handler_webauthn_credentials.go:205 (WebAuthnCredentialDELETE)
    ├─ 检查会话权限
    ├─ LoadWebAuthnCredentialByID(id)
    ├─ 校验 credential.Username == session.Username
    └─ DeleteWebAuthnCredential(kid)
        ↓
internal/storage/sql_provider.go:775
    ↓ DELETE FROM webauthn_credentials WHERE kid = ?
```

### 11.2 管理员删除流程
```
authelia storage user webauthn delete
    ↓
internal/commands/storage.go:412 (newStorageUserWebAuthnCmd)
    ↓
internal/commands/storage_run.go:1445 (StorageUserWebAuthnDeleteRunE)
    ├─ byKID → DeleteWebAuthnCredential(kid)
    └─ byUser → DeleteWebAuthnCredentialByUsername(user, desc)
```

### 11.3 登录时的撤销检测
```
POST /api/secondfactor/webauthn/assertion
    ↓
internal/handlers/handler_sign_webauthn.go:129 (WebAuthnAssertionPOST)
    ├─ 解析浏览器返回的签名
    ├─ handleGetWebAuthnUserByRPID() ← 重新加载用户凭据
    ├─ w.ValidateLogin(user, ...)     ← 密码学验证（使用数据库中的公钥）
    │   └─ 凭据已删除 → 公钥列表中无匹配 → 返回错误 → HTTP 403
    └─ 遍历 user.Credentials 匹配 KID ← 二次确认凭据存在
        └─ 凭据已删除 → found=false → HTTP 403
```

---

## 12. 相关文件索引

| 功能 | 文件路径 |
|------|---------|
| 凭据数据结构 | internal/model/webauthn.go |
| 用户删除 Handler | internal/handlers/handler_webauthn_credentials.go |
| 注册 Handler | internal/handlers/handler_register_webauthn.go |
| 登录验证 Handler | internal/handlers/handler_sign_webauthn.go |
| Passkey 1FA Handler | internal/handlers/handler_firstfactor_passkey.go |
| WebAuthn 辅助函数 | internal/handlers/webauthn.go |
| 存储层实现 | internal/storage/sql_provider.go |
| SQL 查询定义 | internal/storage/sql_provider_queries.go |
| CLI 命令 | internal/commands/storage_run.go |
| 会话结构体 | internal/session/types.go |
| 路由注册 | internal/server/handlers.go |
| 授权中间件 | internal/middlewares/require_auth.go |
| WebAuthn 工具函数 | internal/webauthn/util.go |
| WebAuthn 凭据验证 | internal/webauthn/credential.go |
| 登出 Handler | internal/handlers/handler_logout.go |
| 错误消息常量 | internal/handlers/const.go |
| UserInfo 模型 | internal/model/user_info.go |
