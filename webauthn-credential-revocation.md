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
    KID               Base64        `db:"kid"`           // 公钥 ID
    AAGUID            uuid.NullUUID `db:"aaguid"`        // 认证器型号 ID
    AttestationType   string        `db:"attestation_type"`
    AttestationFormat string        `db:"attestation_format"`
    Attachment        string        `db:"attachment"`    // 平台/跨平台
    Transport         string        `db:"transport"`
    SignCount         uint32        `db:"sign_count"`
    CloneWarning      bool          `db:"clone_warning"`
    Legacy            bool          `db:"legacy"`
    Discoverable      bool          `db:"discoverable"`  // Passkey 标志
    Present           bool          `db:"present"`
    Verified          bool          `db:"verified"`
    BackupEligible    bool          `db:"backup_eligible"`
    BackupState       bool          `db:"backup_state"`
    PublicKey         []byte        `db:"public_key"`    // 加密存储
    Attestation       []byte        `db:"attestation"`   // 加密存储
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

## 2. 凭据撤销方式

### 2.1 用户主动删除（Web UI）

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
// 权限校验 - 确保用户只能删除自己的凭据
if credential.Username != userSession.Username {
    ctx.SetStatusCode(fasthttp.StatusForbidden)
    return
}

// 按 KID 删除（不是按数据库 ID）
if err = ctx.Providers.StorageProvider.DeleteWebAuthnCredential(
    ctx, credential.KID.String()); err != nil {
    // 错误处理
}
```

### 2.2 管理员强制清理（CLI 命令）

#### 命令格式
```bash
# 按用户名删除所有凭据
authelia storage user webauthn delete john --all

# 按用户名+描述删除
authelia storage user webauthn delete john --description "YubiKey 5"

# 按 KID 直接删除
authelia storage user webauthn delete --kid "AAECAwQFBgcICQoLDA0ODw"
```

#### 代码入口
- 命令定义：`internal/commands/storage.go:412` → `newStorageUserWebAuthnCmd`
- RunE 函数：`internal/commands/storage_run.go:1444-1465` → `StorageUserWebAuthnDeleteRunE`

#### 处理流程
```
1. 解析命令行参数（--all, --description, --kid）
   ↓
2. 连接数据库并验证 schema 版本
   ↓
3. 分支处理：
   ├─ 按 KID 删除 → DeleteWebAuthnCredential(kid)
   └─ 按用户名/描述删除 → DeleteWebAuthnCredentialByUsername(user, description)
```

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

## 3. 撤销到验证拒绝的传递机制

### 3.1 验证流程总览

WebAuthn 登录验证分为两步：
1. **GET /api/secondfactor/webauthn/assertion** - 开始认证（生成挑战）
2. **POST /api/secondfactor/webauthn/assertion** - 完成认证（验证签名）

### 3.2 关键检查点

#### 检查点 1：生成挑战时加载凭据列表
**位置**：`internal/handlers/handler_sign_webauthn.go:67-74`

```go
// 加载用户所有凭据用于生成 allowedCredentials
user, err = handleGetWebAuthnUserByRPID(ctx, userSession.Username, ...)
// 内部调用: LoadWebAuthnCredentialsByUsername(rpid, username)
// → 如果凭据已删除，不会出现在列表中
```

**影响**：浏览器只会看到未被删除的凭据列表。如果删除了唯一的凭据，浏览器可能无法发起签名。

#### 检查点 2：验证签名时二次加载凭据
**位置**：`internal/handlers/handler_sign_webauthn.go:197-204`

```go
// 验证前重新从数据库加载用户凭据
user, err = handleGetWebAuthnUserByRPID(ctx, userSession.Username, ...)

// go-webauthn 库使用 user.Credentials 进行密码学验证
c, err := w.ValidateLogin(user, *userSession.WebAuthn.SessionData, response)
```

**关键**：即使浏览器缓存了旧的凭据 ID，在验证阶段会重新查询数据库。如果凭据已删除，`user.Credentials` 中不包含该凭据，`ValidateLogin` 会因为找不到对应公钥而失败。

#### 检查点 3：验证成功后确认凭据存在
**位置**：`internal/handlers/handler_sign_webauthn.go:223-251`

```go
// 遍历数据库中的凭据，匹配 KID
for _, credential := range user.Credentials {
    if bytes.Equal(credential.KID.Bytes(), c.ID) {
        // 找到匹配的凭据，更新签名计数
        credential.UpdateSignInInfo(...)
        ctx.Providers.StorageProvider.UpdateWebAuthnCredentialSignIn(...)
        found = true
        break
    }
}

if !found {
    // 凭据不存在，拒绝登录
    ctx.SetStatusCode(fasthttp.StatusForbidden)
    ctx.SetJSONError(messageMFAValidationFailed)
    return
}
```

**安全冗余**：即使 `ValidateLogin` 通过（理论上不可能），这一步会再次确认凭据存在于数据库中。

---

## 4. 与活跃会话的关系

### 4.1 会话数据结构
**位置**：`internal/session/types.go:20-48`

```go
type UserSession struct {
    Username    string
    FirstFactorAuthnTimestamp  int64  // 1FA 时间
    SecondFactorAuthnTimestamp int64  // 2FA 时间
    AuthenticationMethodRefs   authorization.AuthenticationMethodsReferences
    
    // 注意：会话中只记录认证时间和方法，不绑定具体的凭据 ID
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

## 5. 多设备/多域名同步状态

### 5.1 Cookie 域会话共享
Authelia 支持通过 Cookie Domain 配置实现多域名/子域名共享会话。

### 5.2 凭据撤销的跨设备影响

| 场景 | 影响 |
|------|------|
| **同一设备不同域名** | 共享同一个会话，撤销不影响已登录状态 |
| **不同设备** | 各有各的会话，撤销不影响对方已登录状态 |
| **Passkey 同步** | 硬件密钥内部的跨设备同步由厂商管理，Authelia 只在验证时检查凭据是否存在于数据库 |

### 5.3 关键边界：Passkey 升级
**位置**：`internal/handlers/webauthn.go:58-66`

```go
if ctx.Configuration.WebAuthn.EnablePasskeyUpgrade {
    // 升级模式：加载所有 WebAuthn 凭据
    u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnCredentialsByUsername(...)
} else {
    // 非升级模式：只加载可发现凭据（Passkey）
    u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnPasskeyCredentialsByUsername(...)
}
```

**注意**：删除 Passkey 凭据会影响免用户名登录流程，但已登录的会话仍然有效。

---

## 6. 代码调用链总结

### 6.1 用户删除流程
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

### 6.2 管理员删除流程
```
authelia storage user webauthn delete
    ↓
internal/commands/storage.go:412 (newStorageUserWebAuthnCmd)
    ↓
internal/commands/storage_run.go:1445 (StorageUserWebAuthnDeleteRunE)
    ├─ byKID → DeleteWebAuthnCredential(kid)
    └─ byUser → DeleteWebAuthnCredentialByUsername(user, desc)
```

### 6.3 登录时的撤销检测
```
POST /api/secondfactor/webauthn/assertion
    ↓
internal/handlers/handler_sign_webauthn.go:129 (WebAuthnAssertionPOST)
    ├─ 解析浏览器返回的签名
    ├─ handleGetWebAuthnUserByRPID() ← 重新加载用户凭据
    ├─ w.ValidateLogin(user, ...)     ← 密码学验证（使用数据库中的公钥）
    └─ 遍历 user.Credentials 匹配 KID ← 二次确认凭据存在
```

---

## 7. 安全建议

### 7.1 紧急应对
如果员工硬件密钥丢失：
1. **立即执行**：`authelia storage user webauthn delete <username> --all`
2. **可选**：强制用户重新登录（需要销毁会话，Authelia 目前没有内置的全局会话销毁 API，可通过重启 session provider 实现）

### 7.2 注意事项
- 凭据删除是**物理删除**（DELETE FROM），没有软删除标记
- 删除后无法恢复，除非有数据库备份
- 已登录的会话不会自动失效，这符合大多数 SSO 系统的行为
- 如果需要"撤销立即使所有会话失效"的能力，需要额外开发会话吊销机制

---

## 8. 相关文件索引

| 功能 | 文件路径 |
|------|---------|
| 凭据数据结构 | internal/model/webauthn.go |
| 用户删除 Handler | internal/handlers/handler_webauthn_credentials.go |
| 登录验证 Handler | internal/handlers/handler_sign_webauthn.go |
| 存储层实现 | internal/storage/sql_provider.go |
| CLI 命令 | internal/commands/storage_run.go |
| 会话结构体 | internal/session/types.go |
| 路由注册 | internal/server/handlers.go |
| 授权中间件 | internal/middlewares/require_auth.go |
