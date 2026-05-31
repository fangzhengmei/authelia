# Authelia 自助密码重置流程 —— 弱信任环境下的安全性分析

## 1. 流程总览

Authelia 的自助密码重置（Self-Service Password Reset）流程分为三个阶段：

1. **身份验证启动（Identity Start）**：用户提交用户名 → 系统发送包含 JWT 令牌的邮件
2. **身份验证完成（Identity Finish）**：用户点击邮件链接提交 JWT → 系统验证 JWT 并在会话中标记已通过身份验证
3. **密码重置（Reset Password）**：用户提交新密码 → 系统写入存储后端并通知

此外，Authelia 还存在一个独立的 **修改密码（Change Password）** 流程，需要已登录用户通过会话提升（Session Elevation）才能执行。

---

## 2. 端点与路由定义

路由注册位于 `internal/server/handlers.go:261-272`：

```
POST /api/reset-password/identity/start  → ResetPasswordIdentityStart (带速率限制)
POST /api/reset-password/identity/finish → ResetPasswordIdentityFinish (带 IP 速率限制)
POST /api/reset-password                 → ResetPasswordPOST
DELETE /api/reset-password               → ResetPasswordDELETE (撤销令牌)
```

**前置条件**：仅当 `authentication_backend.password_reset.disable = false` 且 `password_reset.custom_url` 为空时才注册这些端点。

**中间件**：所有端点仅使用 `middlewareAPI`，即 `SecurityHeadersBase + SecurityHeadersNoStore + SecurityHeadersCSPNone`。密码重置流程 **不要求用户已登录**（不需要 `Require1FA` 或 `RequireElevated`），这是合理的——用户正是因为忘记密码才需要此流程。

---

## 3. 阶段一：发起重置请求（Identity Start）

### 3.1 代码入口

`internal/handlers/handler_reset_password.go:257-265`

```go
var ResetPasswordIdentityStart = middlewares.IdentityVerificationStart(
    middlewares.IdentityVerificationStartArgs{
        MailTitle:               "Reset your password",
        MailButtonContent:       "Reset",
        MailButtonRevokeContent: "Revoke",
        TargetEndpoint:          "/reset-password/step2",
        RevokeEndpoint:          "/revoke/reset-password",
        ActionClaim:             ActionResetPassword,  // "ResetPassword"
        IdentityRetrieverFunc:   identityRetrieverFromStorage,
    },
    middlewares.TimingAttackDelay(10, 250, 85, time.Millisecond*500, false),
)
```

### 3.2 身份检索逻辑

`internal/handlers/handler_reset_password.go:231-253`

```go
func identityRetrieverFromStorage(ctx *middlewares.AutheliaCtx) (*session.Identity, error) {
    requestBody := resetPasswordStep1RequestBody{Username: ...}
    details, err := ctx.Providers.UserProvider.GetDetails(requestBody.Username)
    if len(details.Emails) == 0 {
        return nil, fmt.Errorf("user %s has no email address configured", ...)
    }
    return &session.Identity{Username, DisplayName, Email}, nil
}
```

**关键安全特性**：
- 无论用户是否存在、邮箱是否存在，系统始终返回 HTTP 200（防用户枚举）
- 若检索身份失败，`IdentityVerificationStart` 会 `ctx.ReplyOK()` 后直接返回，不发送邮件

### 3.3 JWT 令牌生成

`internal/middlewares/identity_verification.go:49-80`

1. 生成随机 `jti`（JWT ID，UUID v4）
2. 创建 `IdentityVerification` 记录，包含 `jti`、`username`、`action="ResetPassword"`、`issued_ip`、`expires_at`（= now + JWTExpiration）
3. 将 `IdentityVerification` 记录持久化到数据库（`SaveIdentityVerification`）
4. 用 HMAC 签署 JWT（密钥来自 `identity_validation.reset_password.jwt_secret`），算法默认 HS256（可选 HS384/HS512）
5. 构造包含 JWT 的邮件链接和撤销链接，通过 SMTP 发送

**JWT Claims 结构**（`internal/model/identity_verification.go:54-63`）：

| 字段 | 值 |
|------|------|
| `jti` | UUID v4，全局唯一标识 |
| `iss` | Authelia Issuer URL |
| `iat` | 签发时间 |
| `exp` | 过期时间 |
| `action` | `"ResetPassword"` |
| `username` | 目标用户名 |

### 3.4 速率限制

`internal/configuration/schema/server.go:142-148`

默认速率限制：
- 10 分钟内 5 次请求
- 15 分钟内 10 次请求
- 30 分钟内 15 次请求

应用于 `/api/reset-password/identity/start`，基于 IP 限流。

### 3.5 时序攻击防护

`TimingAttackDelay(10, 250, 85, time.Millisecond*500, false)`

参数含义：最小 10ms，最大 250ms，平均 85ms 的随机延迟，加上 500ms 的基础延迟。无论请求成功或失败，响应时间均被模糊化，防止通过响应时间差异推断用户是否存在。

---

## 4. 阶段二：完成身份验证（Identity Finish）

### 4.1 代码入口

`internal/handlers/handler_reset_password.go:289-290`

```go
var ResetPasswordIdentityFinish = middlewares.IdentityVerificationFinish(
    middlewares.IdentityVerificationFinishArgs{ActionClaim: ActionResetPassword},
    resetPasswordIdentityVerificationFinish,
)
```

### 4.2 JWT 验证流程

`internal/middlewares/identity_verification.go:143-264`

验证步骤（严格按序）：

1. **解析请求体**：从 POST body 获取 `token` 字段
2. **JWT 解析与签名验证**：使用 `jwt_secret` 验证 HMAC 签名，同时校验 `iat`、`iss`、`exp`
3. **Claims 映射**：将 JWT Claims 映射为 `model.IdentityVerificationClaim`
4. **转换为 IdentityVerification**：提取 `jti`、`username`、`action`
5. **数据库查找**：`FindIdentityVerification(jti)` — 检查记录是否存在且未被消费/撤销/过期
6. **Action 匹配**：验证 `claims.Action == "ResetPassword"`，防止令牌被用于非预期操作
7. **消费令牌**：`ConsumeIdentityVerification(jti, remoteIP)` — 将记录标记为已消费，**确保一次性使用**
8. **回调**：调用 `resetPasswordIdentityVerificationFinish`

### 4.3 FindIdentityVerification 的防御逻辑

`internal/storage/sql_provider.go:982-1002`

```go
func (p *SQLProvider) FindIdentityVerification(ctx, jti) (found bool, err error) {
    // 从数据库查询记录
    switch {
    case verification.RevokedAt.Valid:
        return false, fmt.Errorf("the token has been revoked")
    case verification.ConsumedAt.Valid:
        return false, fmt.Errorf("the token has already been consumed")
    case verification.ExpiresAt.Before(time.Now()):
        return false, fmt.Errorf("the token expired %s ago", ...)
    default:
        return true, nil
    }
}
```

**三重防御**：已撤销 → 已消费 → 已过期，任一条件为真则拒绝。

### 4.4 会话标记

`internal/handlers/handler_reset_password.go:267-286`

```go
func resetPasswordIdentityVerificationFinish(ctx, username string) {
    ctx.ReplyOK()  // 先回复 200
    userSession, _ := ctx.GetSession()
    userSession.PasswordResetUsername = &username  // 在会话中存储已验证的用户名
    ctx.SaveSession(userSession)
}
```

**关键设计**：
- 身份验证完成后，在**当前会话**中设置 `PasswordResetUsername` 指针
- 后续的 `ResetPasswordPOST` 会检查此字段是否存在来判断是否已完成身份验证
- 这意味着身份验证完成和密码重置必须在**同一浏览器会话**中完成

### 4.5 速率限制

`internal/configuration/schema/server.go:149-154`

默认速率限制：
- 1 分钟内 10 次请求
- 2 分钟内 15 次请求

应用于 `/api/reset-password/identity/finish`，基于 IP 限流。

---

## 5. 阶段三：执行密码重置（Reset Password POST）

### 5.1 代码逻辑

`internal/handlers/handler_reset_password.go:136-229`

验证步骤：

1. **获取会话**：从 cookie 获取 `UserSession`
2. **检查身份验证标记**：`userSession.PasswordResetUsername == nil` → 拒绝
3. **密码策略检查**：`PasswordPolicy.Check(newPassword)`
4. **写入存储后端**：`UserProvider.UpdatePassword(username, newPassword)`
5. **清除会话标记**：`userSession.PasswordResetUsername = nil`，保存会话
6. **发送通知邮件**：获取用户邮箱，发送 "Password changed successfully" 通知

### 5.2 密码写入路径

`UserProvider.UpdatePassword()` 的实现取决于后端类型：
- **LDAP**：通过 LDAP Modify 操作更新 `userPassword` 属性
- **文件后端（YAML）**：直接更新 YAML 文件中的密码哈希

LDAP 情况下，如果 LDAP 服务器有密码策略（如 AD 的复杂度要求），会返回错误，Authelia 会将这些错误映射为用户友好的提示。

### 5.3 密码变更通知

`internal/handlers/handler_reset_password.go:206-228`

通知邮件内容：
- 标题：`"Password changed successfully"`
- 包含 `RemoteIP`（操作来源 IP）
- 包含 `Action: "Password Reset"`
- 使用 `EventEmailTemplate` 模板

**安全意义**：即使用户未主动请求重置，邮件到达后用户也能发现异常并采取措施。

---

## 6. 令牌撤销机制

### 6.1 DELETE 端点

`internal/handlers/handler_reset_password.go:20-133`

流程：
1. 从请求体获取 `token`
2. JWT 签名验证 + Claims 解析
3. 验证 `action == "ResetPassword"`
4. 从数据库加载 `IdentityVerification` 记录
5. 检查是否已被撤销
6. 执行撤销：`RevokeIdentityVerification(jti, remoteIP)`

### 6.2 前端撤销入口

`web/src/views/Revoke/RevokeResetPasswordTokenView.tsx`

邮件中同时包含验证链接和撤销链接。用户可以在意识到令牌泄露时主动撤销。

---

## 7. 对比：修改密码（Change Password）流程

### 7.1 端点

`POST /api/change-password` → `ChangePasswordPOST`

### 7.2 中间件要求

使用 `middlewareElevated1FA`，即 `RequireElevated`，要求：
- 用户已登录（1FA）
- 会话已提升（Elevation）或满足 SkipSecondFactor 条件

### 7.3 会话提升（Session Elevation）

与密码重置的 JWT 邮件验证不同，修改密码使用**一次性验证码（OTC）**机制：

| 方面 | 密码重置 | 修改密码（会话提升） |
|------|---------|-------------------|
| 身份验证方式 | JWT 邮件链接 | OTC 邮件验证码 |
| 前置要求 | 无需登录 | 需要已登录（1FA） |
| 令牌/代码有效期 | JWT 5 分钟（默认） | OTC 5 分钟 + 提升会话 10 分钟 |
| 存储位置 | `identity_verification` 表 | `one_time_code` 表 |
| 一次性保证 | 数据库 consumed_at 标记 | 数据库 consumed_at 标记 |
| 提升后有效期 | 会话 cookie 有效期 | 10 分钟（默认），IP 绑定 |

### 7.4 RequireElevated 中间件逻辑

`internal/middlewares/require_auth.go:58-136`

检查顺序：
1. 若 `skip_second_factor = true` 且用户已 2FA → 直接放行
2. 若 `require_second_factor = true` 且用户未 2FA 且有 2FA 设备 → 拒绝
3. 若会话无 Elevation 记录 → 拒绝
4. 验证 Elevation：
   - 检查是否过期
   - 检查 IP 是否匹配（RemoteIP 必须与创建 Elevation 时的 IP 一致）
   - 任一不满足 → 清除 Elevation 并拒绝

---

## 8. 令牌有效期与一次性限制分析

### 8.1 密码重置 JWT

| 参数 | 默认值 | 配置路径 |
|------|--------|---------|
| JWT 有效期 | 5 分钟 | `identity_validation.reset_password.jwt_lifespan` |
| JWT 算法 | HS256 | `identity_validation.reset_password.jwt_algorithm` |
| JWT 密钥 | 必须配置 | `identity_validation.reset_password.jwt_secret` |

**一次性保证**：
- JWT 本身不携带一次性语义（JWT 是无状态的）
- 一次性通过**数据库记录**保证：`FindIdentityVerification` 检查 `consumed_at` 是否为 NULL
- `ConsumeIdentityVerification` 在验证成功后立即将 `consumed_at` 设为当前时间
- 数据库记录还记录 `consumed_ip`

**双重验证**：JWT 的 `exp` claim 提供第一层过期检查，数据库 `expires_at` 提供第二层。即使 JWT 的 `exp` 被延长（理论上不可能，因为签名会变），数据库也会拒绝过期记录。

### 8.2 会话提升 OTC

| 参数 | 默认值 | 配置路径 |
|------|--------|---------|
| OTC 有效期 | 5 分钟 | `identity_validation.elevated_session.code_lifespan` |
| 提升有效期 | 10 分钟 | `identity_validation.elevated_session.elevation_lifespan` |
| OTC 字符数 | 8 | `identity_validation.elevated_session.characters` |
| 字符集 | 大写字母+数字（无歧义字符） | 内部定义 `CharSetUnambiguousUpper` |

**一次性保证**：
- `LoadOneTimeCode` 查找时检查 `consumed_at`、`revoked_at`、`expires_at`
- `ConsumeOneTimeCode` 将记录标记为已消费
- OTC 使用 `subtle.ConstantTimeCompare` 进行恒定时间比较，防止时序攻击

### 8.3 密码重置 JWT vs 会话提升 OTC 的安全性对比

| 安全属性 | 密码重置 JWT | 会话提升 OTC |
|---------|-------------|-------------|
| 令牌类型 | HMAC 签名的 JWT | 随机验证码 |
| 验证码传输 | 邮件中的 URL query 参数 | 邮件正文 |
| 一次性 | 数据库 consumed_at | 数据库 consumed_at |
| 撤销能力 | 邮件中的撤销链接 | 邮件中的撤销链接 |
| 离线验证 | 否（需查数据库） | 否（需查数据库） |
| IP 绑定 | 仅记录 issued_ip/consumed_ip，未强制验证 | OTC 验证不绑定 IP，但 Elevation 绑定 IP |
| 会话绑定 | 通过 cookie 中的 PasswordResetUsername 绑定 | 通过 cookie 中的 Elevations.User 绑定 |

---

## 9. 与登录、Remember Me、会话存活的关系

### 9.1 密码重置流程中的会话使用

密码重置流程对**会话**的依赖体现在阶段二完成后：

1. `resetPasswordIdentityVerificationFinish` 在会话中写入 `PasswordResetUsername`
2. `ResetPasswordPOST` 从会话中读取 `PasswordResetUsername` 来确认身份验证已完成

这意味着：**用户点击邮件链接完成身份验证后，必须在同一浏览器会话中提交新密码**。

### 9.2 会话存活时间的影响

会话配置默认值（`internal/configuration/schema/session.go:79-86`）：

| 参数 | 默认值 |
|------|--------|
| Expiration（未勾选 Remember Me） | 1 小时 |
| Inactivity | 5 分钟 |
| Remember Me | 30 天 |
| SameSite | Lax |

**关键风险点**：

- 如果用户在阶段二（完成身份验证）和阶段三（提交新密码）之间**会话过期**，`PasswordResetUsername` 将随会话丢失
- 用户需要重新发起整个流程（重新获取 JWT 并验证）
- 由于 JWT 本身 5 分钟内过期，且数据库在消费后标记 consumed_at，因此即使会话仍然存活，已消费的 JWT 也不能再次使用

**弱信任环境下的具体场景**：

1. **共享设备**：用户在公共电脑上发起密码重置，完成身份验证后离开，会话仍在浏览器中。攻击者可以利用存活的会话提交自己的密码——但攻击者需要访问同一浏览器的 cookie。
2. **会话劫持**：如果攻击者窃取了已通过身份验证的会话 cookie，可以在密码重置页面提交新密码。
3. **Remember Me**：密码重置流程不涉及 Remember Me 设置，但登录流程的 Remember Me 会延长会话有效期至 30 天，如果用户在 Remember Me 状态下进行密码重置，会话更不容易过期。

### 9.3 登录流程的会话管理

`internal/handlers/handler_firstfactor_password.go:89-152`

1. 登录成功后**销毁旧会话**（`DestroySession`）
2. 创建**全新默认会话**（`NewDefaultUserSession`）
3. 如果用户勾选 Remember Me 且未禁用，将会话过期时间设为 `RememberMe`（默认 30 天）
4. 设置 1FA 认证时间戳和 AMR（Authentication Method References）
5. 重新生成会话 ID（`RegenerateSession`）

**与密码重置的关系**：
- 密码被重置后，现有会话**不会**被自动失效
- 这意味着旧密码认证的会话在 cookie 有效期内仍然可用
- 这是一个潜在的安全弱点：理想情况下密码重置后应使所有现有会话失效

### 9.4 2FA 与密码重置的关系

- 密码重置流程**不要求**用户已完成 2FA
- 这是设计上的权衡：用户忘记密码时无法完成登录，自然也无法完成 2FA
- 身份验证完全依赖**邮箱所有权**（邮件令牌）
- 相比之下，修改密码（Change Password）流程需要已登录 + 会话提升（可通过 2FA 跳过邮件验证）

---

## 10. 弱信任环境下的安全评估

### 10.1 已有的安全机制

| 机制 | 实现位置 | 作用 |
|------|---------|------|
| 用户枚举防护 | `identity_verification.go:43-47` | 无论用户是否存在均返回 200 |
| 时序攻击防护 | `TimingAttackDelay` | 模糊化响应时间 |
| JWT 签名验证 | `jwt.ParseWithClaims` + HMAC | 防止令牌伪造 |
| JWT 有效期 | 默认 5 分钟 | 缩短攻击窗口 |
| 一次性令牌 | `ConsumeIdentityVerification` | 防止令牌重放 |
| 令牌撤销 | `RevokeIdentityVerification` | 允许用户主动撤销 |
| IP 速率限制 | 默认已启用 | 防止暴力猜测 |
| Action Claim 绑定 | `claims.Action == ActionClaim` | 防止令牌跨操作复用 |
| 密码策略检查 | `PasswordPolicy.Check` | 确保密码强度 |
| 密码变更通知 | 邮件通知 | 用户可感知异常 |
| 会话绑定 | `PasswordResetUsername` | 身份验证与密码提交必须在同一会话 |

### 10.2 潜在风险与建议

#### 风险 1：邮箱即唯一信任因子

密码重置的身份验证完全依赖邮箱所有权。在弱信任环境下：
- 如果邮箱被入侵，攻击者可以重置任何关联账户的密码
- JWT 的 5 分钟有效期仅限制时间窗口，不限制攻击者对邮箱的控制

**建议**：考虑为高安全场景增加二次确认机制（如短信验证码、管理员审批等），尽管 Authelia 当前不支持。

#### 风险 2：密码重置后旧会话未失效

`ResetPasswordPOST` 不销毁现有会话。如果攻击者已获取用户的会话 cookie：
1. 攻击者可以等待用户通过密码重置设置新密码
2. 旧会话仍然有效，攻击者仍可访问

**建议**：密码重置成功后，应主动销毁该用户的所有现有会话。当前代码（`handler_reset_password.go:183`）仅清除 `PasswordResetUsername`，不做会话全局失效。

#### 风险 3：PasswordResetUsername 的会话依赖

`PasswordResetUsername` 存储在会话 cookie 中，其存活时间受会话配置控制：
- 默认非 Remember Me 会话 1 小时过期，5 分钟不活动过期
- 这意味着身份验证完成后，用户最多有 1 小时（或更短）来提交新密码
- 这不是一个严重风险，但在公共设备上，会话存活时间越长，窗口越大

#### 风险 4：IP 不绑定于密码重置流程

与修改密码的 Session Elevation（绑定 RemoteIP）不同，密码重置流程**不验证** IP 一致性：
- `IdentityVerification` 记录了 `issued_ip` 和 `consumed_ip`，但仅用于审计
- 攻击者可以在不同 IP 使用截获的 JWT 完成验证

**影响**：由于 JWT 5 分钟内过期且一次性使用，实际风险较低。但如果 JWT 在有效期内被截获（如邮件被中间人读取），攻击者可在不同 IP 使用。

#### 风险 5：JWT 密钥泄露

`identity_validation.reset_password.jwt_secret` 用于签署和验证所有密码重置 JWT。如果此密钥泄露：
- 攻击者可以为任意用户伪造有效的密码重置令牌
- 攻击者可以绕过整个身份验证流程

**建议**：确保 JWT Secret 的安全存储，定期轮换。

### 10.3 与 Remember Me 的交互

| 场景 | 影响 |
|------|------|
| 用户在 Remember Me 状态下发起密码重置 | 会话有效期 30 天，`PasswordResetUsername` 存活更久，窗口更大 |
| 用户密码被重置后使用旧 cookie | 旧 cookie 仍然有效，因为密码重置不会使会话失效 |
| 攻击者获取 Remember Me cookie 并等待密码重置 | 攻击者可利用存活会话在重置后继续访问 |

### 10.4 密码重置 vs 修改密码的安全性层级

```
安全性从低到高：

1. 密码重置（Reset Password）
   - 无需登录
   - 仅邮箱 JWT 验证
   - 不绑定 IP
   - 不销毁旧会话

2. 修改密码（Change Password）
   - 需要已登录（1FA）
   - 需要会话提升（OTC 验证码）
   - 提升会话绑定 IP
   - 需要提供旧密码
   - 不销毁旧会话（同样的问题）
```

---

## 11. 完整流程时序图

```
用户                前端                   Authelia后端               数据库              邮件服务
 │                  │                        │                        │                   │
 │ 点击"忘记密码"   │                        │                        │                   │
 │─────────────────>│                        │                        │                   │
 │                  │ POST /reset-password/  │                        │                   │
 │                  │ identity/start         │                        │                   │
 │                  │ {username: "alice"}    │                        │                   │
 │                  │───────────────────────>│                        │                   │
 │                  │                        │ GetDetails("alice")    │                   │
 │                  │                        │──────────────────────>│                   │
 │                  │                        │<─────────────────────│                   │
 │                  │                        │ 生成 JWT(jti, exp=5m) │                   │
 │                  │                        │ SaveIdentityVerification│                  │
 │                  │                        │──────────────────────>│                   │
 │                  │                        │                        │ 发送邮件           │
 │                  │                        │──────────────────────────────────────────>│
 │                  │    200 OK (始终返回)    │                        │                   │
 │                  │<───────────────────────│                        │                   │
 │<─────────────────│ 显示"邮件已发送"        │                        │                   │
 │                  │                        │                        │                   │
 │  收到邮件        │                        │                        │                   │
 │<─────────────────────────────────────────────────────────────────────────────────────│
 │  (含JWT链接+撤销链接)                     │                        │                   │
 │                  │                        │                        │                   │
 │ 点击邮件链接     │                        │                        │                   │
 │─────────────────>│                        │                        │                   │
 │                  │ POST /reset-password/  │                        │                   │
 │                  │ identity/finish        │                        │                   │
 │                  │ {token: "eyJ..."}      │                        │                   │
 │                  │───────────────────────>│                        │                   │
 │                  │                        │ 验证JWT签名+exp        │                   │
 │                  │                        │ FindIdentityVerification│                  │
 │                  │                        │──────────────────────>│                   │
 │                  │                        │<─────────────────────│                   │
 │                  │                        │ (检查consumed/revoked/ │                   │
 │                  │                        │  expired)              │                   │
 │                  │                        │ ConsumeIdentityVerification│               │
 │                  │                        │──────────────────────>│                   │
 │                  │                        │ 会话写入PasswordResetUsername            │
 │                  │    200 OK              │                        │                   │
 │                  │<───────────────────────│                        │                   │
 │<─────────────────│ 显示密码输入表单        │                        │                   │
 │                  │                        │                        │                   │
 │ 提交新密码       │                        │                        │                   │
 │─────────────────>│                        │                        │                   │
 │                  │ POST /reset-password   │                        │                   │
 │                  │ {password: "xxx"}      │                        │                   │
 │                  │───────────────────────>│                        │                   │
 │                  │                        │ 检查会话PasswordResetUsername           │
 │                  │                        │ PasswordPolicy.Check() │                   │
 │                  │                        │ UpdatePassword(username,│                   │
 │                  │                        │   newPassword)         │                   │
 │                  │                        │──────────────────────>│(LDAP/文件)        │
 │                  │                        │ 清除PasswordResetUsername               │
 │                  │                        │ 发送变更通知邮件       │                   │
 │                  │                        │──────────────────────────────────────────>│
 │                  │    200 OK              │                        │                   │
 │                  │<───────────────────────│                        │                   │
 │<─────────────────│ 显示"密码已重置"        │                        │                   │
 │                  │                        │                        │                   │
 │  收到通知邮件    │                        │                        │                   │
 │<─────────────────────────────────────────────────────────────────────────────────────│
 │  "Password changed successfully"          │                        │                   │
```

---

## 12. 关键代码文件索引

| 文件 | 行号 | 功能 |
|------|------|------|
| `internal/server/handlers.go` | 261-272 | 路由注册 |
| `internal/handlers/handler_reset_password.go` | 20-133 | DELETE 撤销令牌 |
| `internal/handlers/handler_reset_password.go` | 136-229 | POST 执行密码重置 |
| `internal/handlers/handler_reset_password.go` | 231-253 | 身份检索（从存储） |
| `internal/handlers/handler_reset_password.go` | 257-265 | IdentityStart 入口 |
| `internal/handlers/handler_reset_password.go` | 267-290 | IdentityFinish 回调 + 入口 |
| `internal/middlewares/identity_verification.go` | 18-138 | IdentityVerificationStart 通用中间件 |
| `internal/middlewares/identity_verification.go` | 143-264 | IdentityVerificationFinish 通用中间件 |
| `internal/middlewares/require_auth.go` | 24-136 | RequireElevated 中间件 |
| `internal/model/identity_verification.go` | 14-78 | IdentityVerification 模型 + JWT Claims |
| `internal/model/one_time_code.go` | 13-68 | OneTimeCode 模型（会话提升用） |
| `internal/session/types.go` | 20-83 | UserSession 结构（含 PasswordResetUsername） |
| `internal/session/user_session.go` | 24-37 | 认证级别计算 |
| `internal/storage/sql_provider.go` | 953-1014 | 身份验证存储操作 |
| `internal/configuration/schema/identity_validation.go` | 8-39 | 配置结构与默认值 |
| `internal/configuration/schema/session.go` | 77-86 | 会话默认值 |
| `internal/handlers/handler_change_password.go` | 13-152 | 修改密码处理器 |
| `internal/handlers/handler_session_elevation.go` | 23-442 | 会话提升处理器 |
| `web/src/services/ResetPassword.ts` | 1-34 | 前端 API 调用 |
| `web/src/views/ResetPassword/ResetPasswordStep1.tsx` | 15-143 | 前端步骤1：输入用户名 |
| `web/src/views/ResetPassword/ResetPasswordStep2.tsx` | 20-238 | 前端步骤2：输入新密码 |
