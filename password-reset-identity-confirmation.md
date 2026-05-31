# Authelia 自助密码重置流程 —— 弱信任环境下的安全性分析

## 1. 流程总览

Authelia 的自助密码重置（Self-Service Password Reset）流程的入口始于登录页的"Reset password?"按钮。该按钮的行为由两个配置项控制，形成完整的分流决策链。

### 1.1 完整分流决策树

```
登录页渲染
  │
  ├─ resetPassword = false?
  │   ├─ YES → 按钮不渲染 → 流程终止
  │   └─ NO  → 按钮渲染，等待用户点击
  │
  ↓ 用户点击"Reset password?"
  │
  ├─ resetPasswordCustomURL 非空?
  │   ├─ YES → window.open(custom_url) → 外链流程，Authelia 不再介入
  │   └─ NO  → navigate("/reset-password/step1") → 站内流程
  │
  ↓ 站内流程继续
  │
  ├─ Step1: 用户输入用户名 → POST /api/reset-password/identity/start
  │   └─ 系统发送含 JWT 的邮件（JWT 5 分钟内有效）
  │
  ├─ Step2: 用户点击邮件链接 → 浏览器打开 /reset-password/step2?token=xxx
  │   └─ 页面自动调用 POST /api/reset-password/identity/finish
  │       ├─ 验证 JWT 签名、有效期
  │       ├─ 检查数据库：未消费、未撤销、未过期
  │       ├─ 消费 JWT（标记 consumed_at）
  │       └─ 写入会话：PasswordResetUsername = username
  │
  └─ Step3: 用户输入新密码 → POST /api/reset-password
      ├─ 检查会话中的 PasswordResetUsername
      ├─ 密码策略检查
      ├─ 写入存储后端（LDAP/文件）
      ├─ 清除 PasswordResetUsername
      └─ 发送"密码已变更"通知邮件
```

### 1.2 三个主要阶段（站内流程）

1. **身份验证启动（Identity Start）**：用户提交用户名 → 系统发送包含 JWT 令牌的邮件
2. **身份验证完成（Identity Finish）**：用户点击邮件链接提交 JWT → 系统验证 JWT 并在会话中标记已通过身份验证
3. **密码重置（Reset Password）**：用户提交新密码 → 系统写入存储后端并通知

此外，Authelia 还存在一个独立的 **修改密码（Change Password）** 流程，需要已登录用户通过会话提升（Session Elevation）才能执行。

---

## 2. 登录页分流逻辑：resetPassword 开关与 custom_url

### 2.1 配置传递链路（后端 → HTML → 前端）

配置通过三层传递最终决定按钮行为：

#### 后端计算配置值
`internal/server/template.go:227-228`
```go
ResetPassword:           strconv.FormatBool(!config.AuthenticationBackend.PasswordReset.Disable),
ResetPasswordCustomURL:  config.AuthenticationBackend.PasswordReset.CustomURL.String(),
```

#### 嵌入 HTML data 属性
`internal/server/public_html/index.html:7-8`
```html
"ResetPassword":"{{ .ResetPassword }}",
"ResetPasswordCustomURL":"{{ .ResetPasswordCustomURL }}",
```

渲染后实际 HTML 片段（body 标签的 data-* 属性）：
```html
<body data-resetpassword="true" data-resetpasswordcustomurl="">
```

#### 前端读取配置
`web/src/utils/Configuration.ts:22-31`
```typescript
export function getResetPassword() {
    return getEmbeddedVariable("resetpassword") === "true";
}
export function getResetPasswordCustomURL() {
    return getEmbeddedVariable("resetpasswordcustomurl");
}
```

### 2.2 按钮渲染与点击分流逻辑

#### 按钮是否渲染
`web/src/views/LoginPortal/FirstFactor/FirstFactorForm.tsx:384-405`
```tsx
{props.resetPassword ? (
    <Grid ...>
        <Link id="reset-password-button" onClick={handleResetPasswordClick}>
            {translate("Reset password?")}
        </Link>
    </Grid>
) : null}
```

- 若 `resetPassword = false` → 按钮不渲染，用户看不到入口
- 若 `resetPassword = true` → 渲染按钮

#### 点击后的分流
`web/src/views/LoginPortal/FirstFactor/FirstFactorForm.tsx:167-175`
```typescript
const handleResetPasswordClick = () => {
    if (props.resetPassword) {
        if (props.resetPasswordCustomURL) {
            window.open(props.resetPasswordCustomURL); // 走外链
        } else {
            navigate(ResetPasswordStep1Route); // 走站内流程
        }
    }
};
```

### 2.3 完整判定表

| resetPassword | custom_url | 结果 |
|---------------|------------|------|
| `false` | 任意值 | 按钮不渲染，完全禁用 |
| `true` | `""`（空串） | 显示按钮，点击进入站内重置流程 |
| `true` | `"https://other.example.com"` | 显示按钮，点击新窗口打开外链 |

### 2.4 后端 API 端点的注册条件

`internal/server/template.go:234`
```go
EndpointsPasswordReset: !config.AuthenticationBackend.PasswordReset.Disable && 
                        config.AuthenticationBackend.PasswordReset.CustomURL.String() == "",
```

`internal/server/handlers.go:261-272`
```go
if config.Server.Endpoints.EndpointsPasswordReset {
    resetPasswordTokenRL := middlewares.NewIPRateLimit(...)
    r.POST("/api/reset-password/identity/start", ...)
    r.POST("/api/reset-password/identity/finish", ...)
    r.POST("/api/reset-password", ...)
    r.DELETE("/api/reset-password", ...)
}
```

**前后端一致性保证**：当配置了 `custom_url` 时，后端**不会注册**站内密码重置的 API 端点，前端按钮也不会导向站内流程。

---

## 3. 前端站内流程完整调用链

### 3.1 完整时序（前端视角）

```
登录页
  ↓ 点击"Reset password?"按钮
  ↓ FirstFactorForm.tsx:167 handleResetPasswordClick()
  ↓ navigate("/reset-password/step1")
  ↓
ResetPasswordStep1.tsx  [路由 /reset-password/step1]
  ↓ 用户输入用户名，点击"Send Email"
  ↓ ResetPasswordStep1.tsx:55 doInitiateResetPasswordProcess()
  ↓ ResetPassword.ts:13 initiateResetPasswordProcess(username)
  ↓ POST /api/reset-password/identity/start  {username}
  ↓ 返回 200（无论是否发送邮件均返回 200）
  ↓ 前端显示"Email sent"提示
  ↓
（用户在邮件客户端点击链接）
  ↓
浏览器打开 /reset-password/step2?token=eyJ...
  ↓
ResetPasswordStep2.tsx  [路由 /reset-password/step2]
  ↓ useEffect() 自动触发
  ↓ ResetPasswordStep2.tsx:55 submitReset()
  ↓ 从 URL query param 读取 token
  ↓ ResetPassword.ts:17 completeResetPasswordProcess(token)
  ↓ POST /api/reset-password/identity/finish  {token}
  ↓ 若成功 → 后端在会话中写入 PasswordResetUsername
  ↓ 前端启用密码输入表单（setFormDisabled(false)）
  ↓
  ↓ 用户输入两次新密码，点击"Reset"
  ↓ ResetPasswordStep2.tsx:85 doResetPassword()
  ↓ ResetPassword.ts:21 resetPassword(newPassword)
  ↓ POST /api/reset-password  {password}
  ↓ 若成功 → 后端清除 PasswordResetUsername，发送通知邮件
  ↓ 前端显示成功，1.5 秒后 navigate("/") 回到登录页
```

### 3.2 前端三个步骤的代码定位

| 阶段 | 组件 | 触发方式 | API 调用 |
|------|------|---------|---------|
| 发起重置 | `ResetPasswordStep1.tsx` | 用户点击按钮 | `initiateResetPasswordProcess(username)` |
| 完成身份验证 | `ResetPasswordStep2.tsx` | 页面加载自动执行 | `completeResetPasswordProcess(token)` |
| 提交新密码 | `ResetPasswordStep2.tsx` | 用户点击按钮 | `resetPassword(newPassword)` |

### 3.3 前端 API 服务层定义

`web/src/services/ResetPassword.ts:1-34`
```typescript
import {
    CompleteResetPasswordPath,    // "/api/reset-password/identity/finish"
    InitiateResetPasswordPath,    // "/api/reset-password/identity/start"
    ResetPasswordPath,            // "/api/reset-password"
} from "@constants/Api";

export async function initiateResetPasswordProcess(username: string) {
    return PostWithOptionalResponseRateLimited(InitiateResetPasswordPath, { username });
}

export async function completeResetPasswordProcess(token: string) {
    return PostWithOptionalResponseRateLimited(CompleteResetPasswordPath, { token });
}

export async function resetPassword(newPassword: string) {
    return PostWithOptionalResponse(ResetPasswordPath, { password: newPassword });
}

export async function deleteResetPasswordToken(token: string) {
    return fetch(... DELETE /api/reset-password ...);
}
```

### 3.4 前端路由定义

`web/src/constants/Routes.ts:10-11`
```typescript
export const ResetPasswordStep1Route: string = "/reset-password/step1";
export const ResetPasswordStep2Route: string = "/reset-password/step2";
```

`web/src/App.tsx:57-58`
```tsx
<Route path={ResetPasswordStep1Route} element={<ResetPasswordStep1 />} />
<Route path={ResetPasswordStep2Route} element={<ResetPasswordStep2 />} />
```

---

## 4. 端点与路由定义

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

## 5. 阶段一：发起重置请求（Identity Start）

### 5.1 代码入口

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

### 5.2 身份检索逻辑

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

### 5.3 JWT 令牌生成

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

### 5.4 速率限制

`internal/configuration/schema/server.go:142-148`

默认速率限制：
- 10 分钟内 5 次请求
- 15 分钟内 10 次请求
- 30 分钟内 15 次请求

应用于 `/api/reset-password/identity/start`，基于 IP 限流。

### 5.5 时序攻击防护

`TimingAttackDelay(10, 250, 85, time.Millisecond*500, false)`

参数含义：最小 10ms，最大 250ms，平均 85ms 的随机延迟，加上 500ms 的基础延迟。无论请求成功或失败，响应时间均被模糊化，防止通过响应时间差异推断用户是否存在。

---

## 6. 阶段二：完成身份验证（Identity Finish）

### 6.1 代码入口

`internal/handlers/handler_reset_password.go:289-290`

```go
var ResetPasswordIdentityFinish = middlewares.IdentityVerificationFinish(
    middlewares.IdentityVerificationFinishArgs{ActionClaim: ActionResetPassword},
    resetPasswordIdentityVerificationFinish,
)
```

### 6.2 JWT 验证流程

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

### 6.3 FindIdentityVerification 的防御逻辑

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

### 6.4 会话标记

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

### 6.5 速率限制

`internal/configuration/schema/server.go:149-154`

默认速率限制：
- 1 分钟内 10 次请求
- 2 分钟内 15 次请求

应用于 `/api/reset-password/identity/finish`，基于 IP 限流。

---

## 7. 阶段三：执行密码重置（Reset Password POST）

### 7.1 代码逻辑

`internal/handlers/handler_reset_password.go:136-229`

验证步骤：

1. **获取会话**：从 cookie 获取 `UserSession`
2. **检查身份验证标记**：`userSession.PasswordResetUsername == nil` → 拒绝
3. **密码策略检查**：`PasswordPolicy.Check(newPassword)`
4. **写入存储后端**：`UserProvider.UpdatePassword(username, newPassword)`
5. **清除会话标记**：`userSession.PasswordResetUsername = nil`，保存会话
6. **发送通知邮件**：获取用户邮箱，发送 "Password changed successfully" 通知

### 7.2 密码写入路径

`UserProvider.UpdatePassword()` 的实现取决于后端类型：
- **LDAP**：通过 LDAP Modify 操作更新 `userPassword` 属性
- **文件后端（YAML）**：直接更新 YAML 文件中的密码哈希

LDAP 情况下，如果 LDAP 服务器有密码策略（如 AD 的复杂度要求），会返回错误，Authelia 会将这些错误映射为用户友好的提示。

### 7.3 密码变更通知

`internal/handlers/handler_reset_password.go:206-228`

通知邮件内容：
- 标题：`"Password changed successfully"`
- 包含 `RemoteIP`（操作来源 IP）
- 包含 `Action: "Password Reset"`
- 使用 `EventEmailTemplate` 模板

**安全意义**：即使用户未主动请求重置，邮件到达后用户也能发现异常并采取措施。

---

## 8. 令牌撤销机制

### 8.1 DELETE 端点

`internal/handlers/handler_reset_password.go:20-133`

流程：
1. 从请求体获取 `token`
2. JWT 签名验证 + Claims 解析
3. 验证 `action == "ResetPassword"`
4. 从数据库加载 `IdentityVerification` 记录
5. 检查是否已被撤销
6. 执行撤销：`RevokeIdentityVerification(jti, remoteIP)`

### 8.2 前端撤销入口

`web/src/views/Revoke/RevokeResetPasswordTokenView.tsx`

邮件中同时包含验证链接和撤销链接。用户可以在意识到令牌泄露时主动撤销。

---

## 9. 对比：修改密码（Change Password）流程

### 9.1 端点

`POST /api/change-password` → `ChangePasswordPOST`

### 9.2 中间件要求

使用 `middlewareElevated1FA`，即 `RequireElevated`，要求：
- 用户已登录（1FA）
- 会话已提升（Elevation）或满足 SkipSecondFactor 条件

### 9.3 会话提升（Session Elevation）

与密码重置的 JWT 邮件验证不同，修改密码使用**一次性验证码（OTC）**机制：

| 方面 | 密码重置 | 修改密码（会话提升） |
|------|---------|-------------------|
| 身份验证方式 | JWT 邮件链接 | OTC 邮件验证码 |
| 前置要求 | 无需登录 | 需要已登录（1FA） |
| 令牌/代码有效期 | JWT 5 分钟（默认） | OTC 5 分钟 + 提升会话 10 分钟 |
| 存储位置 | `identity_verification` 表 | `one_time_code` 表 |
| 一次性保证 | 数据库 consumed_at 标记 | 数据库 consumed_at 标记 |
| 提升后有效期 | 会话 cookie 有效期 | 10 分钟（默认），IP 绑定 |

### 9.4 RequireElevated 中间件逻辑

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

## 10. 令牌有效期与一次性限制分析

### 10.1 密码重置 JWT

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

### 10.2 会话提升 OTC

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

### 10.3 密码重置 JWT vs 会话提升 OTC 的安全性对比

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

## 11. PasswordResetUsername 与会话过期边界的代码级确认

### 11.1 密码重置各端点的会话操作精确对账

#### 中间件链定义（`internal/server/handlers.go:203-215`）

| 中间件 | 组成 | 适用端点 |
|--------|------|---------|
| `middlewareAPI` | 安全头（Base + NoStore + CSPNone），**无授权检查** | 所有密码重置端点、登录、注销、健康检查等 |
| `middleware1FA` | 安全头 + `Require1FA` | 需要登录的普通操作 |
| `middlewareElevated1FA` | 安全头 + `RequireElevated` | 修改密码、2FA 设备管理等敏感操作 |

**代码证据**：`internal/server/handlers.go:203-215`

**密码重置端点均使用 `middlewareAPI`**，不经过任何授权中间件（`CookieSessionAuthnStrategy`）。代码级结论：
- 密码重置请求不检查 `Require1FA` 或 `RequireElevated`
- 不执行业务层 Inactivity 检查
- 不自动更新业务层 `LastActivity` 时间戳

#### 密码重置各端点会话操作逐段对账

| 端点 | HTTP 方法 | GetSession 调用 | SaveSession 调用 | 经过授权中间件 | 刷新 provider 层 `lastActiveTime` | 更新业务层 `LastActivity` |
|------|-----------|----------------|------------------|---------------|-------------------------------|-------------------------|
| `/api/reset-password/identity/start` | POST | ❌ 否 | ❌ 否 | ❌ 否 | ❌ 否 | ❌ 否 |
| `/api/reset-password/identity/finish` | POST | ✅ 只读（`handler_reset_password.go:275`） | ✅ 写入（`handler_reset_password.go:283`） | ❌ 否 | ✅ 是（Save 触发） | ❌ 否 |
| `/api/reset-password` | POST | ✅ 只读（`handler_reset_password.go:141`） | ✅ 写入（`handler_reset_password.go:185`） | ❌ 否 | ✅ 是（Save 触发） | ❌ 否 |
| `/api/reset-password` | DELETE | ❌ 否 | ❌ 否 | ❌ 否 | ❌ 否 | ❌ 否 |

**代码证据逐段确认**：

1. **Identity Start**：`internal/handlers/handler_reset_password.go:257-265`
   - 调用 `IdentityVerificationStart` 通用中间件
   - 身份检索函数 `identityRetrieverFromStorage` 仅查询用户信息
   - **代码确认**：无任何会话操作

2. **Identity Finish 回调**：`internal/handlers/handler_reset_password.go:267-286`
   ```go
   func resetPasswordIdentityVerificationFinish(ctx *middlewares.AutheliaCtx, username string) {
       ctx.ReplyOK()
       userSession, _ := ctx.GetSession()        // 只读
       userSession.PasswordResetUsername = &username
       ctx.SaveSession(userSession)              // 写入，触发 provider.Save()
   }
   ```
   - **代码确认**：先 GetSession 只读，后 SaveSession 写入

3. **Reset Password POST**：`internal/handlers/handler_reset_password.go:136-185`
   ```go
   func ResetPasswordPOST(ctx *middlewares.AutheliaCtx) {
       userSession, err := ctx.GetSession()      // 只读
       if userSession.PasswordResetUsername == nil { ... }
       // ... 密码策略检查、更新后端密码 ...
       userSession.PasswordResetUsername = nil
       if err = ctx.SaveSession(userSession); err != nil { ... }  // 写入
   }
   ```
   - **代码确认**：先 GetSession 只读，后 SaveSession 写入

4. **Delete（撤销令牌）**：`internal/handlers/handler_reset_password.go:20-133`
   - 仅验证 JWT 并撤销数据库中的令牌记录
   - **代码确认**：无任何会话操作

---

### 11.2 全量 API 路径的会话操作映射（可审计）

#### ✅ 触发 SaveSession（刷新 provider 层 `lastActiveTime`）的 API 路径

| 路径 | 方法 | handler 位置 | 触发 SaveSession 的原因 |
|------|------|-------------|------------------------|
| `/api/reset-password/identity/finish` | POST | `handler_reset_password.go:283` | 写入 `PasswordResetUsername` |
| `/api/reset-password` | POST | `handler_reset_password.go:185` | 清除 `PasswordResetUsername` |
| `/api/firstfactor` | POST | `handler_firstfactor_password.go:277` | 登录成功后保存会话 |
| `/api/firstfactor/passkey` | GET | `handler_firstfactor_passkey.go:72` | Passkey 认证流程 |
| `/api/firstfactor/passkey` | POST | `handler_firstfactor_passkey.go:141` | Passkey 认证成功 |
| `/api/secondfactor/totp` | POST | `handler_sign_totp.go:197` | TOTP 认证成功 |
| `/api/secondfactor/webauthn` | GET | `handler_sign_webauthn.go:107` | WebAuthn 认证流程 |
| `/api/secondfactor/webauthn` | POST | `handler_sign_webauthn.go:218` | WebAuthn 认证成功 |
| `/api/secondfactor/duo` | POST | `handler_sign_duo.go:339` | DUO 认证成功 |
| `/api/secondfactor/password` | POST | `handler_sign_password.go:87` | 密码二次认证成功 |
| `/api/user/session/elevation` | POST | `handler_session_elevation.go:98` | 会话提升启动 |
| `/api/user/session/elevation` | PUT | `handler_session_elevation.go:352` | 会话提升完成 |
| `/api/secondfactor/totp/register` | PUT | `handler_register_totp.go:116` | TOTP 注册流程 |
| `/api/secondfactor/totp/register` | POST | `handler_register_totp.go:242` | TOTP 注册完成 |
| `/api/secondfactor/totp/register` | DELETE | `handler_register_totp.go:294` | TOTP 注册删除 |
| `/api/secondfactor/webauthn/credential/register` | PUT | `handler_register_webauthn.go:117` | WebAuthn 注册流程 |
| `/api/secondfactor/webauthn/credential/register` | POST | `handler_register_webauthn.go:179` | WebAuthn 注册完成 |
| `/api/secondfactor/webauthn/credential/register` | DELETE | `handler_register_webauthn.go:281` | WebAuthn 注册删除 |
| `/api/authz/*`（授权中间件路径） | ANY | `handler_authz_authn.go:131` | 当 `modified = true` 时 |

**授权中间件 `modified = true` 的触发条件（`handler_authz_authn.go:117-134`）**：
1. `!userSession.KeepMeLoggedIn` → 非 Remember Me 用户的每次授权请求 → `handler_authz_authn.go:477-481`
2. RefreshInterval 触发 → 更新 `RefreshTTL` 或用户信息 → `handler_authz_authn.go:534-538`
3. 用户信息实际变更 → `handler_authz_authn.go:552`
4. cookie 域不匹配 → 销毁并创建新会话 → `handler_authz_authn.go:112`
5. 会话无效（如 Inactivity 超时）→ 重新创建 → `handler_authz_authn.go:125`

#### ❌ 只读 GetSession（不刷新 provider 层 `lastActiveTime`）的 API 路径

| 路径 | 方法 | handler 位置 | 代码证据 |
|------|------|-------------|----------|
| `/api/state` | GET | `handler_state.go:14` | 仅 `GetSession()` 读取，无 `SaveSession` |
| `/api/reset-password/identity/finish` 读取阶段 | POST | `handler_reset_password.go:275` | 仅 `GetSession()` 读取 |
| `/api/reset-password` 读取阶段 | POST | `handler_reset_password.go:141` | 仅 `GetSession()` 读取 |
| `/api/authz/*` 读取阶段 | ANY | `handler_authz_authn.go:99` | 仅 `manager.GetSession()` 读取 |

#### ❌ 完全不操作会话的 API 路径

| 路径 | 方法 | handler 位置 | 代码证据 |
|------|------|-------------|----------|
| `/api/reset-password/identity/start` | POST | `handler_reset_password.go:257-265` | 无会话操作 |
| `/api/reset-password` | DELETE | `handler_reset_password.go:20-133` | 无会话操作 |
| `/api/health` | GET/HEAD | `handler_health.go` | 无会话操作 |
| `/api/configuration/password-policy` | GET | `handler_configuration.go` | 无会话操作 |
| `/api/checks/safe-redirection` | POST | `handler_checks.go` | 无会话操作 |

---

### 11.3 会话过期的两层机制（代码级确认）

| 层面 | 检查位置 | 检查内容 | 适用场景 | 代码依据 |
|------|---------|---------|---------|---------|
| **存储层 GC** | `session/memory/provider.go:130-136` | `now >= lastActiveTime + expiration` | 所有请求的底层 session 查找 | `session/memory/provider.go:130-136` |
| **业务层 Inactivity** | `handler_authz_authn.go:486-496` | `LastActivity + Inactivity >= now` | **仅授权中间件路径** | `handler_authz_authn.go:486-496` |

#### 存储层 GC 逻辑（Memory Provider）
```go
// session/memory/provider.go:130-136
if item.expiration == 0 {
    return true
}
if now >= (item.lastActiveTime + item.expiration.Nanoseconds()) {
    _ = p.destroy(key.(string))
}
```
- `expiration`：cookie 的 Expiration（默认 1 小时，Remember Me 为 30 天）
- `lastActiveTime`：**仅在 Save 或 Regenerate 时更新**为当前时间
- `Get` 操作只读，不更新 `lastActiveTime`
- **代码依据**：`session/memory/provider.go:42-54`（Get）、`session/memory/provider.go:56-68`（Save）

#### 业务层 Inactivity 逻辑（仅授权中间件）
```go
// handler_authz_authn.go:477-481
if !userSession.KeepMeLoggedIn {
    modified = true
    userSession.LastActivity = ctx.GetClock().Now().Unix()  // 仅非 Remember Me 用户更新
}

// handler_authz_authn.go:486-496
func handleAuthnCookieValidateInactivity(...) (invalid bool) {
    if isAnonymous || userSession.KeepMeLoggedIn || int64(config.Inactivity.Seconds()) == 0 {
        return false  // Remember Me 用户跳过 Inactivity 检查
    }
    return time.Unix(userSession.LastActivity, 0).Add(config.Inactivity).Before(ctx.GetClock().Now())
}
```
- Inactivity 默认 5 分钟，但**仅适用于未勾选 Remember Me 的授权路径**
- 密码重置流程不经过授权中间件，Inactivity 检查完全不适用
- **代码依据**：`handler_authz_authn.go:486-496`

#### `GetSession()` 不检查 Inactivity 的代码证据
```go
// middlewares/authelia_context.go:380-406
func (ctx *AutheliaCtx) GetSession() (userSession session.UserSession, err error) {
    var provider *session.Session

    if provider, err = ctx.GetSessionProvider(); err != nil {
        return userSession, err
    }

    if userSession, err = provider.GetSession(ctx.RequestCtx); err != nil {
        ctx.Logger.Error("Unable to retrieve user session")
        return provider.NewDefaultUserSession(), nil
    }

    if userSession.CookieDomain != provider.Config.Domain {
        // ... 销毁跨域会话 ...
    }

    return userSession, nil  // 没有任何 Inactivity 检查！
}
```
- **代码级结论**：`GetSession()` 仅做 cookie 域匹配检查，**完全不检查 Inactivity**
- **代码依据**：`middlewares/authelia_context.go:380-406`

---

### 11.4 Memory 与 Redis Session Provider 的过期行为对比（可审计）

#### Memory Provider（`internal/session/memory/`）

| 操作 | 行为 | 代码位置 |
|------|------|---------|
| `Get(id)` | 只读，不更新 `lastActiveTime` | `provider.go:42-54` |
| `Save(id, data, expiration)` | `item.lastActiveTime = time.Now().UnixNano()`；`item.expiration = expiration` | `provider.go:56-68` |
| `Regenerate(id, newID, expiration)` | `item.lastActiveTime = time.Now().UnixNano()`；`item.expiration = expiration` | `provider.go:70-87` |
| GC 检查 | 遍历所有 session，`now >= lastActiveTime + expiration` | `provider.go:124-142` |

**过期语义**：会话在**最后一次 Save/Regenerate 之后的 `expiration` 时间**后过期。Get 操作不会刷新过期时间。
**代码依据**：`internal/session/memory/provider.go:42-142`

#### Redis Provider（`github.com/fasthttp/session/v2 v2.5.9`，外部依赖，实现级证据）

Authelia 通过 `github.com/fasthttp/session/v2` 抽象层使用 Redis Provider，依赖版本见 `go.mod:15`。Redis Provider 的核心实现在 `github.com/fasthttp/session/v2/providers/redis/` 包中。

**Authelia 层调用链证据**：
1. Authelia `Session.SaveSession` → `p.sessionHolder.Save(ctx, store)`（`internal/session/session.go:73`）
2. Authelia `Session.GetSession` → `p.sessionHolder.Get(ctx)`（`internal/session/session.go:33`）
3. Authelia `Session.RegenerateSession` → `p.sessionHolder.Regenerate(ctx)`（`internal/session/session.go:82`）
4. fasthttp/session `Session.Save` → `s.provider.Save(id, data, providerExpiration)`（`fasthttp/session/session.go:180`）
5. fasthttp/session `Session.Regenerate` → `s.provider.Regenerate(id, newID, providerExpiration)`（`fasthttp/session/session.go:214`）
6. Redis Provider 配置：`internal/session/provider_config.go:156-170`

**Redis Provider 实现级行为（源码可验证）**：

| 操作 | 行为（实现级） | 代码位置 |
|------|---------------|---------|
| `Get(id)` | 只读，仅执行 `GET` 命令，**不更新过期时间** | `providers/redis/provider.go:177-185` |
| `Save(id, data, expiration)` | 执行 `SET key value expiration` 命令，**重置过期时间为完整的 `expiration`** | `providers/redis/provider_base.go:24-28` |
| `Regenerate(id, newID, expiration)` | 执行 `RENAME key newKey` + `EXPIRE newKey expiration`，**重置过期时间为完整的 `expiration`** | `providers/redis/provider_base.go:32-48` |
| 过期检查 | 依赖 Redis 键过期机制（惰性删除 + 定期删除），`NeedGC()=false` 不主动 GC | `providers/redis/provider_base.go:72-77` |

**核心代码片段（Redis Provider v2.5.9）**：

```go
// providers/redis/provider.go:177-185
func (p *Provider) Get(id []byte) ([]byte, error) {
    key := p.getRedisSessionKey(id)
    reply, err := p.db.Get(context.Background(), key).Bytes()
    if err != nil && err != redis.Nil {
        return nil, err
    }
    return reply, nil  // 仅GET，不更新过期
}

// providers/redis/provider_base.go:24-28
func (p *Provider) Save(id, data []byte, expiration time.Duration) error {
    key := p.getRedisSessionKey(id)
    return p.db.Set(context.Background(), key, data, expiration).Err()  // SET带过期，重置过期时间
}

// providers/redis/provider_base.go:32-48
func (p *Provider) Regenerate(id, newID []byte, expiration time.Duration) error {
    // ... 检查key存在 ...
    if err = p.db.Rename(context.Background(), key, newKey).Err(); err != nil {
        return err
    }
    if err = p.db.Expire(context.Background(), newKey, expiration).Err(); err != nil {
        return err  // 显式EXPIRE，重置过期时间
    }
    return nil
}
```

**代码依据**：
- Authelia 调用链：`internal/session/session.go:33, 73, 82`
- fasthttp/session 核心调用：`fasthttp/session/session.go:180, 214`
- Redis Provider Get：`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider.go:177-185`
- Redis Provider Save：`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider_base.go:24-28`
- Redis Provider Regenerate：`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider_base.go:32-48`
- 依赖版本：`go.mod:15`
- 配置层：`internal/session/provider_config.go:156-170`

#### 一致性与差异总结（可审计，实现级对比）

| 维度 | Memory Provider（实现级） | Redis Provider（实现级） | 一致性 |
|------|-------------------------|------------------------|-------|
| **Get 操作更新过期时间** | ❌ 否<br>仅读取数据，不修改 `lastActiveTime`<br>`internal/session/memory/provider.go:42-54` | ❌ 否<br>仅执行 `GET` 命令，不调用 `EXPIRE`<br>`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider.go:177-185` | ✅ 完全一致 |
| **Save 操作重置过期时间** | ✅ 是<br>`item.lastActiveTime = time.Now().UnixNano()`<br>`item.expiration = expiration`<br>`internal/session/memory/provider.go:56-68` | ✅ 是<br>`SET key value expiration` 原子设置过期<br>`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider_base.go:24-28` | ✅ 完全一致 |
| **Regenerate 操作重置过期时间** | ✅ 是<br>`item.lastActiveTime = time.Now().UnixNano()`<br>`item.expiration = expiration`<br>`internal/session/memory/provider.go:70-87` | ✅ 是<br>`RENAME` + 显式 `EXPIRE newKey expiration`<br>`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider_base.go:32-48` | ✅ 完全一致 |
| **过期计算方式** | 相对时间计算<br>`now >= lastActiveTime + expiration`<br>`internal/session/memory/provider.go:130-136` | 绝对时间戳<br>Redis 键 TTL 自动过期（SET 时设置） | ⚠️ 实现不同，语义等价 |
| **过期检查触发** | 应用层 GC 周期触发<br>`NeedGC()=true`，每 GCLifetime 扫描一次<br>`internal/session/memory/provider.go:124-142` | Redis 服务端自动过期<br>`NeedGC()=false`，依赖惰性删除+定期删除<br>`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider_base.go:72-77` | ⚠️ 实现不同，语义等价 |

**代码级结论**：Memory Provider 和 Redis Provider 在**过期语义上完全一致**——**只有 Save/Regenerate 操作会刷新过期时间**，Get 操作不会。两者的最终效果相同：每次 Save/Regenerate 重置为完整的 `expiration` 时长。

**代码依据（完整调用链）**：
1. Authelia 层调用：`internal/session/session.go:33, 73, 82`
2. fasthttp/session 层转发：`fasthttp/session/session.go:180, 214`
3. Memory Provider 实现：`internal/session/memory/provider.go:42-142`
4. Redis Provider 实现：`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider.go:177-185`、`provider_base.go:24-48`

---

### 11.5 PasswordResetUsername 的过期边界（代码级确认）

```go
// internal/handlers/handler_reset_password.go:146-152
// Those checks ensure that the identity verification process has been initiated and completed successfully
// otherwise PasswordReset would not be set to true. We can improve the security of this check by making the
// request expire at some point because here it only expires when the cookie expires.
if userSession.PasswordResetUsername == nil {
    ctx.Error(fmt.Errorf("no identity verification process has been initiated"), messageUnableToResetPassword)
    return
}
```

**代码注释的明确说明**：PasswordResetUsername 除了 cookie 过期时间外没有独立的过期时间。这是一个**已知的设计限制**，代码作者明确标注需要改进。

#### PasswordResetUsername 的真实过期条件

| 过期条件 | 是否触发 | 代码依据 |
|---------|---------|---------|
| cookie Expiration 到期（存储层 GC） | ✅ 是 | `session/memory/provider.go:130-136` |
| Inactivity 超时（默认 5 分钟） | ❌ 否 | 密码重置流程不经过授权中间件，`GetSession()` 不检查 Inactivity（`internal/middlewares/authelia_context.go:380-406`） |
| JWT 过期（默认 5 分钟） | 不适用 | JWT 已在 Identity Finish 阶段消费（`ConsumeIdentityVerification`），与 PasswordResetUsername 过期无关 |
| 密码重置成功 | ✅ 是 | `ResetPasswordPOST` 将其设为 nil（`handler_reset_password.go:183`） |
| 用户主动登出 | ✅ 是 | `LogoutPOST` 调用 `DestroySession`（`handler_logout.go`） |
| 重新登录 | ✅ 是 | 登录流程先 `DestroySession` 再创建新会话（`handler_firstfactor_password.go:101`） |
| cookie 域不匹配 | ✅ 是 | `GetSession()` 检测到跨域时销毁会话（`internal/middlewares/authelia_context.go:392-403`） |

---

### 11.6 PasswordResetUsername 与 Remember Me 的关系（代码级确认）

Remember Me 影响的是 **cookie 的 Expiration**，而 PasswordResetUsername 的存活完全依赖 cookie Expiration。

#### 场景 1：未登录用户发起重置
- 用户未登录，点击"忘记密码"按钮
- 浏览器已有一个未认证的会话 cookie（Expiration = 默认 1 小时）
- 完成身份验证（Identity Finish）时调用 `SaveSession`，刷新 provider 层 `lastActiveTime`
- **代码级结论**：PasswordResetUsername 最大存活时间 = 1 小时（从 Identity Finish 的 SaveSession 开始计算）
- 刷新条件：必须触发其他 `SaveSession` 调用（参见 11.2 节列表）
- **代码依据**：`session/memory/provider.go:56-68`

#### 场景 2：已登录但未勾选 Remember Me 的用户发起重置
- 用户已登录但未勾选 Remember Me
- cookie Expiration = 默认 1 小时
- 完成身份验证后，PasswordResetUsername 写入该会话
- **代码级结论**：PasswordResetUsername 最大存活时间 = 1 小时（从最后一次 SaveSession 开始计算）
- 刷新条件：访问任何授权端点（`/api/authz/*`）时，因 `!KeepMeLoggedIn` 自动更新 `LastActivity` 并触发 `SaveSession` → 刷新 1 小时窗口
- **代码依据**：`handler_authz_authn.go:477-481, 130-133`

#### 场景 3：已登录且勾选 Remember Me 的用户发起重置
- 用户已登录且勾选了 Remember Me
- 登录成功时 `UpdateExpiration(RememberMe)`（默认 30 天）被调用
  ```go
  // internal/handlers/handler_firstfactor_password.go:124-128
  if rememberMe && !ctx.Configuration.Session.DisableRememberMe {
      userSession.KeepMeLoggedIn = true
      userSession.Expires = time.Now().Add(ctx.Configuration.Session.RememberMe).Unix()
      ctx.SaveSession(userSession)
  }
  ```
- 完成身份验证后，PasswordResetUsername 写入该会话
- **代码级结论**：PasswordResetUsername 最大存活时间 = 30 天（从最后一次 SaveSession 开始计算）
- 刷新条件：访问授权端点时**不会自动刷新**（因 `KeepMeLoggedIn = true`，`handler_authz_authn.go:477` 条件不成立）。仅当 RefreshInterval 触发、会话状态变更（如 Elevation、2FA 认证）或其他 `SaveSession` 调用发生时，才会刷新窗口
- **代码依据**：`handler_authz_authn.go:477`（`if !userSession.KeepMeLoggedIn` 才更新 `LastActivity`）

---

### 11.7 可重置窗口延长与保持不变的精确边界（代码级）

#### ✅ 会延长可重置窗口的场景（必须触发 SaveSession）

| 场景 | 延长原因 | 代码依据 |
|------|---------|---------|
| 完成身份验证（Identity Finish） | 调用 `SaveSession` 写入 PasswordResetUsername → 刷新 provider 层 `lastActiveTime`（Memory）或重置键 TTL（Redis） | `internal/handlers/handler_reset_password.go:283` |
| 提交新密码（Reset Password POST） | 调用 `SaveSession` 清除 PasswordResetUsername → 刷新过期时间（但此时 PasswordResetUsername 已被清除，窗口无实际意义） | `internal/handlers/handler_reset_password.go:185` |
| 未勾选 Remember Me 的用户访问任何授权端点 | 授权中间件更新 `LastActivity` → `modified = true` → `SaveSession` → 刷新过期时间 | `internal/handlers/handler_authz_authn.go:477-481, 130-133` |
| 任何用户访问触发 RefreshInterval 的授权端点 | 授权中间件更新 `RefreshTTL` 或用户信息 → `modified = true` → `SaveSession` → 刷新过期时间 | `internal/handlers/handler_authz_authn.go:534-538` |
| 用户修改会话状态（Elevation、2FA 认证、2FA 设备注册/删除等） | 相应 handler 调用 `SaveSession` → 刷新过期时间 | 见 11.2 节完整列表 |

#### ❌ 不会延长可重置窗口的场景（无 SaveSession 调用）

| 场景 | 不延长原因 | 代码依据 |
|------|-----------|---------|
| 仅访问静态页面（/reset-password/step1, /reset-password/step2） | 静态资源加载，不调用后端 API，不操作会话 | 前端路由，无后端会话操作 |
| 调用 Identity Start | 仅查询用户信息和发送邮件，不操作会话 | `internal/handlers/handler_reset_password.go:240-272` 无会话操作 |
| 调用 Delete（撤销令牌） | 仅验证 JWT 和修改数据库记录，不操作会话 | `internal/handlers/handler_reset_password.go:20-133` 无会话操作 |
| 仅调用 GetSession（只读） | 不触发 `SaveSession` → 不更新 `lastActiveTime`（Memory）或键 TTL（Redis） | `internal/session/memory/provider.go:42-54`<br>`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider.go:177-185` |
| 勾选 Remember Me 的用户访问不修改会话的授权端点 | Remember Me 用户不更新 `LastActivity`，且无其他修改 → `modified = false` → 不调用 `SaveSession` | `internal/handlers/handler_authz_authn.go:477` `if !userSession.KeepMeLoggedIn` |
| JWT 有效期（默认 5 分钟） | JWT 只在 Identity Finish 阶段使用，消费后即失效，与 PasswordResetUsername 过期无关 | `internal/handlers/handler_reset_password.go:289` 标记 `consumed_at` |
| Inactivity 超时（默认 5 分钟） | 密码重置流程不经过授权中间件，`GetSession()` 不检查 Inactivity | `internal/middlewares/authelia_context.go:380-406` |
| 用户关闭浏览器标签页 | 只要浏览器进程未完全退出，cookie 仍在内存中，无后端操作 | cookie 生命周期 |
| 用户导航离开密码重置页面 | 无后端调用，PasswordResetUsername 仍保留在会话中 | 无主动清除逻辑 |

#### 🔒 立即终止可重置窗口的场景

| 场景 | 终止原因 | 代码依据 |
|------|---------|---------|
| 密码重置成功 | `ResetPasswordPOST` 将 `PasswordResetUsername` 设为 nil | `internal/handlers/handler_reset_password.go:183` |
| 用户主动登出 | `LogoutPOST` 调用 `DestroySession` 销毁整个会话 | `internal/handlers/handler_logout.go` |
| 重新登录 | 登录流程先 `DestroySession` 再创建新会话 | `internal/handlers/handler_firstfactor_password.go:101` |
| cookie 自然过期 | 存储层 GC（Memory）或 Redis 键 TTL 自动过期 | `internal/session/memory/provider.go:130-136`<br>`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider_base.go:24-28` |
| cookie 域不匹配 | `GetSession()` 检测到跨域时销毁会话 | `internal/middlewares/authelia_context.go:392-403` |

---

### 11.8 之前分析的修正说明（证据不足判断的清理）

| 之前的不准确表述 | 修正后的代码级结论 | 修正原因 |
|-----------------|-------------------|---------|
| "只要用户在 30 天内有任何活动，窗口就会持续刷新" | "只有触发 SaveSession 的活动才能刷新窗口。Remember Me 用户的普通授权请求不会自动刷新，除非 RefreshInterval 触发或有其他会话修改" | `handler_authz_authn.go:477` 明确只有 `!KeepMeLoggedIn` 时才更新 `LastActivity` |
| "可无限刷新" | "可在 cookie Expiration 内（1 小时或 30 天）通过触发 SaveSession 刷新，但不能超过 cookie 的绝对过期时间（由浏览器强制）" | 没有 SaveSession 调用，`lastActiveTime` 不会更新；cookie 有浏览器强制的绝对过期时间 |
| "访问任何 Authelia 页面都会刷新" | "只有访问会触发后端 API 且该 API 调用 SaveSession 的页面才会刷新。静态页面不会" | 静态页面不调用后端 API，不操作会话 |

---

## 12. 弱信任环境下的安全评估

### 12.1 已有的安全机制

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

### 12.2 潜在风险与建议

#### 风险 1：邮箱即唯一信任因子（可审计表述）

**风险陈述**：密码重置的身份验证完全依赖邮箱所有权，无其他第二因子验证。若邮箱账户被入侵，攻击者可绕过所有其他安全机制重置用户密码。

**代码级证据**：
1. 身份验证启动（Identity Start）仅需用户名，无额外验证：`internal/handlers/handler_reset_password.go:240-272`
2. 身份验证完成（Identity Finish）仅验证 JWT 令牌有效性，JWT 仅通过邮件发送：`internal/handlers/handler_reset_password.go:274-295`
3. JWT 默认有效期 5 分钟：`internal/handlers/handler_reset_password.go:237`
4. 无其他第二因子验证逻辑（如短信、TOTP 等）

**边界条件**：
- JWT 一次性使用：`consumed_at` 字段标记后不可重复使用<br>`internal/handlers/handler_reset_password.go:289`
- JWT 可撤销：DELETE 端点设置 `revoked_at` 标记<br>`internal/handlers/handler_reset_password.go:20-133`

**审计建议**：
- 考虑为高安全场景增加二次确认机制（如短信验证码、管理员审批等）
- 限制单个账户在特定时间窗口内的密码重置尝试次数

---

#### 风险 2：密码重置后旧会话未失效（可审计表述）

**风险陈述**：密码重置成功后，`ResetPasswordPOST` 仅清除 `PasswordResetUsername` 标志位，不销毁该用户的现有会话。若攻击者已获取用户会话 cookie，密码重置后攻击者仍可通过旧会话继续访问。

**代码级证据**：
1. `ResetPasswordPOST` 处理逻辑：
   ```go
   // internal/handlers/handler_reset_password.go:167-189
   func ResetPasswordPOST(ctx *middlewares.AutheliaCtx) {
       // ... 验证 PasswordResetUsername ...
       // ... 更新密码 ...
       userSession.PasswordResetUsername = nil  // 仅清除标志位
       err = ctx.SaveSession(userSession)      // 仅保存，不销毁会话
       // ... 发送通知 ...
   }
   ```
2. 无调用 `DestroySession()` 或类似全局会话失效逻辑
3. 对比：登录流程会先销毁旧会话再创建新会话<br>`internal/handlers/handler_firstfactor_password.go:101`

**攻击场景（代码可验证）**：
1. 攻击者已获取用户的有效会话 cookie
2. 用户发起密码重置并成功设置新密码
3. 旧会话未被销毁，攻击者仍可使用旧 cookie 访问受保护资源
4. 会话过期仅受 cookie Expiration 和 SaveSession 刷新机制控制

**审计建议**：
- 密码重置成功后，应主动销毁该用户的所有现有会话
- 可通过存储层查询该用户的所有会话并逐个销毁，或引入会话黑名单机制
- 参考登录流程的会话销毁逻辑：`internal/handlers/handler_firstfactor_password.go:101`

#### 风险 3：PasswordResetUsername 无独立过期时间，可被不当延长（可审计表述）

**风险陈述**：`PasswordResetUsername` 标志位无独立过期时间，仅与会话 cookie 过期时间绑定。在特定条件下，可通过触发 SaveSession 调用延长密码重置的有效窗口。

**代码级事实确认（逐条对账）**：

| 事实陈述 | 真伪 | 代码依据 |
|---------|------|---------|
| `PasswordResetUsername` 受 Inactivity（5 分钟）超时限制 | ❌ 伪 | 密码重置流程调用 `GetSession()` 读取会话，该方法仅检查 cookie 域匹配，不检查 Inactivity。Inactivity 检查仅在授权中间件（`/api/authz/*`）中执行。<br>`internal/middlewares/authelia_context.go:380-406` |
| `PasswordResetUsername` 默认最多 1 小时窗口 | ⚠️ 部分真 | 未登录或未勾选 Remember Me 时，cookie Expiration = 1 小时；勾选 Remember Me 时，cookie Expiration = 30 天。<br>`internal/handlers/handler_firstfactor_password.go:124-128` |
| 可通过用户持续活动无限刷新窗口 | ❌ 伪 | 只有触发 SaveSession 调用的活动才能刷新 provider 层 `lastActiveTime`。刷新不能超过 cookie 的绝对过期时间（浏览器强制）。<br>`internal/session/memory/provider.go:56-68`（Save 更新 `lastActiveTime`） |
| Remember Me 用户可"无限续期" | ❌ 伪 | 需在 cookie Expiration 内（30 天）触发 SaveSession 调用，且延长后的过期时间不能超过 cookie 的绝对过期时间。<br>`internal/handlers/handler_authz_authn.go:477`（Remember Me 用户不更新 `LastActivity`） |

**过期行为的精确边界（代码可验证）**：

1. **过期条件**：`PasswordResetUsername` 仅在以下情况过期：
   - 存储层 GC 回收：`now >= lastActiveTime + expiration`（Memory Provider）或 Redis 键 TTL 到期（Redis Provider）
   - 密码重置成功：`ResetPasswordPOST` 将其设为 `nil`
   - 会话销毁：登出、重新登录、cookie 域不匹配

2. **窗口延长条件**（满足任一即可）：
   - 调用 `SaveSession`：刷新 `lastActiveTime`（Memory）或重置键 TTL（Redis）
   - 调用 `RegenerateSession`：重置会话 ID 并刷新过期时间

3. **窗口不延长的边界**：
   - 仅调用 `GetSession`：不修改 `lastActiveTime`，不刷新过期
   - 访问静态页面：不调用后端 API，不操作会话
   - Remember Me 用户的普通授权请求：不更新 `LastActivity`，不触发 SaveSession（除非 RefreshInterval 触发）

**代码证据链（完整可回溯）**：
1. `GetSession()` 不检查 Inactivity：`internal/middlewares/authelia_context.go:380-406`
2. 代码作者明确标注设计限制："We can improve the security of this check by making the request expire at some point because here it only expires when the cookie expires." <br>`internal/handlers/handler_reset_password.go:146-148`
3. Remember Me 场景下 cookie Expiration = 30 天：`internal/handlers/handler_firstfactor_password.go:124-128`
4. 只有 Save/Regenerate 操作更新过期时间：
   - Memory Provider：`internal/session/memory/provider.go:56-87`
   - Redis Provider：`github.com/fasthttp/session/v2@v2.5.9/providers/redis/provider_base.go:24-48`
5. Remember Me 用户的普通授权请求不更新 `LastActivity`：`internal/handlers/handler_authz_authn.go:477`

**攻击场景（基于代码级证据）**：
1. 用户在 Remember Me 状态下完成密码重置身份验证 → Identity Finish 调用 SaveSession 刷新过期时间<br>`internal/handlers/handler_reset_password.go:283`
2. 攻击者窃取会话 cookie
3. 攻击者需在 30 天内触发 SaveSession 调用以延长窗口：
   - 访问授权端点（`/api/authz/*`）触发 RefreshInterval（满足 `RefreshInterval > 0` 且时间间隔足够）<br>`internal/handlers/handler_authz_authn.go:534-538`
   - 或执行其他修改会话的操作（2FA 认证、设备管理等）
   - **边界**：`/api/state` 仅使用 middlewareAPI，不经过授权中间件，不会触发 RefreshInterval<br>`internal/server/handlers.go:220`
4. 即使不断刷新，也不能超过 cookie 的绝对过期时间（浏览器强制）
5. 攻击者可在有效期内提交新密码

**审计建议**：
- 为 `PasswordResetUsername` 添加独立过期时间戳字段（如 `PasswordResetExpiresAt`）
- 在 `ResetPasswordPOST` 中检查独立过期时间，建议设置为 15-30 分钟
- 独立过期时间不应被任何 SaveSession 调用刷新
- 在 Identity Finish 阶段设置独立过期时间戳

---

#### 风险 4：IP 不绑定于密码重置流程（可审计表述）

**风险陈述**：与修改密码的 Session Elevation（绑定 RemoteIP）不同，密码重置流程不验证 IP 一致性。`IdentityVerification` 记录了 `issued_ip` 和 `consumed_ip`，但仅用于审计，不做强制校验。

**代码级证据**：
1. `IdentityVerification` 表结构包含 `issued_ip` 和 `consumed_ip` 字段，用于记录但不验证：
   - `issued_ip` 在 Identity Start 阶段记录：`internal/handlers/handler_reset_password.go:255`
   - `consumed_at` 和 `consumed_ip` 在 Identity Finish 阶段记录：`internal/handlers/handler_reset_password.go:289`
2. Identity Finish 阶段无 IP 一致性校验逻辑，仅验证 JWT 有效性和令牌状态（未消费、未撤销、未过期）：`internal/handlers/handler_reset_password.go:274-295`
3. 对比：Session Elevation（修改密码）强制校验 IP 一致性<br>`internal/handlers/handler_session_elevation.go`

**边界条件**：
- JWT 有效期默认 5 分钟，降低了截获窗口
- JWT 一次性使用，`consumed_at` 标记后不可重复使用
- 实际风险取决于邮件传输的安全性（邮件是否可能被中间人读取）

**审计建议**：
- 考虑增加 IP 一致性校验（`issued_ip` 必须与 `consumed_ip` 匹配）
- 或增加异常 IP 检测逻辑，如跨地域访问时增加额外验证

---

#### 风险 5：JWT 密钥泄露（可审计表述）

**风险陈述**：`identity_validation.reset_password.jwt_secret` 用于签署和验证所有密码重置 JWT。如果此密钥泄露，攻击者可为任意用户伪造有效的密码重置令牌，绕过整个身份验证流程。

**代码级证据**：
1. JWT 签名密钥配置：`internal/configuration/schema/identity_validation.go`（`jwt_secret` 字段）
2. JWT 签名逻辑：Identity Start 阶段使用密钥签署 JWT<br>`internal/handlers/handler_reset_password.go:237`
3. JWT 验证逻辑：Identity Finish 阶段使用密钥验证 JWT 签名<br>`internal/handlers/handler_reset_password.go:282`
4. 密钥泄露后果：攻击者可构造任意 `iat`、`exp`、`jti`、`username` 字段的 JWT，使用泄露的密钥签名，即可通过验证

**边界条件**：
- 密钥泄露为假设性风险，需结合实际部署环境评估
- JWT 包含 `jti`（唯一令牌 ID），理论上可通过黑名单机制缓解，但当前实现仅依赖数据库 `consumed_at` 标记

**审计建议**：
- 确保 JWT Secret 的安全存储（使用密钥管理系统，避免硬编码）
- 建立密钥轮换机制，定期更换 JWT 密钥
- 考虑增加 JWT `jti` 黑名单机制，密钥泄露后可快速作废所有未消费令牌

### 12.3 与 Remember Me 的交互

| 场景 | 对 PasswordResetUsername 的影响 | 代码依据 | 确认程度 |
|------|------------------------------|---------|---------|
| **用户在 Remember Me 状态下发起重置** | cookie Expiration = 30 天，`PasswordResetUsername` 可存活 **30 天**（从最后一次 Save 开始计算）。只有触发 SaveSession 的活动才能刷新窗口，不是所有活动。 | `handler_firstfactor_password.go:124-128` | ✅ 确定 |
| **未登录用户发起重置** | cookie Expiration = 1 小时，`PasswordResetUsername` 最多存活 **1 小时**。只有触发 SaveSession 的活动才能刷新。 | 未登录会话使用默认 Expiration | ✅ 确定 |
| **已登录但未勾选 Remember Me** | cookie Expiration = 1 小时，`PasswordResetUsername` 最多存活 **1 小时**。访问授权端点会自动刷新（因为非 Remember Me 用户每次授权请求都会更新 LastActivity 并触发 SaveSession）。 | `handler_authz_authn.go:477-481, 130-133` | ✅ 确定 |
| **用户密码被重置后使用旧 cookie** | 旧 cookie 仍然有效，因为密码重置不会使会话失效 | `ResetPasswordPOST` 不调用 `DestroySession` | ✅ 确定 |
| **攻击者窃取 Remember Me cookie** | 需要在 30 天内**触发 SaveSession 调用**（如访问触发 RefreshInterval 的端点）才能刷新窗口。不能"无限续期"，受限于 cookie 的绝对过期时间。 | `session/memory/provider.go:56-68` Save 更新 lastActiveTime | ✅ 确定 |
| **用户在身份验证后重新登录** | 登录会销毁旧会话，`PasswordResetUsername` 丢失，需重新发起重置 | `handler_firstfactor_password.go:101` 调用 `DestroySession` | ✅ 确定 |

**关键安全洞察（修正后）**：Remember Me 对密码重置窗口的放大效应确实存在（30 天 vs 1 小时），但**不是"无限刷新"**。刷新窗口需要实际触发 SaveSession 调用，且不能超过 cookie 的绝对过期时间。非 Remember Me 用户的授权端点访问会自动刷新窗口（因为每次都更新 LastActivity），而 Remember Me 用户的普通授权访问不会自动刷新。

### 12.4 密码重置 vs 修改密码的安全性层级

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

## 13. 完整流程时序图

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

## 14. 关键代码文件索引

| 文件 | 行号 | 功能 |
|------|------|------|
| **配置与模板层** | | |
| `internal/server/template.go` | 220-254 | 配置计算与 HTML 模板数据注入 |
| `internal/server/template.go` | 227-228 | resetPassword 和 custom_url 配置值计算 |
| `internal/server/template.go` | 234 | 后端 API 端点注册条件判定 |
| `internal/server/public_html/index.html` | 1-12 | 配置嵌入到 HTML data-* 属性 |
| `internal/server/handlers.go` | 203-215 | 中间件链定义（middlewareAPI 不包含授权） |
| `internal/server/handlers.go` | 261-272 | 后端 API 路由注册 |
| **后端配置** | | |
| `internal/configuration/schema/identity_validation.go` | 8-39 | 身份验证配置结构与默认值 |
| `internal/configuration/schema/session.go` | 77-86 | 会话配置默认值（Expiration/Inactivity/RememberMe） |
| **后端核心处理** | | |
| `internal/handlers/handler_reset_password.go` | 20-133 | DELETE 撤销令牌（不操作会话） |
| `internal/handlers/handler_reset_password.go` | 136-229 | POST 执行密码重置 |
| `internal/handlers/handler_reset_password.go` | 141 | ResetPasswordPOST 中 GetSession 调用（只读） |
| `internal/handlers/handler_reset_password.go` | 146-148 | PasswordResetUsername 过期机制注释（已知安全弱点） |
| `internal/handlers/handler_reset_password.go` | 183 | 重置成功后清除 PasswordResetUsername |
| `internal/handlers/handler_reset_password.go` | 185 | ResetPasswordPOST 中 SaveSession 调用 |
| `internal/handlers/handler_reset_password.go` | 231-253 | 身份检索（从存储，不操作会话） |
| `internal/handlers/handler_reset_password.go` | 257-265 | IdentityStart 入口（不操作会话） |
| `internal/handlers/handler_reset_password.go` | 267-290 | IdentityFinish 回调 + 入口（GetSession + SaveSession） |
| `internal/handlers/handler_reset_password.go` | 275 | IdentityFinish 中 GetSession 调用（只读） |
| `internal/handlers/handler_reset_password.go` | 283 | IdentityFinish 中 SaveSession 调用 |
| `internal/handlers/handler_firstfactor_password.go` | 89-152 | 登录流程会话管理 |
| `internal/handlers/handler_firstfactor_password.go` | 101 | 登录流程中 DestroySession 调用 |
| `internal/handlers/handler_firstfactor_password.go` | 124-128 | Remember Me 设置 cookie Expiration |
| `internal/handlers/handler_authz_authn.go` | 90-147 | CookieSessionAuthnStrategy.Get（授权中间件） |
| `internal/handlers/handler_authz_authn.go` | 117-134 | 授权中间件 SaveSession 触发逻辑（modified 标志） |
| `internal/handlers/handler_authz_authn.go` | 477-481 | 非 Remember Me 用户更新 LastActivity |
| `internal/handlers/handler_authz_authn.go` | 486-496 | 业务层 Inactivity 检查（仅授权中间件） |
| `internal/handlers/handler_authz_authn.go` | 493-495 | Inactivity 检查日志与判断逻辑 |
| `internal/handlers/handler_authz_authn.go` | 535-538 | RefreshInterval 更新 RefreshTTL 触发 modified |
| **中间件** | | |
| `internal/middlewares/identity_verification.go` | 18-138 | IdentityVerificationStart 通用中间件 |
| `internal/middlewares/identity_verification.go` | 143-264 | IdentityVerificationFinish 通用中间件 |
| `internal/middlewares/authelia_context.go` | 380-406 | GetSession() - 不检查 Inactivity 的关键证据 |
| `internal/middlewares/require_auth.go` | 24-136 | RequireElevated 中间件 |
| **数据模型** | | |
| `internal/model/identity_verification.go` | 14-78 | IdentityVerification 模型 + JWT Claims |
| `internal/model/one_time_code.go` | 13-68 | OneTimeCode 模型（会话提升用） |
| **会话管理** | | |
| `internal/session/types.go` | 20-83 | UserSession 结构（含 PasswordResetUsername） |
| `internal/session/user_session.go` | 24-37 | 认证级别计算 |
| `internal/session/session.go` | 30-54 | Session.GetSession（只读，不检查 Inactivity） |
| `internal/session/session.go` | 57-78 | Session.SaveSession（写入，触发 provider.Save） |
| `internal/session/memory/provider.go` | 42-54 | Memory Provider Get（只读，不更新 lastActiveTime） |
| `internal/session/memory/provider.go` | 56-68 | Memory Provider Save（更新 lastActiveTime = now） |
| `internal/session/memory/provider.go` | 70-87 | Memory Provider Regenerate（更新 lastActiveTime = now） |
| `internal/session/memory/provider.go` | 124-142 | Memory Provider GC 逻辑（检查 lastActiveTime + expiration） |
| `internal/session/memory/types.go` | 19-20 | Memory Provider item 结构（lastActiveTime, expiration） |
| `internal/session/provider_config.go` | 59 | 设置 session cookie Expiration |
| **存储操作** | | |
| `internal/storage/sql_provider.go` | 953-1014 | 身份验证存储操作 |
| **前端配置读取** | | |
| `web/src/utils/Configuration.ts` | 22-31 | 前端读取 resetPassword 和 custom_url 配置 |
| **前端登录页** | | |
| `web/src/views/LoginPortal/FirstFactor/FirstFactorForm.tsx` | 38-40 | Props 定义（resetPassword, resetPasswordCustomURL） |
| `web/src/views/LoginPortal/FirstFactor/FirstFactorForm.tsx` | 167-175 | 点击"忘记密码"按钮的分流逻辑 |
| `web/src/views/LoginPortal/FirstFactor/FirstFactorForm.tsx` | 384-405 | 按钮渲染条件 |
| `web/src/App.tsx` | 64-75 | LoginPortal 路由，配置传递 |
| **前端重置流程** | | |
| `web/src/constants/Routes.ts` | 10-11 | 重置流程路由定义 |
| `web/src/App.tsx` | 57-58 | 重置页面路由注册 |
| `web/src/services/ResetPassword.ts` | 1-34 | 前端 API 调用封装 |
| `web/src/views/ResetPassword/ResetPasswordStep1.tsx` | 15-143 | 前端步骤1：输入用户名 |
| `web/src/views/ResetPassword/ResetPasswordStep2.tsx` | 20-238 | 前端步骤2：输入新密码 |
| `web/src/views/ResetPassword/ResetPasswordStep2.tsx` | 54-83 | 页面加载自动调用 completeResetPasswordProcess |
| `web/src/views/ResetPassword/ResetPasswordStep2.tsx` | 85-123 | 提交新密码逻辑 |
| **其他** | | |
| `internal/handlers/handler_change_password.go` | 13-152 | 修改密码处理器 |
| `internal/handlers/handler_session_elevation.go` | 23-442 | 会话提升处理器 |
| `web/src/views/Revoke/RevokeResetPasswordTokenView.tsx` | 1-56 | 令牌撤销页面 |
