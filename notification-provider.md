# Authelia 通知 Provider 工作机制详解

## 一、核心接口定义

通知系统的核心是 `Notifier` 接口，定义在 `internal/notification/notifier.go:12-16`：

```go
type Notifier interface {
    model.StartupCheck
    Send(ctx context.Context, recipient mail.Address, subject string, et *templates.EmailTemplate, data any) (err error)
}
```

**接口说明：**
- `StartupCheck()`: 启动时检查通知通道是否可用
- `Send()`: 发送通知的核心方法

通知 provider 被注入到全局的 `Providers` 结构体中，定义在 `internal/middlewares/types.go:40-58`：
```go
type Providers struct {
    Notifier notification.Notifier  // 通知提供者
    // ... 其他提供者
}
```

---

## 二、通知通道类型与注册方式

### 2.1 支持的通知通道

Authelia 目前支持两种通知通道：

| 通道类型 | 实现文件 | 用途 |
|---------|---------|------|
| **SMTP** | `internal/notification/smtp_notifier.go` | 通过邮件服务器发送真实邮件 |
| **FileSystem** | `internal/notification/file_notifier.go` | 将通知写入本地文件（主要用于测试） |

### 2.2 配置验证

在 `internal/configuration/validator/notifier.go:12-34` 中进行配置验证：

```go
func ValidateNotifier(config *schema.Notifier, validator *schema.StructValidator) {
    // 1. 必须且只能配置一种通知方式
    if config.SMTP == nil && config.FileSystem == nil {
        validator.Push(errors.New("notifier not configured"))
        return
    } else if config.SMTP != nil && config.FileSystem != nil {
        validator.Push(errors.New("multiple notifiers configured"))
        return
    }
    // 2. 验证具体配置
    if config.FileSystem != nil { /* 验证文件路径 */ }
    if config.SMTP != nil { validateSMTPNotifier(config.SMTP, validator) }
}
```

**关键约束：**
- ✅ 必须配置至少一种通知方式
- ❌ 不能同时配置多种通知方式
- ✅ SMTP 配置需验证地址、发送者、TLS 等参数

### 2.3 初始化注册

通知 provider 在 `internal/middlewares/util.go:59-64` 中初始化：

```go
switch {
case config.Notifier.SMTP != nil:
    providers.Notifier = notification.NewSMTPNotifier(config.Notifier.SMTP, caCertPool)
case config.Notifier.FileSystem != nil:
    providers.Notifier = notification.NewFileNotifier(*config.Notifier.FileSystem)
}
```

**注册流程：**
1. 服务启动时调用 `NewProviders()` 初始化所有 provider
2. 根据配置类型创建对应的 Notifier 实例
3. 实例被保存到全局 `Providers` 结构体中供后续使用

---

## 三、通知触发链路详细分析

通知在认证流程中的多个关键点被触发，所有通知最终都通过 `ctx.Providers.Notifier.Send()` 调用。

每个场景我将按以下结构分析：
- **发起方**：谁发起的 HTTP 请求
- **路由入口**：API 端点定义
- **处理链**：经过哪些中间件和 Handler
- **通知调用点**：具体哪行代码调用 `Notifier.Send()`
- **失败策略**：发送失败后是阻断流程还是继续

---

### 3.1 场景一：密码重置 - 发送重置链接

#### 完整调用链路

```
用户点击"忘记密码"
    ↓
前端 POST /api/reset-password/identity/start
    ↓
路由匹配: handlers.go:267
    ↓
中间件链: RateLimit → ResetPasswordIdentityStart
    ↓
Handler 调用: middlewares.IdentityVerificationStart()
    ↓
生成 JWT 令牌并保存到 Storage
    ↓
✅ 调用 Notifier.Send() 发送验证邮件
    ↓
返回 200 OK（无论用户是否存在，防止枚举攻击）
```

#### 逐段详细说明

**1. 发起方：** 用户在登录页面点击"忘记密码"，输入用户名后前端发起请求

**2. 路由入口**（`internal/server/handlers.go:267`）：
```go
r.POST("/api/reset-password/identity/start", 
    middlewareAPI(
        middlewares.NewRateLimitHandler(
            config.Server.Endpoints.RateLimits.ResetPasswordStart, 
            handlers.ResetPasswordIdentityStart
        )
    )
)
```

**3. Handler 定义**（`internal/handlers/handler_reset_password.go:257-265`）：
```go
var ResetPasswordIdentityStart = middlewares.IdentityVerificationStart(
    middlewares.IdentityVerificationStartArgs{
        MailTitle:               "Reset your password",
        MailButtonContent:       "Reset",
        TargetEndpoint:          "/reset-password/step2",
        ActionClaim:             ActionResetPassword,
        IdentityRetrieverFunc:   identityRetrieverFromStorage,  // 从存储获取用户邮箱
    }, 
    middlewares.TimingAttackDelay(10, 250, 85, time.Millisecond*500, false)
)
```

**4. 通知调用点**（`internal/middlewares/identity_verification.go:129`）：
```go
// 这是通用的身份验证启动中间件
if err = ctx.Providers.Notifier.Send(
    ctx, 
    identity.Address(),           // 接收者邮箱
    args.MailTitle,               // 邮件标题："Reset your password"
    ctx.Providers.Templates.GetIdentityVerificationJWTEmailTemplate(), 
    data,                         // 包含重置链接、用户名等
); err != nil {
    ctx.Error(err, messageOperationFailed)  // 返回 500 错误
    return  // ❌ 阻断流程
}
```

**5. 失败策略：❌ 阻断流程**
- 通知发送失败时，向用户返回操作失败错误
- 原因：用户必须收到邮件才能继续重置流程

---

### 3.2 场景二：密码重置 - 重置成功通知

#### 完整调用链路

```
用户点击邮件中的重置链接 → 进入重置页面
    ↓
用户输入新密码 → 前端 POST /api/reset-password
    ↓
路由匹配: handlers.go:270
    ↓
Handler: handlers.ResetPasswordPOST
    ↓
验证 JWT Token 有效性
    ↓
更新用户密码（调用 UserProvider.UpdatePassword）
    ↓
✅ 调用 Notifier.Send() 发送"密码已重置"通知
    ↓
返回 200 OK
```

#### 逐段详细说明

**1. 发起方：** 用户在重置密码页面输入新密码后提交

**2. 路由入口**（`internal/server/handlers.go:270`）：
```go
r.POST("/api/reset-password", middlewareAPI(handlers.ResetPasswordPOST))
```

**3. 通知调用点**（`internal/handlers/handler_reset_password.go:223`）：
```go
// 密码已经成功更新，现在发送通知
data := templates.EmailEventValues{
    Title:       "Password changed successfully",
    DisplayName: userInfo.DisplayName,
    RemoteIP:    ctx.RemoteIP().String(),
    Details: map[string]any{"Action": "Password Reset"},
    BodyPrefix: eventEmailActionPasswordModifyPrefix,
    BodyEvent:  eventEmailActionPasswordReset,
    BodySuffix: eventEmailActionPasswordModifySuffix,
}

if err = ctx.Providers.Notifier.Send(
    ctx, 
    addresses[0], 
    "Password changed successfully", 
    ctx.Providers.Templates.GetEventEmailTemplate(), 
    data,
); err != nil {
    ctx.GetLogger().Error(err)  // ✅ 仅记录错误日志
    ctx.ReplyOK()               // 仍返回 200 OK
    return  // 不阻断，操作已完成
}
```

**4. 失败策略：✅ 容错继续**
- 通知发送失败时，仅记录错误日志
- 仍向用户返回操作成功
- 原因：密码已经成功更新，通知只是事后告知，不应该因为通知失败而让用户困惑

---

### 3.3 场景三：会话提升 - 发送一次性验证码

#### 完整调用链路

```
用户访问需要高权限的资源（如修改 2FA 设置）
    ↓
系统检测到需要提升会话 → 前端请求验证码
    ↓
前端 POST /api/user/session/elevation
    ↓
路由匹配: handlers.go:295
    ↓
中间件链: SecurityHeaders → RateLimit → Require1FA
    ↓
Handler: handlers.UserSessionElevationPOST
    ↓
生成 OneTimeCode 并保存到 Storage
    ↓
✅ 调用 Notifier.Send() 发送验证码邮件
    ↓
返回 200 OK（带撤销 ID）
```

#### 逐段详细说明

**1. 发起方：** 用户访问敏感操作时，系统自动触发会话提升流程

**2. 路由入口**（`internal/server/handlers.go:295`）：
```go
middlewareElevatePOST := middlewares.NewBridgeBuilder(*config, providers).
    WithPreMiddlewares(middlewares.SecurityHeadersBase, ...).
    WithPostMiddlewares(
        middlewares.NewRateLimit(config.Server.Endpoints.RateLimits.SessionElevationStart), 
        middlewares.Require1FA,  // 需要先登录
    ).Build()

r.POST("/api/user/session/elevation", middlewareElevatePOST(handlers.UserSessionElevationPOST))
```

**3. 通知调用点**（`internal/handlers/handler_session_elevation.go:204`）：
```go
data := templates.EmailIdentityVerificationOTCValues{
    Title:              "Confirm your identity",
    RevocationLinkURL:  linkURL.String(),
    DisplayName:        identity.DisplayName,
    RemoteIP:           ctx.RemoteIP().String(),
    Domain:             domain,
    OneTimeCode:        string(otp.Code),  // 6-8 位数字验证码
}

if err = ctx.Providers.Notifier.Send(
    ctx, 
    identity.Address(), 
    data.Title, 
    ctx.Providers.Templates.GetIdentityVerificationOTCEmailTemplate(), 
    data,
); err != nil {
    ctx.Logger.WithError(err).Error("error occurred sending the user the notification")
    ctx.SetStatusCode(fasthttp.StatusForbidden)
    ctx.SetJSONError(messageOperationFailed)
    return  // ❌ 阻断流程
}
```

**4. 失败策略：❌ 阻断流程**
- 通知发送失败时，返回 403 Forbidden
- 原因：用户必须收到验证码才能完成提升，没有验证码无法继续

---

### 3.4 场景四：修改密码成功通知

#### 完整调用链路

```
用户在设置页面修改密码
    ↓
前端 POST /api/change-password
    ↓
路由匹配: handlers.go:275
    ↓
中间件链: SecurityHeaders → RequireElevated
    ↓
Handler: handlers.ChangePasswordPOST
    ↓
验证旧密码 → 更新新密码
    ↓
✅ 调用 Notifier.Send() 发送"密码已修改"通知
    ↓
返回 200 OK
```

#### 逐段详细说明

**1. 发起方：** 用户在账户设置页面主动修改密码

**2. 路由入口**（`internal/server/handlers.go:275`）：
```go
if !config.AuthenticationBackend.PasswordChange.Disable {
    r.POST("/api/change-password", middlewareElevated1FA(handlers.ChangePasswordPOST))
}
```
注意：需要 `RequireElevated` 中间件，即用户必须已经通过会话提升

**3. 通知调用点**（`internal/handlers/handler_change_password.go:141`）：
```go
data := templates.EmailEventValues{
    Title:       "Password changed successfully",
    DisplayName: userInfo.DisplayName,
    RemoteIP:    ctx.RemoteIP().String(),
    Details: map[string]any{"Action": "Password Change"},
    BodyPrefix: eventEmailActionPasswordModifyPrefix,
    BodyEvent:  eventEmailActionPasswordChange,
    BodySuffix: eventEmailActionPasswordModifySuffix,
}

if err = ctx.Providers.Notifier.Send(
    ctx, addresses[0], 
    "Password changed successfully", 
    ctx.Providers.Templates.GetEventEmailTemplate(), 
    data,
); err != nil {
    ctx.GetLogger().WithError(err).Debug("Unable to notify user of password change")
    ctx.ReplyOK()  // ✅ 仍返回成功
    return
}
```

**4. 失败策略：✅ 容错继续**
- 通知发送失败时，仅记录 Debug 日志
- 仍向用户返回操作成功
- 原因：密码已经成功修改，通知是安全提醒，不是流程必需

---

### 3.5 场景五：2FA 设备变更通知（通用安全事件）

#### 完整调用链路

```
用户添加/删除 WebAuthn 设备或 TOTP
    ↓
调用对应 Handler（如 WebAuthnRegistrationPOST）
    ↓
设备信息保存到 Storage
    ↓
调用 ctxLogEvent() 辅助函数
    ↓
✅ 内部调用 Notifier.Send() 发送事件通知
    ↓
返回 200 OK
```

#### 逐段详细说明

**1. 发起方：** 用户在 2FA 设置页面添加或删除认证设备

**2. 路由示例**（`internal/server/handlers.go:332`）：
```go
r.POST("/api/secondfactor/webauthn/credential/register", 
    middlewareElevated1FA(handlers.WebAuthnRegistrationPOST))
```

**3. 通用通知函数**（`internal/handlers/util.go:41-80`）：
```go
func ctxLogEvent(ctx *middlewares.AutheliaCtx, username, description string, 
    body emailEventBody, eventDetails map[string]any) {
    
    // 获取用户邮箱...
    if details, err = ctx.Providers.UserProvider.GetDetails(username); err != nil {
        ctx.Logger.WithError(err).Error(...)
        return  // 获取用户信息失败，直接返回但不阻断主流程
    }
    
    data := templates.EmailEventValues{
        Title:       description,  // 如 "Second Factor Method Added"
        DisplayName: details.DisplayName,
        RemoteIP:    ctx.RemoteIP().String(),
        Details:     eventDetails,
        BodyPrefix:  body.Prefix,
        BodyEvent:   body.Body,
        BodySuffix:  body.Suffix,
    }
    
    if err = ctx.Providers.Notifier.Send(
        ctx, addresses[0], description, 
        ctx.Providers.Templates.GetEventEmailTemplate(), data,
    ); err != nil {
        ctx.Logger.WithError(err).Errorf("Error occurred sending notification")
        return  // ✅ 记录错误，不影响主流程
    }
}
```

**4. 调用示例**（`internal/handlers/handler_register_webauthn.go:251`）：
```go
// WebAuthn 设备注册成功后
ctxLogEvent(ctx, userSession.Username, eventLogAction2FAAdded, body, 
    map[string]any{
        eventLogKeyAction: eventLogAction2FAAdded,
        eventLogKeyCategory: eventLogCategoryWebAuthnCredential,
        eventLogKeyDescription: credential.Description,
    })
```

**5. 失败策略：✅ 容错继续**
- 通知发送失败时，仅记录错误日志
- 设备添加/删除操作仍然成功
- 原因：安全事件通知是额外的安全提醒，不应该影响用户的正常操作

---

### 3.6 通知触发场景汇总表

| 场景 | 发起方 | API 端点 | 通知时机 | 失败策略 |
|-----|-------|---------|---------|---------|
| 发送密码重置链接 | 用户点击"忘记密码" | `POST /api/reset-password/identity/start` | 生成 JWT 后 | ❌ 阻断 |
| 密码重置成功通知 | 用户提交新密码 | `POST /api/reset-password` | 密码更新后 | ✅ 继续 |
| 会话提升验证码 | 访问敏感资源 | `POST /api/user/session/elevation` | 生成 OTC 后 | ❌ 阻断 |
| 密码修改成功通知 | 用户修改密码 | `POST /api/change-password` | 密码更新后 | ✅ 继续 |
| 2FA 设备添加通知 | 用户添加 2FA | 各 2FA 注册端点 | 设备保存后 | ✅ 继续 |
| 2FA 设备删除通知 | 用户删除 2FA | 各 2FA 删除端点 | 设备删除后 | ✅ 继续 |

---

### 3.7 设计模式分析

#### 两种失败策略的设计考量

**❌ 阻断流程的场景（通知是流程的一部分）：**
- 密码重置链接：没有邮件用户无法继续重置
- 会话提升验证码：没有验证码用户无法提升权限
- **共同点**：通知承载了后续流程必需的信息（链接/验证码）

**✅ 容错继续的场景（通知是事后告知）：**
- 密码修改/重置成功通知
- 2FA 设备变更通知
- **共同点**：主操作已完成，通知只是安全审计提醒

#### 时序差异

```
阻断型时序（通知在流程中间）：
请求 → 验证 → 生成令牌 → ✉️ 发送通知 → 存储 → 返回响应
                                  ↓失败
                                返回错误

容错型时序（通知在流程末尾）：
请求 → 验证 → 执行操作 → 存储 → ✉️ 发送通知 → 返回响应
                                            ↓失败
                                          记录日志，仍返回成功
```

---

## 四、发送失败时的回退处理

### 4.1 回退机制分析

**重要结论：Authelia 当前没有实现多通道之间的自动回退机制。**

从代码中可以观察到以下失败处理策略：

#### 4.1.1 启动检查失败
**位置：** `internal/middlewares/startup.go:36-37`

```go
provider, disable = ctx.GetProviders().Notifier, ctx.GetConfiguration().Notifier.DisableStartupCheck
doStartupCheck(ctx, ProviderNameNotification, provider, nil, disable, log, e.errors)
```

**处理方式：**
- 启动时会验证通知通道是否可用（如 SMTP 连接测试）
- 可通过 `disable_startup_check: true` 跳过检查
- 检查失败会阻止服务启动（除非明确禁用）

#### 4.1.2 运行时发送失败

不同场景的失败处理策略不同：

| 场景 | 失败处理 | 代码位置 |
|-----|---------|---------|
| **身份验证启动** | ❌ 操作失败，返回错误给用户 | `identity_verification.go:130-131` |
| **会话提升** | ❌ 操作失败，返回错误给用户 | `handler_session_elevation.go:205-210` |
| **密码重置成功** | ✅ 记录错误日志，操作仍成功 | `handler_reset_password.go:224-227` |
| **密码修改成功** | ✅ 记录错误日志，操作仍成功 | `handler_change_password.go:141-148` |
| **安全事件通知** | ✅ 记录错误日志，操作仍成功 | `util.go:77-78` |

**代码示例 - 关键操作失败阻断：**
```go
// identity_verification.go:129-132
if err = ctx.Providers.Notifier.Send(...); err != nil {
    ctx.Error(err, messageOperationFailed)  // 返回错误给用户
    return  // 阻断流程
}
```

**代码示例 - 非关键操作失败继续：**
```go
// handler_reset_password.go:223-228
if err = ctx.Providers.Notifier.Send(...); err != nil {
    ctx.GetLogger().Error(err)  // 仅记录日志
    ctx.ReplyOK()  // 仍返回成功
    return
}
```

### 4.2 设计意图分析

这种差异化处理策略的设计意图：

1. **关键流程阻断**：身份验证和会话提升需要用户收到通知才能继续，因此发送失败必须阻断流程
2. **事后通知容错**：密码修改/重置成功后的通知属于事后告知，不应该因为通知失败而回滚已完成的安全操作
3. **无自动回退**：当前设计不支持 SMTP 失败时自动回退到文件通知，需运维人员介入

---

## 五、SMTP 通知器内部实现

### 5.1 SMTP 发送流程

**位置：** `internal/notification/smtp_notifier.go:139-166`

```go
func (n *SMTPNotifier) Send(ctx context.Context, recipient mail.Address, ...) (err error) {
    // 1. 创建邮件消息
    if msg, err = n.msg(recipient, subject, et, data); err != nil {
        return fmt.Errorf("notifier: smtp: failed to create envelope: %w", err)
    }
    // 2. 创建 SMTP 客户端
    if client, err = n.factory.GetClient(); err != nil {
        return fmt.Errorf("notifier: smtp: failed to establish client: %w", err)
    }
    // 3. 建立连接
    if err = client.DialWithContext(ctx); err != nil {
        return fmt.Errorf("notifier: smtp: failed to dial connection: %w", err)
    }
    // 4. 发送邮件
    if err = client.Send(msg); err != nil {
        return fmt.Errorf("notifier: smtp: failed to send message: %w", err)
    }
    // 5. 关闭连接
    if err = client.Close(); err != nil {
        return fmt.Errorf("notifier: smtp: failed to close connection: %w", err)
    }
    return nil
}
```

### 5.2 TLS 策略配置

SMTP 支持四种 TLS 策略（`smtp_notifier.go:34-61`）：

| 策略 | 触发条件 | 说明 |
|-----|---------|------|
| **Explicit TLS** | `Address.IsExplicitlySecure()` | 强制使用 SMTPS |
| **No TLS** | `DisableStartTLS = true` | 不使用 TLS（不推荐） |
| **Opportunistic TLS** | `DisableRequireTLS = true` | 尝试 TLS，失败则降级 |
| **Mandatory TLS** | 默认 | 必须使用 TLS |

---

## 六、文件通知器实现

**位置：** `internal/notification/file_notifier.go:49-91`

```go
func (n *FileNotifier) Send(_ context.Context, recipient mail.Address, ...) (err error) {
    // 打开文件（默认覆盖模式）
    flag = os.O_TRUNC | os.O_CREATE | os.O_WRONLY
    f, err = os.OpenFile(n.path, flag, fileNotifierMode)
    
    // 写入邮件头
    fmt.Fprintf(w, fileNotifierHeader, time.Now(), recipient, subject)
    
    // 执行模板
    et.Text.Execute(w, data)
    
    // 刷新到磁盘
    w.Flush()
    f.Sync()
    return nil
}
```

**文件模式：** 默认使用 `0600` 权限，目录使用 `0700` 权限。

---

## 七、总结

### 7.1 核心流程

```
配置加载 → 配置验证 → 通知器初始化 → 启动检查 → 运行时触发发送
     ↓          ↓            ↓            ↓            ↓
  读取配置   确保合法   创建SMTP/File   验证连通性    按场景失败处理
```

### 7.2 关键设计决策

1. **单通知通道设计**：同一时间只能使用一种通知通道，简化配置和维护
2. **差异化失败处理**：关键操作阻断，非关键操作容错
3. **无自动回退**：通知失败需要人工介入，不自动降级
4. **启动检查**：提前发现配置问题，避免运行时故障

### 7.3 扩展点

如果需要增加新的通知通道（如 Webhook、钉钉、企业微信等），只需：

1. 实现 `Notifier` 接口
2. 在配置 schema 中添加新的配置项
3. 在配置验证器中添加验证逻辑
4. 在 `NewProviders()` 中添加初始化分支
