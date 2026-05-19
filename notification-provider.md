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

## 三、触发时机与调用链

通知在认证流程中的多个关键点被触发，主要通过 `ctx.Providers.Notifier.Send()` 调用。

### 3.1 密码重置流程

#### 3.1.1 发送重置链接
**位置：** `internal/middlewares/identity_verification.go:129`

```go
// 在 IdentityVerificationStart 中间件中
if err = ctx.Providers.Notifier.Send(
    ctx, 
    identity.Address(), 
    args.MailTitle, 
    ctx.Providers.Templates.GetIdentityVerificationJWTEmailTemplate(), 
    data,
); err != nil {
    ctx.Error(err, messageOperationFailed)
    return
}
```

**触发场景：** 用户请求密码重置时，发送包含 JWT 令牌的验证链接。

#### 3.1.2 重置成功通知
**位置：** `internal/handlers/handler_reset_password.go:223`

```go
// 密码重置成功后
data := templates.EmailEventValues{
    Title:       "Password changed successfully",
    DisplayName: userInfo.DisplayName,
    RemoteIP:    ctx.RemoteIP().String(),
    Details: map[string]any{"Action": "Password Reset"},
    // ...
}
if err = ctx.Providers.Notifier.Send(
    ctx, addresses[0], 
    "Password changed successfully", 
    ctx.Providers.Templates.GetEventEmailTemplate(), 
    data,
); err != nil {
    ctx.GetLogger().Error(err)
}
```

### 3.2 会话提升流程

**位置：** `internal/handlers/handler_session_elevation.go:204`

```go
// 创建一次性验证码后发送邮件
data := templates.EmailIdentityVerificationOTCValues{
    Title:       "Confirm your identity",
    OneTimeCode: string(otp.Code),
    // ...
}
if err = ctx.Providers.Notifier.Send(
    ctx, identity.Address(), 
    data.Title, 
    ctx.Providers.Templates.GetIdentityVerificationOTCEmailTemplate(), 
    data,
); err != nil {
    ctx.Logger.WithError(err).Error("error occurred sending the user the notification")
    ctx.SetStatusCode(fasthttp.StatusForbidden)
    ctx.SetJSONError(messageOperationFailed)
    return
}
```

**触发场景：** 用户需要提升会话权限时（如访问敏感资源），发送一次性验证码。

### 3.3 密码修改通知

**位置：** `internal/handlers/handler_change_password.go:141`

```go
// 密码修改成功后发送通知
data := templates.EmailEventValues{
    Title:       "Password changed successfully",
    Details:     map[string]any{"Action": "Password Change"},
    // ...
}
if err = ctx.Providers.Notifier.Send(ctx, addresses[0], ...); err != nil {
    ctx.GetLogger().WithError(err).Debug("Unable to notify user of password change")
    // 注意：即使通知失败，操作仍然成功
    ctx.ReplyOK()
    return
}
```

### 3.4 通用安全事件通知

**位置：** `internal/handlers/util.go:41-80`

```go
func ctxLogEvent(ctx *middlewares.AutheliaCtx, username, description string, ...) {
    // 获取用户信息...
    if err = ctx.Providers.Notifier.Send(ctx, addresses[0], description, ...); err != nil {
        ctx.Logger.WithError(err).Errorf("Error occurred sending notification")
        return
    }
}
```

**使用场景：** 用于 2FA 设备添加/移除等安全事件通知。

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
