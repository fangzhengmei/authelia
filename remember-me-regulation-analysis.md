# Remember-Me Cookie 与登录限流耦合分析

## 概述

本文档分析 Authelia 中长期登录票据（Remember-Me Cookie）与登录失败限流机制之间的耦合关系，重点关注三个方面：
1. Remember-Me Cookie 的发放与续期逻辑
2. 登录失败计入与限流逻辑
3. 被限流账号能否凭旧票据登录的判定逻辑

---

## 一、Remember-Me Cookie 的发放与续期逻辑

### 1.1 发放时机

Remember-Me Cookie 的发放发生在**第一因素认证成功后**，支持两种首因子路径：

#### 1.1.1 密码登录路径

**代码位置**：`internal/handlers/handler_firstfactor_password.go:123-140`

```go
// 检查用户是否勾选了 "Keep me logged in"
keepMeLoggedIn := !provider.Config.DisableRememberMe && bodyJSON.KeepMeLoggedIn != nil && *bodyJSON.KeepMeLoggedIn

// 如果勾选，更新 cookie 过期时间为 RememberMe 配置（默认30天）
if keepMeLoggedIn {
    err = provider.UpdateExpiration(ctx.RequestCtx, provider.Config.RememberMe)
    // ...
}

// 在 session 中标记 KeepMeLoggedIn 状态
userSession.SetOneFactorPassword(ctx.GetClock().Now(), details, keepMeLoggedIn)
```

#### 1.1.2 通行密钥（Passkey）登录路径

**代码位置**：`internal/handlers/handler_firstfactor_passkey.go:314-341`

```go
// 关键：Passkey 登录也有完整的 remember-me 发放逻辑
keepMeLoggedIn := !provider.Config.DisableRememberMe && bodyJSON.KeepMeLoggedIn != nil && *bodyJSON.KeepMeLoggedIn

if keepMeLoggedIn {
    if err = provider.UpdateExpiration(ctx.RequestCtx, provider.Config.RememberMe); err != nil {
        // ...
    }
}

userSession.SetOneFactorPasskey(
    ctx.GetClock().Now(), details,
    keepMeLoggedIn,
    response.AuthenticatorAttachment == protocol.CrossPlatform,
    response.Response.AuthenticatorData.Flags.HasUserPresent(),
    response.Response.AuthenticatorData.Flags.HasUserVerified(),
)
```

**发放条件**（两条路径相同）：
- 配置 `session.remember_me` 未被禁用（`DisableRememberMe` 为 false）
- 用户在登录表单中勾选了 "Keep me logged in"
- 认证成功

**默认配置**（`internal/configuration/schema/session.go:83`）：
- `RememberMe`: 30 天
- `Expiration`: 1 小时（未勾选时）
- `Inactivity`: 5 分钟（不活动超时）

### 1.2 续期逻辑

Remember-Me Cookie 的"续期"机制比较特殊，它不是自动延长过期时间，而是**跳过不活动超时检查**：

**代码位置**：`internal/handlers/handler_authz_authn.go:487-490`

```go
func handleAuthnCookieValidateInactivity(...) (invalid bool) {
    // 如果是记住登录状态，直接返回 false（不检查不活动超时）
    if isAnonymous || userSession.KeepMeLoggedIn || int64(provider.Config.Inactivity.Seconds()) == 0 {
        return false
    }
    // 否则检查最后活动时间是否超过 Inactivity 配置
    return time.Unix(userSession.LastActivity, 0).Add(provider.Config.Inactivity).Before(ctx.GetClock().Now())
}
```

**关键行为**：
- `KeepMeLoggedIn = true` 的 session **不会因不活动而过期**
- 但 cookie 本身的过期时间（30天）仍然有效，过期后需要重新登录
- 没有自动续期 cookie 过期时间的逻辑，过期后必须重新认证

---

## 二、登录失败计入与限流逻辑

### 2.1 登录失败计入

登录失败的记录通过 `doMarkAuthenticationAttempt` 函数统一处理：

**代码位置**：`internal/handlers/response.go:461-497`

```go
func doMarkAuthenticationAttempt(ctx *middlewares.AutheliaCtx, successful bool, ban *regulation.Ban, authType string, errAuth error) {
    // ...
    doMarkAuthenticationAttemptWithRequest(ctx, successful, ban, authType, requestURI, requestMethod, errAuth)
}

func doMarkAuthenticationAttemptWithRequest(...) {
    // 调用 Regulator 记录认证尝试
    ctx.Providers.Regulator.HandleAttempt(ctx, successful, ban.IsBanned(), ban.Value(), requestURI, requestMethod, authType)
    // ...
}
```

**记录的 authType 可能的值**：
- `AuthType1FA`：密码登录
- `AuthTypePasskey`：通行密钥登录
- `AuthTypeTOTP`：TOTP 二因素
- `AuthTypeWebAuthn`：WebAuthn 二因素
- `AuthTypeDuo`：Duo 二因素
- `AuthTypePassword`：密码二因素

### 2.2 限流触发条件（核心逻辑）

**代码位置**：`internal/regulation/regulator.go:26-55`

```go
func (r *Regulator) HandleAttempt(ctx Context, successful, banned bool, username, requestURI, requestMethod, authType string) {
    // 记录认证尝试日志（所有 authType 都会记录）
    attempt := model.AuthenticationAttempt{...}
    r.store.AppendAuthenticationLog(ctx, attempt)

    // 关键：只有满足以下 ALL 条件才会检查是否需要限流
    if successful || banned || (!r.ips && !r.users) || authType != AuthType1FA {
        return
    }

    // 检查 IP 和用户是否需要限流
    r.handleAttemptPossibleBannedIP(ctx, since)
    r.handleAttemptPossibleBannedUser(ctx, since, username)
}
```

**限流触发的必要条件（必须同时满足）**：

| 条件 | 说明 |
|------|------|
| `successful == false` | 认证必须失败 |
| `banned == false` | 尚未被限流（已限流的不会重复触发） |
| `authType == AuthType1FA` | **必须是密码登录（仅密码！）** |

**重要结论**：只有**密码登录（AuthType1FA）**的失败才会触发限流。其他认证方式的失败虽然会被记录到日志中，但**不会触发限流**：

| 认证方式 | authType | 失败是否触发限流 |
|---------|----------|----------------|
| 密码登录 | `AuthType1FA` | ✅ 是 |
| Passkey 登录 | `AuthTypePasskey` | ❌ 否 |
| TOTP 二因素 | `AuthTypeTOTP` | ❌ 否 |
| WebAuthn 二因素 | `AuthTypeWebAuthn` | ❌ 否 |
| Duo 二因素 | `AuthTypeDuo` | ❌ 否 |
| 密码二因素 | `AuthTypePassword` | ❌ 否 |

### 2.3 限流算法与失败计数重置

**代码位置**：`internal/regulation/regulator.go:165-193`

```go
func (r *Regulator) expires(since time.Time, records []model.RegulationRecord) *time.Time {
    failures := make([]model.RegulationRecord, 0, len(records))

loop:
    for _, record := range records {
        switch {
        case record.Successful:
            break loop  // 遇到成功记录，停止统计（成功会重置失败计数）
        case len(failures) >= r.config.MaxRetries:
            continue
        case record.Time.Before(since):
            continue
        default:
            failures = append(failures, record)
        }
    }

    if len(failures) < r.config.MaxRetries {
        return nil  // 未达到最大重试次数，不限流
    }

    expires := failures[0].Time.Add(r.config.BanTime)
    return &expires
}
```

**限流逻辑**：
1. 在 `FindTime` 窗口内（默认2分钟）统计失败次数
2. 遇到**任何成功认证**（包括 passkey 成功登录）都会重置失败计数（break loop）
3. 失败次数达到 `MaxRetries`（默认3次）则触发限流
4. 限流时长为 `BanTime`（默认5分钟）

**关键点澄清**：
- "通行密钥成功会重置密码失败计数" —— **这句话只在用户未被限流时成立**
- 重置逻辑是在**统计失败次数时**触发的：查询历史记录时遇到任何成功记录就停止统计
- 这是一种防御机制：用户用 passkey 成功登录后，之前的密码失败记录不会累积到限流阈值

### 2.4 限流预检（BanCheck）的执行顺序

两种首因子路径在认证流程中都会执行 BanCheck，但**执行时机不同**：

#### 2.4.1 密码登录：BanCheck 在密码验证之前

**代码位置**：`internal/handlers/handler_firstfactor_password.go:50-64`

```go
// 先检查限流状态
if ban, _, expires, err := ctx.Providers.Regulator.BanCheck(ctx, details.Username); err != nil {
    if errors.Is(err, regulation.ErrUserIsBanned) {
        // 被限流，直接拒绝，不会验证密码
        doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(ban, details.Username, expires), regulation.AuthType1FA, nil)
        respondUnauthorized(ctx, messageAuthenticationFailed)
        return
    }
}

// 只有未被限流，才会验证密码
userPasswordOk, err := ctx.Providers.UserProvider.CheckUserPassword(details.Username, bodyJSON.Password)
```

#### 2.4.2 Passkey 登录：BanCheck 在 Passkey 验证成功之后

**代码位置**：`internal/handlers/handler_firstfactor_passkey.go:284-295`

```go
// 先验证 Passkey
if u, c, err = w.ValidatePasskeyLogin(...); err != nil {
    // Passkey 验证失败，直接拒绝
    doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(regulation.BanTypeNone, "", nil), regulation.AuthTypePasskey, nil)
    return
}

// Passkey 验证成功后，才检查限流状态
if ban, _, expires, err := ctx.Providers.Regulator.BanCheck(ctx, details.Username); err != nil {
    if errors.Is(err, regulation.ErrUserIsBanned)