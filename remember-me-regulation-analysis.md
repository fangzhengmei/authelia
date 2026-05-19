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
    if errors.Is(err, regulation.ErrUserIsBanned) {
        // 即使 Passkey 正确，被限流也会拒绝
        doMarkAuthenticationAttempt(ctx, false, regulation.NewBan(ban, details.Username, expires), regulation.AuthTypePasskey, nil)
        return
    }
}

// 只有未被限流，才会完成登录
doMarkAuthenticationAttempt(ctx, true, regulation.NewBan(regulation.BanTypeNone, details.Username, nil), regulation.AuthTypePasskey, nil)
```

**执行顺序对比**：

| 登录方式 | 流程顺序 |
|---------|---------|
| **密码登录** | 1. 获取用户信息 → 2. BanCheck 限流检查 → 3. 验证密码 → 4. 完成登录 |
| **Passkey 登录** | 1. 验证 Passkey → 2. 获取用户信息 → 3. BanCheck 限流检查 → 4. 完成登录 |

**关键区别**：
- 密码登录：被限流时不会验证密码（节省性能）
- Passkey 登录：被限流时已经完成了 Passkey 验证（但仍被拒绝）

---

## 三、被限流账号能否凭旧票据登录

### 3.1 被限流时各登录方式的真实结果

假设场景：用户密码连续失败3次，已被限流5分钟。此时尝试各种登录方式的结果：

| 登录方式 | 流程 | 结果 | 原因 |
|---------|------|------|------|
| **密码登录** | BanCheck 发现被限流 → 直接拒绝 | ❌ 无法登录 | 限流预检在密码验证前 |
| **Passkey 登录** | Passkey 验证成功 → BanCheck 发现被限流 → 拒绝 | ❌ 无法登录 | 即使 Passkey 正确，限流预检仍会拒绝 |
| **Basic Auth** | BanCheck 发现被限流 → 直接拒绝 | ❌ 无法登录 | 限流预检在密码验证前 |
| **Remember-Me Cookie** | 无 BanCheck → 直接通过 | ✅ 正常访问 | Cookie 认证路径不检查限流 |

**重要修正（解决之前的矛盾）**：

> ❌ **错误结论**：被限流后可通过通行密钥解锁
>
> ✅ **正确结论**：被限流后**无法**通过通行密钥解锁。因为 Passkey 登录成功后仍会执行 BanCheck，被限流的用户即使 Passkey 验证成功也会被拒绝，无法产生成功登录记录，因此无法重置密码失败计数。

**"通行密钥成功会重置密码失败计数"的真实适用场景**：
- 用户**未被限流**，但有1-2次密码失败记录
- 用户改用 Passkey 成功登录
- 下次密码失败时，统计会遇到这个成功记录，重置失败计数
- 作用：防止不同登录方式的失败记录累积导致误限流

### 3.2 Cookie 认证路径（无 BanCheck）

**代码位置**：`internal/handlers/handler_authz_authn.go:91-148`

```go
func (s *CookieSessionAuthnStrategy) Get(ctx *middlewares.AutheliaCtx, provider *session.Session, _ *authorization.Object) (authn *Authn, err error) {
    var userSession session.UserSession
    
    // 1. 从 cookie 中获取 session
    if userSession, err = provider.GetSession(ctx.RequestCtx); err != nil {
        // ...
    }

    // 2. 验证 cookie 有效性
    if modified, invalid := handleAuthnCookieValidate(ctx, provider, &userSession, s.refresh); invalid {
        // ...
    }

    // 3. 返回认证信息
    return &Authn{
        Username: friendlyUsername(userSession.Username),
        Level:    userSession.AuthenticationLevel(ctx.Configuration.WebAuthn.EnablePasskey2FA),
        Type:     AuthnTypeCookie,
    }, nil
}
```

**关键发现**：`CookieSessionAuthnStrategy.Get()` 方法中 **没有调用 `Regulator.BanCheck()`**！

`handleAuthnCookieValidate` 只检查：
- Session 是否匿名且认证级别异常
- 不活动超时（对 remember-me 跳过）
- Refresh TTL（用户信息刷新）
- Session-Username header 一致性

**不检查**：用户是否被限流。

### 3.3 不同鉴权等级下的旧票据可用性

**代码位置**：`internal/session/user_session.go:24-37`

```go
func (s *UserSession) AuthenticationLevel(passkey2FA bool) authentication.Level {
    switch {
    case s.Username == "":
        return authentication.NotAuthenticated
    case s.AuthenticationMethodRefs.FactorPossession() && s.AuthenticationMethodRefs.FactorKnowledge():
        return authentication.TwoFactor
    case passkey2FA && s.AuthenticationMethodRefs.WebAuthn && s.AuthenticationMethodRefs.WebAuthnUserVerified:
        return authentication.TwoFactor
    case s.AuthenticationMethodRefs.FactorPossession() || s.AuthenticationMethodRefs.FactorKnowledge():
        return authentication.OneFactor
    default:
        return authentication.NotAuthenticated
    }
}
```

鉴权等级判定：
- **1FA 级别**：密码登录、passkey 登录（未启用 passkey2FA 时）
- **2FA 级别**：密码 + TOTP/WebAuthn/Duo、passkey 登录（启用 passkey2FA 且用户验证时）

**重要**：无论鉴权等级是 1FA 还是 2FA，cookie 认证路径都**不检查限流状态**。持有有效 remember-me cookie 的用户，即使被限流，也可以正常访问任何级别的受保护资源。

### 3.4 对比：Basic Auth 路径（有 BanCheck）

**代码位置**：`internal/handlers/handler_authz_authn.go:307-317`

```go
func (s *HeaderAuthnStrategy) handleGetBasic(ctx *middlewares.AutheliaCtx, authn *Authn, object *authorization.Object) (...) {
    username = authn.Header.Authorization.BasicUsername()

    // 关键：在验证密码之前先检查限流状态
    if ban, value, expires, err = ctx.Providers.Regulator.BanCheck(ctx, username); err != nil {
        if errors.Is(err, regulation.ErrUserIsBanned) {
            // 被限流，直接拒绝
            doMarkAuthenticationAttemptWithRequest(ctx, false, regulation.NewBan(ban, value, expires), regulation.AuthType1FA, ...)
            return "", authentication.NotAuthenticated, fmt.Errorf(...)
        }
        // ...
    }

    // 验证密码...
}
```

---

## 四、三者耦合关系总览

### 4.1 耦合关系图

```
┌─────────────────────┐     成功登录发放     ┌─────────────────────┐
│  密码登录 (1FA)     │──────────────────────▶│ Remember-Me Cookie  │
└─────────┬───────────┘                       └──────────┬──────────┘
          │                                               │
          │ 失败计入（仅密码）                                 │
          ▼                                               │
┌─────────────────────┐                                   │
│  登录失败限流机制    │◀──────────────────────────────────┘
└─────────────────────┘
          ▲
          │ 不检查限流
          │
┌─────────────────────┐
│  Cookie 认证访问    │（1FA/2FA 都不检查限流）
└─────────────────────┘

┌─────────────────────┐
│  Passkey 登录       │──────┐
└─────────────────────┘      │
          │                   │
          │ 成功重置失败计数   │  成功登录发放
          ▼                   ▼
┌─────────────────────┐     ┌─────────────────────┐
│  登录失败限流机制    │     │ Remember-Me Cookie  │
└─────────────────────┘     └─────────────────────┘

注意：被限流时，Passkey 登录的 BanCheck 会在成功验证后拒绝，无法产生成功记录
```

### 4.2 关键交互点（修正版）

| 交互场景 | 行为 | 代码位置 |
|---------|------|----------|
| 密码登录成功 + 勾选 remember-me | 设置 cookie 过期时间为 30 天，标记 `KeepMeLoggedIn=true` | `handler_firstfactor_password.go:123-140` |
| Passkey 登录成功 + 勾选 remember-me | 设置 cookie 过期时间为 30 天，标记 `KeepMeLoggedIn=true` | `handler_firstfactor_passkey.go:314-341` |
| 密码登录失败 | 计入失败次数，可能触发限流 | `handler_firstfactor_password.go:80` → `regulator.go:26` |
| Passkey 登录失败 | 记录失败日志，但不触发限流 | `handler_firstfactor_passkey.go:196` → `regulator.go:26` |
| 密码登录成功 | 重置失败计数（后续统计时会 break loop） | `regulator.go:171` |
| Passkey 登录成功（未被限流时） | 重置失败计数（后续统计时会 break loop） | `regulator.go:171` |
| Passkey 登录（已被限流时） | Passkey 验证成功，但 BanCheck 拒绝，无法重置计数 | `handler_firstfactor_passkey.go:284-295` |
| 使用 remember-me cookie 访问（1FA/2FA） | 不检查限流状态，直接通过 | `handler_authz_authn.go:91-148` |
| 使用 Basic Auth 访问 | 先检查限流状态，被限流则拒绝 | `handler_authz_authn.go:307-317` |
| Remember-me cookie 续期 | 不自动续期，但跳过不活动超时 | `handler_authz_authn.go:487-490` |

### 4.3 被限流时的行为矩阵

| 登录方式 | 能否登录 | 是否记录尝试 | 是否影响限流 |
|---------|---------|-------------|-------------|
| 密码登录 | ❌ 否 | ✅ 是（AuthType1FA，banned=true） | ❌ 否（已 banned，跳过限流检查） |
| Passkey 登录 | ❌ 否 | ✅ 是（AuthTypePasskey） | ❌ 否（authType != AuthType1FA） |
| Basic Auth | ❌ 否 | ✅ 是（AuthType1FA，banned=true） | ❌ 否（已 banned，跳过限流检查） |
| Remember-Me Cookie | ✅ 是 | ❌ 否（无记录） | ❌ 否（无 BanCheck） |

### 4.4 安全考量

**潜在风险**：
1. **限流绕过**：攻击者如果获取了有效的 remember-me cookie，即使触发了 IP 或用户限流，仍然可以继续访问
2. **Cookie 窃取**：remember-me cookie 有效期长达 30 天，一旦被窃取，攻击者有很长的窗口期可以访问

**设计意图**：
- Remember-me cookie 本身就是"已认证"状态的证明
- 限流主要针对**认证过程**，防止暴力破解密码
- 对于已经通过认证的用户（持有有效 cookie），限流机制不应该影响其正常使用

**建议的安全增强**（如果需要）：
- 在 `handleAuthnCookieValidate` 中增加 `BanCheck` 调用（会影响用户体验，合法用户被限流后也无法访问）
- 缩短 remember-me cookie 的有效期
- 增加 cookie 绑定机制（如绑定用户代理、IP 等）

---

## 五、相关配置参数

### 5.1 Session 配置

```yaml
session:
  name: authelia_session
  expiration: 1h        # 未勾选 remember-me 时的 cookie 有效期
  inactivity: 5m        # 不活动超时（remember-me 用户跳过）
  remember_me: 30d      # 勾选 remember-me 后的 cookie 有效期
  disable_remember_me: false  # 是否禁用 remember-me 功能
```

### 5.2 Regulation 配置

```yaml
regulation:
  modes:
    - user              # 按用户限流（还可以是 ip）
  max_retries: 3        # 最大失败次数
  find_time: 2m         # 统计失败次数的时间窗口
  ban_time: 5m          # 限流时长
```

### 5.3 Passkey 配置

```yaml
webauthn:
  enable_passkey2fa: false  # 是否将 passkey 视为 2FA 级别
```

---

## 六、总结（修正版）

1. **Remember-Me Cookie 发放**：密码登录和 Passkey 登录成功且用户勾选时发放，有效期 30 天

2. **登录失败限流**：
   - 仅针对**密码登录（AuthType1FA）**失败，3 次失败在 2 分钟内会被限流 5 分钟
   - Passkey 失败、二因素失败只会记录日志，**不会触发限流**
   - **BanCheck 执行顺序**：密码登录在验证前检查，Passkey 登录在验证成功后检查

3. **被限流账号的 Cookie 访问**：
   - **可以正常访问**，因为 Cookie 认证路径（无论 1FA/2FA）都不检查限流状态

4. **关于"通行密钥解锁"的澄清**：
   - ❌ **被限流后无法通过通行密钥解锁**——BanCheck 会在 Passkey 验证成功后拒绝登录
   - ✅ **未被限流时**，Passkey 成功登录会重置密码失败计数（防止不同方式的失败累积）

这种设计的核心思想是：**限流保护的是认证过程，而不是已认证的会话**。记住登录状态的用户被认为已经通过了身份验证，因此不受登录限流的影响。
