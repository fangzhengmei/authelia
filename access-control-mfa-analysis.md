# 访问控制规则、多因素认证与 OIDC 会话协作逻辑分析报告

## 1. 核心概念概述

### 1.1 访问控制规则 (Access Control Rules)
访问控制规则是 Authelia 中用于保护资源的核心机制，通过定义一系列规则来决定谁可以访问什么资源。

### 1.2 多因素认证 (Multi-Factor Authentication, MFA)
多因素认证要求用户提供两种或两种以上的认证因素，以提高账户安全性。Authelia 支持：
- 单因素认证 (OneFactor): 仅用户名密码
- 双因素认证 (TwoFactor): 密码 + TOTP/WebAuthn/Duo 等

### 1.3 OIDC 会话 (OpenID Connect Session)
OIDC 会话管理 OAuth 2.0 和 OpenID Connect 协议中的用户认证状态和令牌生命周期。

---

## 2. 核心数据结构

### 2.1 授权级别定义

**位置**: `internal/authorization/const.go`

```go
type Level int

const (
    Bypass      Level = iota  // 绕过认证
    OneFactor                 // 单因素认证
    TwoFactor                 // 双因素认证
    Denied                    // 拒绝访问
)
```

### 2.2 认证级别定义

**位置**: `internal/authentication/types.go`

```go
type Level int

const (
    NotAuthenticated Level = iota  // 未认证
    OneFactor                        // 单因素认证
    TwoFactor                        // 双因素认证
)
```

### 2.3 访问控制规则结构

**位置**: `internal/authorization/access_control_rule.go`

```go
type AccessControlRule struct {
    HasSubjects bool
    Position    int
    Domains     []AccessControlDomain
    Resources   []AccessControlResource
    Query       []AccessControlQuery
    Methods     []string
    Networks    AccessControlNetworks
    Subjects    []AccessControlSubjects
    Policy      Level  // 该规则要求的授权级别
}
```

### 2.4 OIDC 会话结构

**位置**: `internal/oidc/session.go`

```go
type Session struct {
    *openid.DefaultSession
    AccessToken  *AccessTokenSession
    ChallengeID  uuid.NullUUID
    ClientID     string       // 客户端 ID
    ClientCredentials bool    // 是否为客户端凭证模式
    // ... 其他字段
}
```

---

## 3. 协作逻辑详解

### 3.1 授权决策流程

**核心入口**: `internal/handlers/handler_authz.go:Handler`

```
请求到达
   ↓
1. 获取目标资源对象 (Object)
   - 解析目标 URL
   - 提取请求方法
   ↓
2. 获取会话提供者
   - 根据目标域名确定会话 Cookie 域
   ↓
3. 认证信息获取 (authn 函数)
   ├─ 按顺序尝试各种认证策略
   │  ├─ Cookie 会话认证策略
   │  ├─ Header Authorization 认证策略
   │  └─ 其他认证策略
   └─ 返回用户认证级别 (OneFactor/TwoFactor)
   ↓
4. 获取访问控制要求级别
   - 调用 Authorizer.GetRequiredLevel()
   - 传入 Subject（用户名、组、IP、ClientID）
   - 传入 Object（目标资源）
   ↓
5. 权限决策比较
   - isAuthzResult(authn.Level, required, ruleHasSubject)
   ├─ AuthzResultForbidden: 返回 403
   ├─ AuthzResultUnauthorized: 返回 401 并重定向
   └─ AuthzResultAuthorized: 返回 200 并设置头信息
```

### 3.2 访问控制规则匹配机制

**位置**: `internal/authorization/access_control_rule.go:IsMatch`

```go
func (acr *AccessControlRule) IsMatch(subject Subject, object Object) bool {
    // 1. 匹配域名
    if !acr.MatchesDomains(subject, object) { return false }
    
    // 2. 匹配资源路径
    if !acr.MatchesResources(subject, object) { return false }
    
    // 3. 匹配查询参数
    if !acr.MatchesQuery(object) { return false }
    
    // 4. 匹配 HTTP 方法
    if !acr.MatchesMethods(object) { return false }
    
    // 5. 匹配网络/IP
    if !acr.MatchesNetworks(subject) { return false }
    
    // 6. 匹配用户/组
    if !acr.MatchesSubjects(subject) { return false }
    
    return true  // 所有条件匹配成功
}
```

**关键点**:
- 规则按配置顺序逐一匹配
- 第一个匹配的规则决定所需的认证级别
- 若无匹配规则，则使用默认策略 (`default_policy`)

### 3.3 MFA 启用判定逻辑

**位置**: `internal/authorization/authorizer.go:NewAuthorizer`

```go
func NewAuthorizer(config *schema.Configuration) *Authorizer {
    authorizer := &Authorizer{
        defaultPolicy: NewLevel(config.AccessControl.DefaultPolicy),
        rules:         NewAccessControlRules(config.AccessControl),
        log:           logging.Logger(),
    }

    // 判定逻辑：
    // 1. 如果默认策略是 TwoFactor，则启用 MFA
    if authorizer.defaultPolicy == TwoFactor {
        authorizer.mfa = true
        return authorizer
    }

    // 2. 如果任何规则的策略是 TwoFactor，则启用 MFA
    for _, rule := range authorizer.rules {
        if rule.Policy == TwoFactor {
            authorizer.mfa = true
            return authorizer
        }
    }

    // 3. 检查 OIDC 配置是否需要 MFA
    authorizer.mfa = isOpenIDConnectMFA(config)

    return authorizer
}
```

### 3.4 Cookie 会话认证流程

**位置**: `internal/handlers/handler_authz_authn.go:CookieSessionAuthnStrategy.Get`

```
获取会话 Cookie
   ↓
1. 会话验证
   ├─ 检查 Cookie 域名是否匹配
   ├─ 验证会话有效性（防篡改）
   ├─ 检查不活动超时 (inactivity timeout)
   └─ 检查是否需要刷新用户信息
   ↓
2. 确定认证级别
   - 调用 userSession.AuthenticationLevel()
   - 根据会话中的 2FA 完成状态返回
   ↓
3. 返回认证结果
   - Username: 用户名
   - Details: 用户详细信息（显示名、邮箱、组）
   - Level: OneFactor / TwoFactor
```

### 3.5 OIDC Bearer Token 认证流程

**位置**: `internal/handlers/handler_authz_authn.go:handleVerifyGETAuthorizationBearerIntrospection`

```
收到 Bearer Token
   ↓
1. Token 内省 (Introspection)
   - 验证 Token 是否有效、未过期
   - 验证 Token 用途为 AccessToken
   ↓
2. Audience 验证
   - 验证 Token 的 audience 是否包含目标 URL
   - 使用客户端配置的 Audience 策略
   ↓
3. 客户端验证
   - 根据 Session 中的 ClientID 查询客户端
   - 验证客户端是否拥有 authelia_bearer_authz scope
   ↓
4. 认证级别判定 (关键交叉点)
   ```go
   if authorization.NewAuthenticationMethodsReferencesFromClaim(
       osession.DefaultSession.Claims.AuthenticationMethodsReferences,
   ).MultiFactorAuthentication() {
       level = authentication.TwoFactor
   } else {
       level = authentication.OneFactor
   }
   ```
   ↓
5. 返回认证结果
```

---

## 4. 三者交叉影响机制

### 4.1 OIDC AMR Claim 与 MFA 的关联

**Authentication Methods References (AMR)** 是 OIDC 标准中的声明，用于标识用户采用了哪些认证方法。

**位置**: `internal/authorization/const.go`

```go
// AMR 值定义 (RFC 8176)
const (
    AMRKnowledgeBasedAuthentication  = "kba"   // 基于知识的认证
    AMRMultiFactorAuthentication     = "mfa"   // 多因素认证
    AMRMultiChannelAuthentication    = "mca"   // 多渠道认证
    AMRUserPresence                  = "user"  // 用户存在性
    AMRPersonalIdentificationNumber  = "pin"   // PIN 码
    AMRPasswordBasedAuthentication   = "pwd"   // 密码认证
    AMROneTimePassword               = "otp"   // 一次性密码 (TOTP)
    AMRProofOfPossession             = "pop"   // 持有证明
    AMRHardwareSecuredKey            = "hwk"   // 硬件安全密钥
    AMRSoftwareSecuredKey            = "swk"   // 软件安全密钥
    AMRShortMessageService           = "sms"   // SMS 短信
)
```

**交叉影响点**:
- OIDC 会话中的 `amr` 声明决定了访问控制时的认证级别
- 当 `amr` 包含 `"mfa"` 时，认证级别被视为 `TwoFactor`
- 这使得 OIDC Token 可以正确地用于需要双因素认证的资源访问

### 4.2 Subject 中的 ClientID 对访问控制的影响

**位置**: `internal/authorization/types.go:Subject`

```go
type Subject struct {
    Username string   // 用户名
    Groups   []string // 用户组
    ClientID string   // OIDC 客户端 ID - 关键交叉字段
    IP       net.IP   // 客户端 IP
}
```

**影响机制**:
1. **规则匹配时的 Subject 过滤**:
   - 访问控制规则可以针对特定的 `oauth2:client:client_id` 主体
   - 不同的 OIDC 客户端可以有不同的访问控制策略

2. **Client 授权策略**:
   - OIDC 客户端有自己的授权策略配置 (`ClientAuthorizationPolicy`)
   - 客户端级别的策略可能要求更高的认证级别

### 4.3 会话状态对访问控制的动态影响

1. **会话不活动超时**:
   - 用户在配置的 `inactivity` 时间内无活动时，会话失效
   - 即使原先是 TwoFactor 认证，超时后变为 NotAuthenticated

2. **会话刷新机制**:
   - 定期从认证后端刷新用户信息（组、邮箱等）
   - 组变化可能导致匹配的访问控制规则变化
   - 例如：用户从某个组被移除，可能失去对某些资源的访问权限

3. **Cookie 域名绑定**:
   - 会话 Cookie 与特定域名绑定
   - 跨域名访问需要重新认证

---

## 5. OIDC 客户端授权策略

**位置**: `internal/oidc/client_policy.go`

### 5.1 客户端授权策略结构

```go
type ClientAuthorizationPolicy struct {
    Name          string
    DefaultPolicy authorization.Level  // 默认策略
    Rules         []ClientAuthorizationPolicyRule  // 规则列表
}
```

### 5.2 客户端策略判定流程

```go
func (p *ClientAuthorizationPolicy) GetRequiredLevel(subject authorization.Subject) authorization.Level {
    // 1. 逐一检查规则
    for _, rule := range p.Rules {
        if rule.IsMatch(subject) {
            return rule.Policy  // 返回匹配规则的级别
        }
    }
    
    // 2. 无匹配规则时返回默认策略
    return p.DefaultPolicy
}
```

### 5.3 客户端规则匹配

```go
type ClientAuthorizationPolicyRule struct {
    Subjects []authorization.AccessControlSubjects
    Networks authorization.AccessControlNetworks
    Policy   authorization.Level
}

func (p *ClientAuthorizationPolicyRule) MatchesSubjects(subject authorization.Subject) bool {
    // 1. 检查是否有 Subject 要求且用户为匿名
    if len(p.Subjects) != 0 && subject.IsAnonymous() {
        return false
    }
    
    // 2. 匹配用户/组规则
    for _, rule := range p.Subjects {
        if rule.IsMatch(subject) {
            matchesSubject = true
            break
        }
    }
    
    // 3. 检查网络匹配
    return p.Networks.IsMatch(subject)
}
```

---

## 6. 认证结果与授权要求的比较逻辑

**核心比较函数**: `isAuthzResult`

```
输入:
  - 当前认证级别 (authn.Level)
  - 要求的授权级别 (required)
  - 规则是否有主体要求 (ruleHasSubject)

输出:
  - AuthzResultForbidden    (403 禁止)
  - AuthzResultUnauthorized (401 未授权)
  - AuthzResultAuthorized   (200 已授权)
```

**比较矩阵**:

| 当前认证级别 | 要求级别 | 规则有主体 | 结果 |
|-------------|---------|-----------|-----|
| NotAuthenticated | Bypass | 否 | Authorized |
| NotAuthenticated | Bypass | 是 | Unauthorized |
| NotAuthenticated | OneFactor | 任意 | Unauthorized |
| NotAuthenticated | TwoFactor | 任意 | Unauthorized |
| OneFactor | Bypass | 任意 | Authorized |
| OneFactor | OneFactor | 任意 | Authorized |
| OneFactor | TwoFactor | 任意 | Unauthorized |
| TwoFactor | Bypass | 任意 | Authorized |
| TwoFactor | OneFactor | 任意 | Authorized |
| TwoFactor | TwoFactor | 任意 | Authorized |
| 任意 | Denied | 任意 | Forbidden |

---

## 7. 关键交互点总结

### 7.1 数据流图

```
OIDC Identity Provider
        │
        ▼  生成 Token 时设置 amr
OIDC Session (Session)
  ├─ Claims.AuthenticationMethodsReferences
  │   └─ ["pwd", "otp", "mfa"]
  ├─ ClientID
  └─ Username
        │
        ▼  内省 Token 时提取
Authentication Info (Authn)
  ├─ Level: TwoFactor (由 amr 决定)
  ├─ Username: johndoe
  ├─ ClientID: my-client
  └─ Details: {Groups: ["admin", "dev"]}
        │
        ▼  传入访问控制检查
Access Control Check
  ├─ Subject: {Username, Groups, ClientID, IP}
  ├─ Object: {URL, Domain, Path, Method}
  └─ Result: Required Level (e.g., TwoFactor)
        │
        ▼  比较决策
Authorization Decision
  └─ 200 OK / 401 Unauthorized / 403 Forbidden
```

### 7.2 关键设计决策

1. **AMR 作为认证级别载体**:
   - 不依赖外部会话状态，Token 自包含认证级别信息
   - 符合 OAuth 2.0 无状态设计原则

2. **规则顺序敏感**:
   - 第一个匹配的规则生效，配置顺序至关重要
   - 应将更具体的规则放在前面

3. **多认证策略共存**:
   - Cookie 会话和 Bearer Token 可以同时使用
   - 按配置顺序尝试认证策略，第一个成功的生效

4. **会话刷新机制**:
   - 定期同步用户组信息，确保访问控制规则的时效性
   - 组变化可能立即影响用户的访问权限

---

## 8. OIDC 授权同意流程中的策略联动

**位置**: `internal/handlers/handler_oauth2_authorization_consent_core.go:handleOAuth2AuthorizationConsent`

### 8.1 授权同意流程总览

```
OIDC 授权请求到达
   ↓
1. 会话更新与验证
   - 刷新会话信息
   - 验证会话有效性
   ↓
2. 客户端授权策略判定 (关键联动点)
   ```go
   level := policy.GetRequiredLevel(authorization.Subject{
       Username: userSession.Username, 
       Groups:   userSession.Groups, 
       IP:       ctx.RemoteIP()
   })
   ```
   ↓
3. 分支判断与处理
   ├─ 用户匿名 → 生成 consent 并重定向到登录
   ├─ 认证级别足够 → 按 consent 模式处理
   │  ├─ Explicit: 显式同意页面
   │  ├─ Implicit: 隐式同意直接授权
   │  └─ PreConfigured: 预配置同意
   ├─ 策略要求 Denied → 返回 403 客户端拒绝访问
   └─ 认证级别不足 → 生成 consent 并重定向到认证
   ↓
4. 同意决策后生成 Token
   - amr 声明基于实际认证级别设置
   - Token 返回给客户端
```

### 8.2 客户端策略与会话认证级别的联动判定

**核心判定点 1: 认证级别检查**
```go
// handler_oauth2_authorization_consent_core.go:38-79
switch {
case userSession.IsAnonymous():
    // 匿名用户：重定向到登录认证
    handler = handleOAuth2AuthorizationConsentNotAuthenticated
    
case authorization.IsAuthLevelSufficient(
    userSession.AuthenticationLevel(...), level):
    // 认证级别满足策略要求：按 consent 模式处理
    mode := client.GetConsentPolicy().Mode
    switch mode {
    case oidc.ClientConsentModeExplicit:
        handler = handleOAuth2AuthorizationConsentModeExplicit
    case oidc.ClientConsentModeImplicit:
        handler = handleOAuth2AuthorizationConsentModeImplicit
    case oidc.ClientConsentModePreConfigured:
        handler = handleOAuth2AuthorizationConsentModePreConfigured
    }
    
case level == authorization.Denied:
    // 策略明确拒绝：返回 access_denied 错误
    ctx.Providers.OpenIDConnect.WriteDynamicAuthorizeError(
        ctx, rw, requester, oidc.ErrClientAuthorizationUserAccessDenied)
    
default:
    // 认证级别不足：生成 consent 并引导升级认证
    return handleOAuth2AuthorizationConsentGenerate(...)
}
```

**核心判定点 2: 同意提交时二次验证**
```go
// handler_oauth2_consent.go:228-238
level := userSession.AuthenticationLevel(ctx.Configuration.WebAuthn.EnablePasskey2FA)

if !client.IsAuthenticationLevelSufficient(level, authorization.Subject{
    Username: userSession.Username, 
    Groups:   userSession.Groups, 
    IP:       ctx.RemoteIP()
}) {
    // 即使到达同意页面，认证级别不足仍拒绝
    ctx.SetJSONError(messageOperationFailed)
    return
}
```

**关键联动机制**:
1. **双重检查机制**: 授权请求开始时检查一次，用户提交同意时再检查一次，防止会话状态变化
2. **策略动态判定**: 每次授权请求都实时调用 `policy.GetRequiredLevel()`，策略配置变化立即生效
3. **Subject 完整传递**: 传递用户名、用户组、IP 地址给策略判定，支持基于用户属性和网络位置的精细控制
4. **认证级别映射**: OIDC 客户端策略的 `Level` 与通用访问控制的 `Level` 使用同一套枚举值

---

## 9. 认证失败、匿名与拒绝访问的分支影响

### 9.1 匿名用户访问分支

**触发条件**:
- Cookie 会话不存在或已失效
- `userSession.IsAnonymous() == true`

**对访问控制的影响**:
```go
// 访问控制规则匹配中的匿名处理
func (acr *AccessControlRule) MatchesSubjects(subject Subject) bool {
    if subject.IsAnonymous() {
        // 规则有主体要求时，匿名用户直接不匹配
        return len(acr.Subjects) == 0
    }
    // ... 后续匹配逻辑
}
```

**访问结果矩阵（匿名用户）**:
| 要求级别 | 规则有主体 | 访问结果 |
|---------|-----------|---------|
| Bypass | 否 | Authorized (200) |
| Bypass | 是 | Unauthorized (401) |
| OneFactor | 任意 | Unauthorized (401) |
| TwoFactor | 任意 | Unauthorized (401) |
| Denied | 任意 | Forbidden (403) |

**关键影响**:
- 匿名用户只能访问设置为 `Bypass` 且无主体要求的资源
- 任何需要身份验证的资源（OneFactor/TwoFactor）都要求先登录
- 对于 OIDC 授权流程，匿名用户直接被引导到认证流程

### 9.2 认证失败分支

**常见认证失败场景**:

1. **Basic Auth 密码错误**
   ```go
   valid, cached, err := s.basic(ctx, authn.Header.Authorization)
   if !valid {
       // 认证失败，级别为 NotAuthenticated
       return "", authentication.NotAuthenticated, err
   }
   ```

2. **Bearer Token 验证失败**
   ```go
   if _, err = oidc.IsAccessToken(ctx, authn.Header.Authorization.Value()); !at {
       // Token 无效或不匹配，级别为 NotAuthenticated
       return "", "", false, authentication.NotAuthenticated, errTokenIntent
   }
   ```

3. **会话不活动超时**
   ```go
   func handleAuthnCookieValidateInactivity(...) bool {
       if !isAnonymous && !userSession.KeepMeLoggedIn {
           // 超过 inactivity 时间，会话失效
           return time.Unix(userSession.LastActivity, 0).
               Add(provider.Config.Inactivity).Before(now)
       }
       return false
   }
   ```

**认证失败后的访问控制决策**:
- 认证级别重置为 `NotAuthenticated`
- 按照匿名用户的访问控制规则进行判定
- 如果目标资源需要认证，则返回 `401 Unauthorized`
- OIDC 授权流程中认证失败会导致 `access_denied` 或 `login_required` 错误

### 9.3 拒绝访问分支 (Denied)

**触发场景**:

1. **访问控制规则明确拒绝**
   ```go
   // 配置示例
   access_control:
     rules:
       - domain: internal.example.com
         policy: deny
   ```

2. **OIDC 客户端策略拒绝**
   ```go
   level := policy.GetRequiredLevel(subject)
   if level == authorization.Denied {
       // 返回客户端授权拒绝错误
       return oidc.ErrClientAuthorizationUserAccessDenied
   }
   ```

3. **用户被禁止登录**
   ```go
   ban, value, expires, err := ctx.Providers.Regulator.BanCheck(ctx, username)
   if errors.Is(err, regulation.ErrUserIsBanned) {
       // 用户被临时封禁
       return authentication.NotAuthenticated, err
   }
   ```

**拒绝访问的结果表现**:
| 场景 | HTTP 状态码 | 错误类型 |
|-----|------------|---------|
| 访问控制规则 deny | 403 Forbidden | 直接返回禁止访问 |
| OIDC 客户端策略拒绝 | OAuth2 错误 | `access_denied` |
| 用户被封禁 | 401 Unauthorized | 认证失败 |
| Token 内省失败 | 401 Unauthorized | `invalid_token` |

---

## 10. 端到端场景分析

### 场景一：OIDC 客户端访问需要双因素认证的内部资源

**配置**:
```yaml
# 访问控制规则
access_control:
  default_policy: two_factor
  rules:
    - domain: internal-app.example.com
      policy: two_factor

# OIDC 客户端配置
identity_providers:
  oidc:
    clients:
      - id: internal-dashboard
        authorization_policy:
          default_policy: two_factor
```

**用户旅程**:
```
1. 用户访问 internal-app.example.com
   ↓
2. Authelia 检测到需要 two_factor
   - 用户当前是 NotAuthenticated（新会话）
   - 重定向到 Authelia 登录页面
   ↓
3. 用户输入用户名密码（1FA 完成）
   - 会话级别变为 OneFactor
   ↓
4. 访问控制检查发现需要 TwoFactor
   - 重定向到 2FA 验证页面
   ↓
5. 用户输入 TOTP 验证码（2FA 完成）
   - 会话级别变为 TwoFactor
   - 会话 amr: ["pwd", "otp", "mfa"]
   ↓
6. 访问被允许，成功访问内部应用
   ↓
7. 用户通过 OIDC 登录 internal-dashboard
   - OIDC 授权策略要求 two_factor
   - 会话级别是 TwoFactor，满足要求
   - OIDC 授权流程继续，进入 consent 页面
   ↓
8. 用户同意授权
   - 生成 ID Token，amr: ["pwd", "otp", "mfa"]
   - 客户端收到包含 mfa 声明的 Token
   ↓
9. 后续 Bearer Token 访问
   - Token 内省提取 amr 声明
   - 检测到 "mfa" → 认证级别为 TwoFactor
   - 满足 two_factor 策略要求，访问成功
```

**关键交叉点**:
- 会话认证级别在 1FA → 2FA 过程中升级
- amr 声明持久化在 OIDC Token 中
- Bearer Token 认证时 amr 反向映射回认证级别
- 访问控制规则与 OIDC 客户端策略协同工作

### 场景二：用户组变化导致的动态权限变更

**配置**:
```yaml
access_control:
  rules:
    - domain: admin.example.com
      subject: ["group:admins"]
      policy: two_factor
    - domain: app.example.com
      policy: one_factor
```

**用户旅程**:
```
初始状态:
- 用户 john 属于 groups: ["users"]
- 已完成 2FA 认证，会话级别: TwoFactor

1. john 访问 app.example.com
   - 匹配规则：policy one_factor
   - 当前级别 TwoFactor 满足要求
   - 访问成功 ✓
   ↓
2. john 尝试访问 admin.example.com
   - 规则有主体要求：group:admins
   - john 不在 admins 组
   - 规则不匹配，使用默认策略
   - 访问结果：Unauthorized (401) ✗
   ↓
3. 管理员将 john 加入 admins 组
   - 后端 LDAP/数据库更新
   ↓
4. 会话刷新触发（refresh_interval）
   ```go
   details, err := ctx.Providers.UserProvider.GetDetails(username)
   // groups 变为 ["users", "admins"]
   userSession.Groups = details.Groups
   ```
   ↓
5. john 再次访问 admin.example.com
   - 规则匹配：subject group:admins 匹配
   - policy two_factor
   - 当前级别 TwoFactor 满足要求
   - 访问成功 ✓
   ↓
6. john 发起 OIDC 授权请求
   - Subject 中 Groups 包含 "admins"
   - 客户端策略可能对 admin 组有特殊要求
   - 策略判定根据最新组信息执行
```

**关键交叉点**:
- 会话刷新机制确保用户组信息及时更新
- 用户组变化影响访问控制规则的主体匹配
- OIDC 授权策略同样基于最新的 Subject 信息判定
- 权限变更无需用户重新登录，会话刷新后台自动处理

### 场景三：Denied 策略与安全边界

**配置**:
```yaml
access_control:
  rules:
    - domain: internal.example.com
      networks: ["192.168.1.0/24"]  # 公司内网
      policy: one_factor
    - domain: internal.example.com  # 外网访问拒绝
      policy: deny

identity_providers:
  oidc:
    clients:
      - id: partner-api
        authorization_policy:
          rules:
            - networks: ["203.0.113.0/24"]  # 合作伙伴网络
              policy: two_factor
          default_policy: deny
```

**用户旅程**:
```
用户从外部 IP 198.51.100.10 访问:
   ↓
1. 访问 internal.example.com
   - 第一条规则 networks 不匹配 (198.51.100.10 不在 192.168.1.0/24)
   - 匹配第二条规则 policy: deny
   - 返回 403 Forbidden ✗
   ↓
2. 尝试 OIDC 授权 code 流程
   - 客户端 partner-api 的策略判定
   - 源 IP 不在 203.0.113.0/24
   - 使用 default_policy: deny
   - 返回 OAuth2 错误 access_denied ✗
   ↓
用户切换到公司内网 IP 192.168.1.50:
   ↓
3. 再次访问 internal.example.com
   - 匹配第一条规则 networks + policy one_factor
   - 重定向到认证
   - 完成 1FA 后访问成功 ✓
   ↓
4. 发起 OIDC 授权请求
   - 源 IP 192.168.1.50 不在合作伙伴网络
   - 客户端策略 default_policy deny 生效
   - 即使是公司内网，非合作伙伴网络访问仍被拒绝 ✗
   ↓
用户使用合作伙伴网络 IP 203.0.113.25:
   ↓
5. 发起 OIDC 授权请求
   - 匹配客户端策略规则 networks + policy two_factor
   - 会话级别 OneFactor 不满足
   - 引导完成 2FA 认证后授权成功 ✓
```

**关键交叉点**:
- 多层安全边界：全局访问控制 + OIDC 客户端特定策略
- 网络位置是重要的访问控制维度
- Denied 策略是硬边界，不触发认证重定向，直接拒绝
- 不同资源可以有完全独立的安全策略要求

---

## 11. OIDC 用户令牌与客户端凭证令牌的 Subject 回填差异

### 11.1 内省后的字段回填差异

**核心代码位置**: `internal/handlers/handler_authz_authn.go:handleVerifyGETAuthorizationBearerIntrospection`

两种令牌类型在 Token 内省后的字段回填逻辑有本质差异：

```go
if osession.ClientCredentials {
    // 客户端凭证模式 (Client Credentials)
    return "", osession.ClientID, true, authentication.OneFactor, nil
}

// 用户令牌模式 (Authorization Code / Implicit)
if authorization.NewAuthenticationMethodsReferencesFromClaim(
    osession.DefaultSession.Claims.AuthenticationMethodsReferences,
).MultiFactorAuthentication() {
    level = authentication.TwoFactor
} else {
    level = authentication.OneFactor
}

return osession.Username, "", false, level, nil
```

**回填差异对比表**:

| 字段 | 用户令牌 (User Token) | 客户端凭证令牌 (Client Credentials) |
|-----|----------------------|-----------------------------------|
| username | `osession.Username` (非空，实际用户名) | `""` (空字符串) |
| clientID | `""` (空字符串) | `osession.ClientID` (非空，客户端 ID) |
| ccs | `false` | `true` |
| level | 根据 amr 判定：OneFactor/TwoFactor | 固定 OneFactor |
| Groups | 用户所属的用户组 (从用户详情加载) | 空数组 |

**关键数据结构**:
```go
// 最终传递给访问控制的 Subject
type Subject struct {
    Username string   // 用户令牌：有值；客户端凭证：空
    Groups   []string // 用户令牌：用户组；客户端凭证：空
    ClientID string   // 用户令牌：空；客户端凭证：有值
    IP       net.IP
}
```

### 11.2 oauth2:client 规则命中机制

**规则匹配代码**: `internal/authorization/access_control_subjects.go:AccessControlClient.IsMatch`

```go
// AccessControlClient represents an ACL subject of type `oauth2:client:`.
type AccessControlClient struct {
    Provider string
    ID       string
}

func (acc AccessControlClient) IsMatch(subject Subject) bool {
    return acc.ID == subject.ClientID
}
```

**命中条件分析**:

1. **客户端凭证令牌 → 可以命中 oauth2:client 规则**
   ```yaml
   access_control:
     rules:
       - domain: api.example.com
         subject: ["oauth2:client:backend-service"]
         policy: one_factor
   ```
   - ClientID 回填为 `backend-service`
   - `acc.ID == subject.ClientID` → `"backend-service" == "backend-service"` → **匹配 ✓**

2. **用户令牌 → 无法命中 oauth2:client 规则**
   - ClientID 回填为空字符串
   - `acc.ID == subject.ClientID` → `"backend-service" == ""` → **不匹配 ✗**

**规则匹配矩阵**:

| 令牌类型 | oauth2:client:xxx 规则 | user:xxx 规则 | group:xxx 规则 |
|---------|-----------------------|--------------|---------------|
| 用户令牌 | ✗ 不匹配 (ClientID 为空) | ✓ 可匹配 | ✓ 可匹配 |
| 客户端凭证令牌 | ✓ 可匹配 | ✗ 不匹配 (Username 为空) | ✗ 不匹配 (Groups 为空) |

### 11.3 双因素认证资源的可达性差异

#### 11.3.1 用户令牌的双因素可达性

**认证级别判定**:
```go
// 用户令牌：根据 amr 声明动态判定
if authorization.NewAuthenticationMethodsReferencesFromClaim(
    osession.DefaultSession.Claims.AuthenticationMethodsReferences,
).MultiFactorAuthentication() {
    level = authentication.TwoFactor  // 用户完成了 2FA
} else {
    level = authentication.OneFactor  // 用户只完成了密码认证
}
```

**访问结果**:
| 用户完成的认证 | Token 中的 amr | 认证级别 | two_factor 资源 | one_factor 资源 |
|--------------|---------------|---------|----------------|----------------|
| 仅密码 | ["pwd"] | OneFactor | ✗ 401 Unauthorized | ✓ 200 OK |
| 密码 + TOTP | ["pwd", "otp", "mfa"] | TwoFactor | ✓ 200 OK | ✓ 200 OK |

**用户令牌访问 two_factor 资源的流程**:
```
1. 用户完成 1FA（密码）→ amr: ["pwd"] → level: OneFactor
2. 访问 two_factor 资源 → OneFactor < TwoFactor → 401 重定向
3. 用户完成 TOTP 2FA → amr: ["pwd", "otp", "mfa"]
4. 新 Token 包含 mfa 声明 → level: TwoFactor
5. 访问 two_factor 资源 → ✓ 授权成功
```

#### 11.3.2 客户端凭证令牌的双因素可达性

**认证级别判定**:
```go
// 客户端凭证令牌：固定为 OneFactor
if osession.ClientCredentials {
    return "", osession.ClientID, true, authentication.OneFactor, nil
}
```

**访问结果**:
| 资源要求策略 | 客户端凭证令牌级别 | 访问结果 | 原因 |
|------------|------------------|---------|------|
| one_factor | OneFactor | ✓ 200 OK | 级别足够 |
| two_factor | OneFactor | ✗ 401 Unauthorized | 级别不足 |
| bypass | OneFactor | ✓ 200 OK | 绕过认证 |
| deny | OneFactor | ✗ 403 Forbidden | 规则拒绝 |

**关键限制：客户端凭证令牌无法达到 TwoFactor 级别**
- 客户端凭证流程（`grant_type=client_credentials`）无用户参与
- 没有用户交互就无法完成第二因素认证（TOTP/WebAuthn 等）
- 因此 `ClientCredentials` 模式的令牌认证级别永久固定为 `OneFactor`
- **结论：客户端凭证令牌永远无法访问 policy=two_factor 的资源**

#### 11.3.3 实际场景对比

**场景 A：机器到机器 API 调用（客户端凭证）**
```yaml
# 可行的配置
access_control:
  rules:
    - domain: api.example.com
      resources: ["^/public/.*$"]
      subject: ["oauth2:client:api-service"]
      policy: one_factor  # ✓ 客户端凭证可以访问

    - domain: api.example.com
      resources: ["^/admin/.*$"]
      subject: ["oauth2:client:admin-service"]
      policy: two_factor  # ✗ 客户端凭证永远无法访问
```

**场景 B：用户浏览器 + API 后端调用（用户令牌）**
```yaml
# 可行的配置
access_control:
  rules:
    - domain: app.example.com
      subject: ["group:users"]
      policy: one_factor  # ✓ 用户完成密码即可访问

    - domain: app.example.com
      resources: ["^/settings/.*$"]
      subject: ["group:admins"]
      policy: two_factor  # ✓ 用户完成 2FA 即可访问
```

#### 11.3.4 配置最佳实践

1. **为客户端凭证令牌专门设计访问规则**:
   ```yaml
   access_control:
     rules:
       # 客户端凭证专用规则
       - domain: api.example.com
         subject: ["oauth2:client:backend", "oauth2:client:worker"]
         policy: one_factor
         methods: ["GET", "POST"]
   ```

2. **不要给客户端凭证令牌配置 two_factor 策略**:
   ```yaml
   # ❌ 无效配置：永远无法匹配
   - domain: api.example.com
     subject: ["oauth2:client:backend"]
     policy: two_factor
   ```

3. **对敏感操作考虑额外的认证机制**:
   - 使用客户端证书双向认证 (mTLS)
   - 要求特定的请求签名
   - 使用网络白名单限制源 IP

4. **用户令牌与客户端凭证分离配置**:
   ```yaml
   access_control:
     rules:
       # 用户访问前端应用
       - domain: app.example.com
         subject: ["group:users"]
         policy: two_factor
       
       # 服务间 API 调用
       - domain: api.example.com
         subject: ["oauth2:client:backend-service"]
         policy: one_factor
         networks: ["10.0.0.0/8"]  # 仅限内网调用
   ```

---

## 12. 令牌内省分支生效的前置条件

### 12.1 认证策略顺序对 Bearer 解析的影响

**核心代码位置**: `internal/handlers/handler_authz.go:160-185`

认证策略采用**顺序执行、首胜终止**的机制：

```go
for _, strategy = range authz.strategies {
    if authn, err = strategy.Get(ctx, provider, object); err != nil {
        // 错误处理...
    }

    if authn.Level != authentication.NotAuthenticated {
        break  // 首个认证成功的策略终止后续执行
    }
}
```

**默认策略顺序**（以 AuthRequest 实现为例）：
```
1. HeaderProxyAuthorizationAuthRequestAuthnStrategy (仅 Basic scheme)
   ↓ （如果认证失败或未提供凭据）
2. CookieSessionAuthnStrategy
   ↓ （如果也未认证）
   → 最终为 NotAuthenticated
```

**策略顺序的关键影响**：

1. **Bearer 策略的优先级**
   - 如果 Header 策略配置了 Bearer scheme，它会在 Cookie 策略之前执行
   - 携带有效 Bearer Token 的请求会被优先识别为令牌认证
   - Cookie 会话不会被触发

2. **Basic 与 Bearer 的互斥性**
   - 如果同时配置了 Basic 和 Bearer，请求只会匹配其中一个 scheme
   - `Authorization: Basic xxx` 走密码认证流程
   - `Authorization: Bearer xxx` 走令牌内省流程

3. **Cookie 策略的兜底效应**
   - 即使 Header 策略未认证成功，Cookie 策略仍可能认证成功
   - 浏览器请求通常携带 Cookie，会优先走会话认证而非令牌认证

### 12.2 Endpoint 未启用 Bearer Scheme 时的跳过机制

**核心代码位置**: `internal/handlers/handler_authz_authn.go:236-257`

当请求携带 Bearer Token 但 Endpoint 未启用 Bearer scheme 时：

```go
scheme := authn.Header.Authorization.Scheme()

if !s.schemes.Has(scheme) {
    ctx.Logger.
        WithFields(map[string]any{
            "scheme": authn.Header.Authorization.SchemeRaw(), 
            "header": string(s.headerAuthorize)
        }).
        Debug("Skipping header authorization as the scheme and header combination is unknown to this endpoint configuration")

    return authn, nil  // 直接返回，不执行后续认证逻辑
}
```

**跳过行为的具体表现**：

| 场景 | 行为 | 结果 |
|------|------|------|
| 请求带 Bearer Token 但 scheme 未配置 | Header 策略检测 scheme 不匹配，返回 `nil` 错误 | 继续执行下一个策略（通常是 Cookie） |
| 请求带 Bearer Token 且 scheme 已配置但 Token 无效 | 执行令牌内省，返回认证错误 | `CanHandleUnauthorized()=true`，循环终止，**不尝试 Cookie** |
| 请求带 Bearer Token 且 scheme 已配置且 Token 有效 | 令牌内省成功 | 认证成功，循环终止 |
| 请求既带 Cookie 又带 Bearer Token（scheme 未配置） | scheme 不匹配，Header 策略跳过 | 继续执行 Cookie 策略 |
| 请求既带 Cookie 又带 Bearer Token（scheme 已配置但 Token 无效） | Header 策略返回错误 | 循环终止，**不会 fallback 到 Cookie** |

**默认配置情况**：
```yaml
# DefaultServerConfiguration - 所有 Authz 端点默认
endpoints:
  authz:
    auth-request:
      authn_strategies:
        - name: HeaderAuthorization
          schemes: ["basic"]  # 默认仅启用 Basic，无 Bearer
        - name: CookieSession
```

**关键结论**：默认配置下，Bearer Token 会被静默跳过，不会触发令牌内省。

### 12.3 对 oauth2:client 规则命中的边界结论

**命中的前置条件链**：
```
oauth2:client 规则命中
   ↓ 必须
ClientID 非空
   ↓ 必须
令牌内省流程被触发
   ↓ 必须
Header 策略在策略列表中
   ↓ 必须
Header 策略配置了 Bearer scheme
   ↓ 必须
请求携带 Authorization: Bearer xxx 头
```

**边界情况分析**：

1. **边界 1：未启用 Bearer scheme（默认情况）**
   ```
   配置: schemes: ["basic"]（默认）
   请求: Authorization: Bearer authelia_at_xxx
   流程:
     - Header 策略检测到 scheme 不匹配 → 跳过
     - 继续执行 Cookie 策略
     - Cookie 无会话 → NotAuthenticated
     - Subject.ClientID = ""
   结果: oauth2:client 规则永远无法命中
   ```

2. **边界 2：启用 Bearer 但策略顺序在 Cookie 之后**
   ```
   配置: authn_strategies: [CookieSession, HeaderAuthorization(basic, bearer)]
   请求: 浏览器请求（带有效 Cookie + Bearer Token）
   流程:
     - Cookie 策略首先执行 → 会话认证成功
     - 循环 break，Header 策略不执行
     - Subject 来自会话，ClientID = ""
   结果: oauth2:client 规则无法命中（被 Cookie 抢占）
   ```

3. **边界 3：启用 Bearer 且策略顺序正确**
   ```
   配置: authn_strategies: [HeaderAuthorization(basic, bearer), CookieSession]
   请求: Authorization: Bearer authelia_at_xxx（客户端凭证令牌）
   流程:
     - Header 策略执行，scheme 匹配
     - 令牌内省成功，识别为客户端凭证
     - Subject.ClientID = 实际客户端 ID
   结果: oauth2:client 规则可以命中
   ```

**配置最佳实践（oaut2:client 场景）**：
```yaml
endpoints:
  authz:
    api-gateway:
      implementation: ExtAuthz
      authn_strategies:
        - name: HeaderAuthorization
          schemes: ["bearer"]  # 仅启用 Bearer，避免 Basic 干扰
          scheme_basic_cache_lifespan: 0s
        - name: CookieSession
```

### 12.4 对双因素资源可达性的边界结论

**客户端凭证令牌的双重限制**：
```
访问 two_factor 资源
   ↓ 需要
认证级别 = TwoFactor
   ↓ 需要
用户令牌 + amr 包含 mfa
   ← 且 →
Bearer scheme 已启用 + Header 策略顺序正确
```

**边界矩阵**：

| 令牌类型 | Bearer 已启用 | 策略顺序正确 | 可访问 one_factor | 可访问 two_factor | 可命中 oauth2:client |
|---------|--------------|-------------|-----------------|------------------|---------------------|
| 客户端凭证 | ❌ | 任意 | ❌ | ❌ | ❌ |
| 客户端凭证 | ✅ | ❌（Cookie 在前） | ❌ | ❌ | ❌ |
| 客户端凭证 | ✅ | ✅ | ✅ | ❌（固定 OneFactor） | ✅ |
| 用户令牌（1FA） | ✅ | ✅ | ✅ | ❌ | ❌ |
| 用户令牌（2FA + amr=mfa） | ✅ | ✅ | ✅ | ✅ | ❌ |

**关键边界结论**：

1. **客户端凭证令牌的硬限制**：
   - 无论如何配置，客户端凭证令牌的认证级别**永远是 OneFactor**
   - 这是 OAuth 2.0 规范的设计：客户端凭证流程不涉及用户交互，无法完成 2FA
   - **结论**：客户端凭证令牌永远无法访问 `policy: two_factor` 的资源

2. **用户令牌的配置依赖**：
   - 用户令牌访问 two_factor 资源依赖正确的 Endpoint 配置
   - 必须同时满足：启用 Bearer scheme + Header 策略顺序正确
   - 还需要用户实际完成了 2FA（amr 包含 mfa）

3. **代理端点的隔离配置**：
   - 建议为 API 调用和浏览器访问使用不同的 Authz 端点
   - API 端点：仅 Header 策略 + 仅 Bearer scheme
   - 浏览器端点：Cookie 策略优先 + Basic/Bearer 作为备选

**实际配置建议**：
```yaml
endpoints:
  authz:
    # 专为 API 调用的端点 - 仅 Bearer
    api-endpoint:
      implementation: ExtAuthz
      authn_strategies:
        - name: HeaderAuthorization
          schemes: ["bearer"]

    # 专为浏览器的端点 - Cookie 优先
    web-endpoint:
      implementation: ForwardAuth
      authn_strategies:
        - name: CookieSession
        - name: HeaderAuthorization
          schemes: ["basic", "bearer"]
```

---

## 13. 文件位置索引

| 功能模块 | 文件路径 |
|---------|--------|
| 授权主处理器 | `internal/handlers/handler_authz.go` |
| 认证策略实现 | `internal/handlers/handler_authz_authn.go` |
| Bearer Token 内省逻辑 | `internal/handlers/handler_authz_authn.go:572-640` |
| OIDC 授权处理 | `internal/handlers/handler_oauth2_authorization.go` |
| OIDC 授权同意核心 | `internal/handlers/handler_oauth2_authorization_consent_core.go` |
| OIDC 同意处理 | `internal/handlers/handler_oauth2_consent.go` |
| 访问控制规则匹配 | `internal/authorization/access_control_rule.go` |
| 访问控制 Subject 匹配器 | `internal/authorization/access_control_subjects.go` |
| 授权级别常量 | `internal/authorization/const.go` |
| Authorizer 核心 | `internal/authorization/authorizer.go` |
| Subject/Object 类型 | `internal/authorization/types.go` |
| 认证级别类型 | `internal/authentication/types.go` |
| OIDC 会话结构 | `internal/oidc/session.go` |
| OIDC 客户端策略 | `internal/oidc/client_policy.go` |
| OIDC 核心类型 | `internal/oidc/types.go` |
