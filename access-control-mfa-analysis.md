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

## 8. 文件位置索引

| 功能模块 | 文件路径 |
|---------|--------|
| 授权主处理器 | `internal/handlers/handler_authz.go` |
| 认证策略实现 | `internal/handlers/handler_authz_authn.go` |
| 访问控制规则 | `internal/authorization/access_control_rule.go` |
| 授权级别常量 | `internal/authorization/const.go` |
| Authorizer 核心 | `internal/authorization/authorizer.go` |
| Subject/Object 类型 | `internal/authorization/types.go` |
| 认证级别类型 | `internal/authentication/types.go` |
| OIDC 会话结构 | `internal/oidc/session.go` |
| OIDC 客户端策略 | `internal/oidc/client_policy.go` |
| OIDC 核心类型 | `internal/oidc/types.go` |
