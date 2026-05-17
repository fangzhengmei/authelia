# OIDC 授权确认链路机制说明

## 一、核心概念澄清

### 1.1 三个正交的安全机制

在 Authelia 的 OIDC 授权流程中，存在三个**相互独立但可协同**的安全机制：

| 机制 | 英文 | 作用域 | 解决的问题 |
|------|------|--------|----------|
| **认证级别** | Authentication Level | 全局会话 | 用户登录时达到的身份验证强度（1FA/2FA） |
| **会话提升** | Session Elevation | 特定操作 | 在已有会话基础上进行的临时二次验证 |
| **授权同意** | Consent | 单次授权 | 用户对特定客户端请求特定 scope 的知情同意 |

### 1.2 会话提升的真实接口路径

会话提升是一套独立的 API 体系，与 OIDC 授权流程**没有直接耦合**：

| 方法 | 路径 | 作用 |
|------|------|------|
| GET | `/api/user/session/elevation` | 查询当前会话的提升状态 |
| POST | `/api/user/session/elevation` | 发起提升请求（发送一次性验证码） |
| PUT | `/api/user/session/elevation` | 提交验证码，完成提升 |
| DELETE | `/api/user/session/elevation/{id}` | 撤销提升会话 |

### 1.3 会话提升的触发边界

会话提升**仅**由 `RequireElevated` 中间件保护的独立 API 触发，主要用于：
- 修改密码：`POST /api/change-password`
- 注册 TOTP：`GET/POST/PUT/DELETE /api/secondfactor/totp/register`
- 注册 WebAuthn：`PUT/POST/DELETE /api/secondfactor/webauthn/credential/register`
- 删除 WebAuthn 凭证：`PUT/DELETE /api/secondfactor/webauthn/credential/{credentialID}`

**关键结论：OIDC 授权确认流程中，不会直接进入会话提升。**

## 二、授权确认链路的完整决策流

### 2.1 主入口调度

`handleOAuth2AuthorizationConsent` 是授权同意流程的总调度：

```
授权请求到达
    ↓
检查会话是否需要刷新（handleOAuth2AuthorizationConsentSessionUpdates）
    ↓
计算客户端策略要求的认证级别（policy.GetRequiredLevel）
    ↓
判断分支：
    ├─ 用户未登录（IsAnonymous）
    │      ↓
    │   重定向到登录页（handleOAuth2AuthorizationConsentNotAuthenticated）
    │
    ├─ 认证级别足够（IsAuthLevelSufficient）
    │      ↓
    │   获取 Subject UUID
    │      ↓
    │   根据同意模式进入对应分支：
    │   ├─ 强制显式同意（prompt=consent/login / code flow+offline_scope 等） → 显式同意分支
    │   ├─ 客户端配置为 Explicit → 显式同意分支
    │   ├─ 客户端配置为 Implicit → 隐式自动放行分支
    │   └─ 客户端配置为 Pre-configured → 预配置缓存分支
    │
    └─ 认证级别不足
           ↓
       生成 consent session 并保存
           ↓
       检查是否需要重新登录（RequesterRequiresLogin）
           ├─ 是 → 重定向到登录页
           └─ 否 → 调用 handleOAuth2AuthorizationConsentRedirect
```

### 2.2 `handleOAuth2AuthorizationConsentRedirect` 的决策

这是认证级别不足时的关键分支点：

```go
if client.IsAuthenticationLevelSufficient(userSession.AuthenticationLevel(...), subject) {
    // 认证级别足够 → 重定向到同意决策页
    location = "/consent/openid/decision?flow=openid&flow_id=xxx"
} else {
    // 认证级别不足 → 重定向到前端登录/认证流程
    location = handleOIDCAuthorizationConsentGetRedirectionURL(...)
}
```

**重要：认证级别不足时，是重定向到登录/2FA 认证流程，而不是会话提升流程。**

### 2.3 同意后续流程：按 Response Type 区分

同意完成后，最终授权响应的生成由 `response_type` 决定。这里需要明确**两个层面**的 response type 支持：

#### 2.3.1 服务器 Discovery 声明的支持能力

`/.well-known/openid-configuration` 端点（`internal/oidc/discovery.go:16-24`）会声明 Authelia 作为 OP（OpenID Provider）**全局支持全部 7 种标准 response type**：

| 类别 | Response Type | 说明 |
|------|--------------|------|
| 授权码流程 | `code` | Authorization Code Flow |
| Implicit 流程 | `id_token` / `token` / `id_token token` | Implicit Flow 变体 |
| Hybrid 流程 | `code id_token` / `code token` / `code id_token token` | Hybrid Flow 变体 |

这是服务器的**能力声明**，告诉客户端"我能处理这些 response type"。

#### 2.3.2 单个客户端的实际可用限制

单个客户端的可用 response type 由**配置项**决定，而非服务器全局能力：

- **配置项**：`identity_providers.oidc.clients[].response_types`
- **默认值**：`["code"]`（`internal/configuration/schema/identity_providers.go:265`），即默认仅支持授权码流程
- **可配置值**：必须是上述 7 种中的一种或多种
- **验证位置**：`validateOIDCClientResponseTypes`（`internal/configuration/validator/identity_providers.go:1109`）

**关键限制**：
- 客户端配置决定了该客户端**实际能请求**的 response type
- 即使服务器支持 7 种，如果客户端只配置了 `["code"]`，那么该客户端请求 `response_type=id_token` 会被拒绝
- 这层限制是**配置时验证**和**运行时检查**的双重保障

#### 2.3.3 Response Type 对同意后续路径的影响

同意流程本身（显式/隐式/预配置）与 response type 是**正交**的，即无论哪种同意模式，最终都支持全部 7 种 response type。但客户端配置的 response type 会直接限制：

1. **能否使用强制显式同意触发条件**：
   - `offline` / `offline_access` / `authelia.bearer.authz` 这些高权限 scope 的强制显式同意检查，**仅当 response_type 包含 `code` 时才触发**（`RequesterIsAuthorizeCodeFlow` 判断）
   - 如果客户端仅配置了 Implicit flow 的 response type（如 `id_token token`），则即使请求了 offline_access，也不会触发强制显式同意（但此时 offline_access 本身也没有实际意义）

2. **能否使用预配置缓存**：
   - 预配置缓存本身不依赖 response type，但如果客户端不支持 code flow，预配置缓存中的 `offline_access` 等 scope 无法被实际授予

3. **授权响应的实际内容**：
   - `NewAuthorizeResponse`（`internal/handlers/handler_oauth2_authorization.go:158`）根据 `requester.GetResponseTypes()` 自动构造对应响应
   - `HydrateIDTokenClaims`（`internal/handlers/handler_oauth2_authorization_claims.go:60`）会通过 `GetResponseTypes().ExactOne(ResponseTypeImplicitFlowIDToken)` 判断是否为纯 Implicit 流程，以决定 ID Token 的填充策略

**代码中的判定位置**：
- `RequesterIsAuthorizeCodeFlow`（`internal/oidc/util.go`）：判断请求是否包含 code flow 的 response type
- 运行时还会校验 `requester.GetResponseTypes()` 是否在客户端配置的 `response_types` 范围内

## 三、强制显式同意的完整触发条件

在进入同意模式分支前，`handleOAuth2AuthorizationConsent` 会调用 `RequesterRequiresExplicitConsent`（`internal/oidc/util.go:610`）进行强制显式同意检查。即使客户端配置为 Implicit 或 Pre-configured，只要满足以下任一条件，都会被强制走显式同意分支：

### 3.1 Prompt 参数触发

| 触发条件 | 代码判定位置 | 说明 |
|---------|------------|------|
| `prompt=consent` | `internal/oidc/util.go:617` | 客户端明确要求用户确认 |
| `prompt=login` | `internal/oidc/util.go:622` | 客户端要求重新登录，此时用户必须重新输入凭证，也需要显式同意 |

### 3.2 授权码流程下的高权限 Scope 触发

**仅当 `response_type` 包含 `code` 时**（即 `RequesterIsAuthorizeCodeFlow` 返回 true，`internal/oidc/util.go:626`），如果请求了以下任一 scope，也会触发强制显式同意：

| Scope | 代码判定位置 | 说明 |
|-------|------------|------|
| `offline` | `internal/oidc/util.go:627`（RequestedScopes）/ `631`（GrantedScopes） | Authelia 内部别名 |
| `offline_access` | `internal/oidc/util.go:627` / `631` | 标准 OIDC scope，用于获取 refresh token |
| `authelia.bearer.authz` | `internal/oidc/util.go:627` / `631` | Authelia 专有 scope，用于获取代理授权令牌 |

检查会同时验证 `RequestedScopes`（请求的 scope）和 `GrantedScopes`（已授予的 scope），确保两者中任一包含这些 scope 时都会触发。

### 3.3 强制显式同意的决策位置

`internal/handlers/handler_oauth2_authorization_consent_core.go:51-54`：
```go
if oidc.RequesterRequiresExplicitConsent(requester) && mode != oidc.ClientConsentModeExplicit {
    // 强制切换到显式同意分支
    handler = handleOAuth2AuthorizationConsentModeExplicit
}
```

## 四、显式同意分支（Explicit Mode）

### 4.1 无 consent_id（首次请求）

1. 生成新的 `OAuth2ConsentSession` 并持久化
2. 检查是否需要重新登录（`RequesterRequiresLogin`）
3. 调用 `handleOAuth2AuthorizationConsentRedirect`：
   - 认证级别足够 → 重定向到 `/consent/openid/decision`
   - 认证级别不足 → 重定向到登录/认证流程
4. 用户在前端页面点击同意或拒绝

### 4.2 有 consent_id（用户提交后）

1. 从存储加载 `OAuth2ConsentSession`
2. 验证：subject 匹配、未过期、未响应过
3. 检查用户是否已授权：
   - 已授权 → 返回 consent 会话，继续授权流程（根据 response_type 返回 code / id_token / token 等）
   - 未授权 → 重定向回同意决策页

### 4.3 用户提交同意（OAuth2ConsentPOST）

1. 验证会话状态和用户身份
2. **再次检查认证级别**是否满足客户端策略要求
3. 调用 `ConsentGrant(consent, true, claims)` 授予 scope
4. 如果客户端允许且用户勾选"记住"，创建预配置缓存
5. 保存响应结果，重定向完成授权

## 五、隐式自动放行分支（Implicit Mode）

### 5.1 核心逻辑

无需用户交互，系统自动代表用户完成同意。

### 5.2 无 consent_id（首次请求）

1. 生成新的 `OAuth2ConsentSession` 并持久化
2. 检查是否需要重新登录
3. 直接调用 `ConsentGrantImplicit` 完成授权
4. 保存会话并返回，继续授权流程（根据 response_type 返回 code / id_token / token 等）

### 5.3 有 consent_id

1. 从存储加载会话
2. 验证通过后调用 `ConsentGrantImplicit`
3. 保存并返回

## 六、Scope 计算机制

### 6.1 `ConsentGrant` 核心函数

这是所有同意模式共享的 Scope 授予逻辑：

```go
func ConsentGrant(consent *model.OAuth2ConsentSession, explicit bool, claims []string) {
    consent.GrantAudience()
    consent.GrantClaims(claims)

    if explicit {
        // 显式模式：授予所有请求的 scope
        consent.GrantScopes()
    } else {
        // 隐式模式：排除 offline / offline_access
        for _, scope := range consent.RequestedScopes {
            switch scope {
            case ScopeOffline, ScopeOfflineAccess:
                continue  // 跳过，不授予
            default:
                consent.GrantScope(scope)
            }
        }
    }
}
```

### 6.2 两种模式的 Scope 差异

| 模式 | explicit 参数 | 授予范围 | 可授予 offline_access |
|------|--------------|----------|---------------------|
| 显式 | true | 所有请求的 scope | 是 |
| 隐式 | false | 排除 offline / offline_access | 否 |

**设计意图**：`offline_access` 意味着获得 refresh token，可以长期访问用户资源。出于安全考虑，这种高权限 scope 必须经过用户明确同意。

### 6.3 `ConsentGrantImplicit` 辅助函数

为隐式模式封装的便捷函数（`internal/oidc/session.go:219`）：
```go
func ConsentGrantImplicit(consent *model.OAuth2ConsentSession, claims []string, subject uuid.UUID, respondedAt time.Time) {
    consent.SetRespondedAt(respondedAt, 0)
    consent.SetSubject(subject)
    ConsentGrant(consent, false, claims)
}
```

**参数顺序说明**：按实际代码，参数顺序为 `consent` → `claims` → `subject` → `respondedAt`，调用方（如隐式模式处理器）会传入 `ctx.GetClock().Now()` 作为时间参数。

## 七、Pre-configured Scope 缓存机制

### 7.1 缓存载体

`OAuth2ConsentPreConfig` 表存储用户的预配置同意信息：

| 字段 | 说明 |
|------|------|
| ClientID | 客户端标识 |
| Subject | 用户标识 |
| Scopes | 已同意的作用域列表 |
| Audience | 已同意的受众列表 |
| GrantedClaims | 已同意的声明 |
| ExpiresAt | 过期时间 |
| SignatureClaims | 请求声明的签名，用于精确匹配 |

### 7.2 缓存匹配逻辑

`handleOAuth2AuthorizationConsentModePreConfiguredGetPreConfig`（`internal/handlers/handler_oauth2_authorization_consent_preconfigured.go:217`）执行匹配：

1. 调用 `LoadOAuth2ConsentPreConfigurations` 加载该用户对该客户端的所有有效预配置记录
2. 遍历记录，依次执行以下匹配检查：
   - **有效性检查**：`config.CanConsentAt(ctx.GetClock().Now())` 检查是否已过期、被撤销
   - **精确匹配 Grants**：`config.HasExactGrants(scopes, audience)`（`internal/model/oidc.go:225`）
     - 内部调用 `HasExactGrantedScopes(scopes)` 精确匹配 scope 列表
     - 内部调用 `HasExactGrantedAudience(audience)` 精确匹配 audience 列表
   - **匹配 Claims 签名**：`config.HasClaimsSignature(signature)`（`internal/model/oidc.go:240`）对请求的 claims 签名进行比对
3. 全部匹配成功 → 返回该预配置记录，用于后续授权

**匹配方法的真实命名对照**：

| 概念描述 | 实际代码方法名 | 所在文件 |
|---------|---------------|---------|
| 精确匹配 scope 和 audience | `HasExactGrants(scopes, audience []string)` | `internal/model/oidc.go:225` |
| 精确匹配 scope 列表 | `HasExactGrantedScopes(scopes []string)` | `internal/model/oidc.go:235` |
| 精确匹配 audience 列表 | `HasExactGrantedAudience(audience []string)` | `internal/model/oidc.go:230` |
| 匹配 claims 签名 | `HasClaimsSignature(signature string)` | `internal/model/oidc.go:240` |

### 7.3 缓存的创建与生命周期

- **创建时机**：用户在显式同意页勾选"记住此选择"并提交同意后，调用 `SaveOAuth2ConsentPreConfiguration` 保存
- **有效期**：由客户端配置的 `consent.duration` 决定
- **失效条件**：过期、被用户撤销、`HasExactGrants` 不匹配、`HasClaimsSignature` 不匹配

## 八、三者关系的概念模型

### 8.1 认证级别 vs 会话提升

这是两个最容易混淆的概念，需明确区分：

| 维度 | 认证级别（Authentication Level） | 会话提升（Session Elevation） |
|------|--------------------------------|------------------------------|
| **触发时机** | 用户登录时 | 执行敏感操作前 |
| **验证方式** | 密码、TOTP、WebAuthn、Duo 等 | 一次性验证码（OTC），发送到邮箱 |
| **持续时间** | 整个会话生命周期 | 临时（由 `elevation_lifespan` 配置） |
| **作用范围** | 所有需要认证的操作 | 特定敏感操作 |
| **IP 绑定** | 否 | 是（IP 变化则失效） |
| **在 OIDC 授权中的作用** | 决定是否能进入同意流程 | 无直接作用 |

### 8.2 授权流程中的检查点

在 OIDC 授权确认链路中，**只有认证级别会被检查**：

```
授权请求
    ↓
检查认证级别（IsAuthenticationLevelSufficient）
    ├─ 足够 → 进入同意模式分支（显式/隐式/预配置）
    │       ↓
    │   预配置缓存匹配（仅 pre-configured 模式）
    │   · 调用 LoadOAuth2ConsentPreConfigurations 加载记录
    │   · CanConsentAt 检查有效性
    │   · HasExactGrants 精确匹配 scope + audience
    │   · HasClaimsSignature 匹配 claims 签名
    │       ↓
    │   Scope 计算（ConsentGrant / ConsentGrantImplicit）
    │       ↓
    │   按 response_type 生成授权响应（code / id_token / token / hybrid）
    │
    └─ 不足 → 重定向到登录/2FA 认证流程
             （绝对不会进入会话提升流程）
```

**关键结论：Scope 计算、预配置缓存匹配与会话提升三者在 OIDC 授权流程中没有任何直接交互。**

### 8.3 什么时候会话提升会介入？

会话提升**不在 OIDC 授权确认链路的代码路径中**，它是独立的安全机制：

```
用户登录（获得认证级别：1FA/2FA）
    ↓
用户访问受保护资源 → 触发 OIDC 授权流程
    ↓
[授权确认链路：只检查认证级别，不检查会话提升]
    ↓
授权完成，用户获得访问令牌
    ↓
用户执行敏感操作（如修改密码）
    ↓
[RequireElevated 中间件检查]
    ├─ 已提升 → 允许操作
    └─ 未提升 → 返回 403，前端引导用户完成会话提升
```

### 8.4 概念关系图

```
┌──────────────────────────────────────────────────────────────────┐
│                      用户会话（User Session）                     │
│  ┌──────────────────┐    ┌──────────────────────────────────┐    │
│  │ 认证级别         │    │ 会话提升（可选，临时）            │    │
│  │ - OneFactor      │    │ - Elevations.User                │    │
│  │ - TwoFactor      │    │   · Expires（过期时间）           │    │
│  │                  │    │   · RemoteIP（IP 绑定）           │    │
│  └──────────────────┘    └──────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
                         │                          │
                         ▼                          ▼
        ┌─────────────────────────────┐    ┌─────────────────────┐
        │    OIDC 授权确认链路        │    │  敏感操作 API       │
        │  - 仅检查认证级别           │    │  - 修改密码         │
        │  - Scope 计算               │    │  - 注册 2FA 设备    │
        │  - 预配置缓存匹配           │    │  - RequireElevated  │
        └─────────────────────────────┘    └─────────────────────┘
                         │
                         ▼
        ┌─────────────────────────────┐
        │  同意模式分支                │
        │  - Explicit（显式）         │
        │  - Implicit（隐式自动放行）  │
        │  - Pre-configured（缓存）   │
        └─────────────────────────────┘
```

## 九、关键设计决策分析

### 9.1 为什么授权流程不直接触发会话提升？

1. **关注点分离**：认证级别解决"你是谁"，会话提升解决"是你本人在操作吗"，两者关注点不同
2. **流程简洁性**：OAuth 授权流程本身已经足够复杂，不引入额外的验证步骤
3. **客户端兼容性**：标准 OAuth/OIDC 协议没有会话提升的概念，保持兼容性
4. **用户体验**：在授权流程中插入额外的验证步骤会严重破坏用户体验

### 9.2 为什么预配置缓存要求精确匹配？

1. **安全原则**：用户同意的是特定的 scope 集合，不能默认扩大授权范围
2. **避免 Scope 蔓延**：如果客户端后来增加了请求的 scope，必须重新获得用户同意
3. **可审计性**：每一次 scope 变更都有明确的用户同意记录

### 9.3 为什么隐式模式不能授予 offline_access？

1. **最小权限原则**：无感知授权不应该授予长期访问权限
2. **用户知情权**：offline_access 意味着应用可以在用户不在场时访问资源，必须明确告知
3. **风险控制**：refresh token 如果泄露，攻击者可以长期访问用户资源，需要更强的授权确认

### 9.4 为什么强制显式同意只在 code flow 下触发？

1. **技术限制**：Implicit Flow（`id_token`、`token`、`id_token token`）不支持 refresh token，因此 offline_access 等 scope 在这些流程下没有实际意义
2. **安全边界**：只有 code flow 能通过 refresh token 获得长期访问权限，因此需要更强的授权确认
3. **协议兼容**：符合 OAuth 2.0 安全最佳实践，高权限操作必须有明确的用户交互

## 十、总结

1. **OIDC 授权确认链路中，认证级别是唯一的准入条件**，会话提升不直接参与授权决策
2. **同意流程与 response type 正交**：无论哪种同意模式，最终都支持全部 7 种 response type（code / id_token / token / 各种 hybrid 组合）
3. **强制显式同意的完整触发条件**：`prompt=consent`、`prompt=login`，以及 code flow 下请求了 `offline` / `offline_access` / `authelia.bearer.authz` scope
4. **显式同意和隐式自动放行的核心差异在于 Scope 计算**：显式模式调用 `ConsentGrant(..., true, ...)` 授予所有 scope，隐式模式调用 `ConsentGrantImplicit` 排除 offline_access 等高权限 scope
5. **预配置缓存匹配由 `handleOAuth2AuthorizationConsentModePreConfiguredGetPreConfig` 驱动**，依次调用 `CanConsentAt` → `HasExactGrants` → `HasClaimsSignature` 完成精确匹配
6. **会话提升是独立于 OIDC 授权的安全机制**，用于保护敏感操作（修改密码、注册 2FA 设备等）
7. 各机制**正交但协同**，共同构成了 Authelia 的分层安全体系
