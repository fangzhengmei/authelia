# Bearer Token 与 OAuth2 Client 主体匹配深度分析

## 一、Bearer Token 场景下组信息的来源与传递链

### 1.1 Bearer Token 的两种模式

Authelia 的 Bearer Token 认证支持两种截然不同的模式，组信息来源完全不同：

| 模式 | Token 类型 | 身份主体 | 组信息来源 |
|------|-----------|----------|-----------|
| **用户模式** | Authorization Code / Implicit / Password | 具体用户 (Username 非空) | 从 LDAP/文件后端实时查询 |
| **客户端模式** | Client Credentials | OAuth2 客户端 (ClientID 非空) | **无组信息** |

### 1.2 用户模式 (User Mode) 组信息传递链

```
客户端携带 Bearer Token 请求
    ↓
HeaderAuthnStrategy.Get()  [handler_authz_authn.go:207]
    ├─ 解析 Authorization: Bearer <token>
    └─ handleVerifyGETAuthorizationBearer()
        ↓
handleVerifyGETAuthorizationBearerIntrospection()  [handler_authz_authn.go:573]
    ├─ provider.IntrospectToken()  ← 验证 token 有效性
    ├─ 检查 scope: authelia.bearer.authz
    ├─ 检查 audience: 请求的 URL
    ├─ osession.ClientCredentials = false  ← 用户模式
    └─ 返回: username=osession.Username, clientID="", ccs=false
        ↓
HeaderAuthnStrategy.Get() 继续处理  [handler_authz_authn.go:266-290]
    └─ default 分支 (非 Client Credentials):
        ├─ UserProvider.GetDetails(username)  ← 实时从后端获取
        │   ├─ LDAP: LDAP 搜索 + 组映射属性
        │   └─ File: 从 YAML 数据库读取
        ├─ authn.Details = *details  ← Groups 来自此处
        └─ authn.Username = details.Username
        ↓
handler_authz.go:192-200 构造 Subject
    ├─ Username: authn.Details.Username  ← 非空
    ├─ Groups: authn.Details.Groups      ← 来自后端
    ├─ ClientID: authn.ClientID           ← 空字符串
    └─ IP: ctx.RemoteIP()
        ↓
组匹配: AccessControlGroup.IsMatch()
    → utils.IsStringInSlice(groupName, subject.Groups)
```

**关键代码位置** (`handler_authz_authn.go:275-290`)：
```go
default:
    var details *authentication.UserDetails
    if details, err = ctx.GetProviders().UserProvider.GetDetails(username); err != nil {
        // 错误处理
        return authn, err
    }
    authn.Username = friendlyUsername(details.Username)
    authn.Details = *details  // Groups 信息从此处来
```

### 1.3 客户端模式 (Client Credentials) 组信息传递链

```
客户端使用 Client ID / Secret 获取 Token
    ↓
OAuth2 Token 端点: grant_type=client_credentials
    ↓
HydrateClientCredentialsFlowSessionWithAccessRequest()  [oidc/util.go:285]
    ├─ session.Subject = ""           ← 无用户
    ├─ session.ClientID = client.GetID()
    ├─ session.Claims.Subject = client.GetID()
    └─ session.ClientCredentials = true  ← 标记为客户端模式
        ↓
客户端携带 Bearer Token 请求受保护资源
    ↓
HeaderAuthnStrategy.Get()
    └─ handleVerifyGETAuthorizationBearerIntrospection()
        ├─ IntrospectToken 验证 token
        ├─ osession.ClientCredentials = true
        └─ 返回: username="", clientID=osession.ClientID, ccs=true
            ↓
HeaderAuthnStrategy.Get() 继续处理  [handler_authz_authn.go:266-272]
    └─ case ccs:  // Client Credentials 分支
        └─ authn.ClientID = clientID  // 只设置 ClientID!
        // 注意: 不调用 GetDetails(), 不设置 authn.Details!
        ↓
handler_authz.go:192-200 构造 Subject
    ├─ Username: authn.Details.Username  ← 空字符串 ""
    ├─ Groups: authn.Details.Groups      ← 空切片 []
    ├─ ClientID: authn.ClientID           ← "my-client"
    └─ IP: ctx.RemoteIP()
        ↓
组匹配: AccessControlGroup.IsMatch()
    → utils.IsStringInSlice("admins", [])  → 永远 false!
```

**关键代码位置** (`handler_authz_authn.go:266-272`)：
```go
switch {
case ccs:  // Client Credentials 模式
    if len(clientID) == 0 {
        return authn, fmt.Errorf("failed to determine client id")
    }
    authn.ClientID = clientID
    // 这里没有调用 GetDetails()!
    // authn.Details 保持零值: Username="", Groups=[]
case len(username) == 0:
    // ...
default:
    // 用户模式才调用 GetDetails()
}
```

**重要结论**：Client Credentials 模式下，`Subject.Groups` **永远为空**，所有 `group:` 规则对客户端模式的请求都不生效。

---

## 二、ClientID 存在时匿名判断的逻辑交互（关键 Bug）

### 2.1 IsAnonymous 的判定逻辑

`internal/authorization/types.go:62-64`：
```go
func (s Subject) IsAnonymous() bool {
    return s.Username == "" && len(s.Groups) == 0
}
```

**问题**：`IsAnonymous()` 只检查 `Username` 和 `Groups`，**完全不考虑 `ClientID` 是否存在**！

### 2.2 Client Credentials 模式下的矛盾状态

对于 Client Credentials 请求，构造的 `Subject` 是：
```go
Subject{
    Username: "",           // 空字符串
    Groups:   []string{},   // 空切片
    ClientID: "my-client",  // 非空！
    IP:       net.IP{...},
}
```

但 `IsAnonymous()` 返回 `true`，因为 `Username == "" && len(Groups) == 0`。

**矛盾点**：
- 从认证角度：请求已通过 OAuth2 token 验证，有明确的客户端身份 (`ClientID`)
- 从 `IsAnonymous()` 角度：被判定为匿名用户
- 从语义角度："已认证的客户端" 和 "匿名用户" 是矛盾的

### 2.3 对 MatchesSubjects 的影响

`internal/authorization/access_control_rule.go:149-155`：
```go
func (acr *AccessControlRule) MatchesSubjects(subject Subject) (match bool) {
    if subject.IsAnonymous() {
        return true  // 匿名用户直接通过主体检查！
    }
    return acr.MatchesSubjectExact(subject)
}
```

**Bug 表现**：Client Credentials 请求虽然有 `ClientID`，但因为 `IsAnonymous() == true`，所以：
1. `MatchesSubjects()` 直接返回 `true`
2. **跳过了所有主体约束检查**，包括 `oauth2:client:` 规则！
3. 即使规则配置了 `subject: ["oauth2:client:trusted-app"]`，**任何客户端都能通过**

### 2.4 对 isAuthzResult 的影响

`internal/handlers/handler_authz_util.go:28-43`：
```go
func isAuthzResult(level authentication.Level, required authorization.Level, ruleHasSubject bool) AuthzResult {
    switch {
    case required == authorization.Bypass:
        return AuthzResultAuthorized
    case required == authorization.Denied && (level != authentication.NotAuthenticated || !ruleHasSubject):
        return AuthzResultForbidden
    // ...
    default:
        return AuthzResultUnauthorized
    }
}
```

Client Credentials 模式下：
- `level = authentication.OneFactor`（来自 `handleVerifyGETAuthorizationBearerIntrospection:631`）
- 所以 `level != authentication.NotAuthenticated` 为 `true`
- 结果：`Denied` 策略 → `AuthzResultForbidden` (403)

**与真正匿名用户的区别**：
| 场景 | IsAnonymous() | authn.Level | Denied 策略结果 |
|------|---------------|-------------|-----------------|
| 真正匿名用户 (无 token) | true | NotAuthenticated | ruleHasSubject → Unauthorized |
| Client Credentials | true | OneFactor | 总是 → Forbidden |

Client Credentials 请求虽然被 `IsAnonymous()` 判定为匿名，但认证级别是 `OneFactor`，所以在 Denied 策略下会直接返回 403，而不是 302 重定向。

---

## 三、OAuth2 客户端规则的反例边界

### 3.1 AccessControlClient 匹配器本身是正确的

`internal/authorization/access_control_subjects.go:58-61`：
```go
func (acc AccessControlClient) IsMatch(subject Subject) (match bool) {
    return acc.ID == subject.ClientID
}
```

匹配器逻辑本身没问题：`ClientID` 相等则匹配。

### 3.2 问题：匹配器永远不会被调用

问题出在调用链的上游：

```
IsMatch()
    ↓
MatchesSubjects(subject)
    ↓
subject.IsAnonymous() → true  ← Client Credentials 在此短路
    ↓
return true  ← 直接返回，不调用 MatchesSubjectExact()
    ↓
// AccessControlClient.IsMatch() 永远不会执行！
```

### 3.3 反例验证

**配置**：
```yaml
access_control:
  rules:
    - domain: api.example.com
      subject: "oauth2:client:trusted-app"
      policy: bypass
```

**测试场景 1：正确的 ClientID**
```go
subject := Subject{
    ClientID: "trusted-app",
    Username: "",
    Groups:   []string{},
}
```

**预期**：匹配成功（ClientID 正确）
**实际**：匹配成功（但原因是 `IsAnonymous()=true` 绕过了检查）

**测试场景 2：错误的 ClientID**
```go
subject := Subject{
    ClientID: "malicious-app",  // 不是 trusted-app
    Username: "",
    Groups:   []string{},
}
```

**预期**：匹配失败（ClientID 不正确）
**实际**：**匹配成功！** 原因是 `IsAnonymous()=true` 直接返回 true，**完全绕过了 ClientID 检查**

**测试场景 3：有用户名的 OAuth2 客户端（用户模式）**
```go
subject := Subject{
    ClientID: "malicious-app",
    Username: "john",  // 非空
    Groups:   []string{"users"},
}
```

**预期**：匹配失败（ClientID 不正确）
**实际**：匹配失败（因为 `IsAnonymous()=false`，会执行 `MatchesSubjectExact()` → `AccessControlClient.IsMatch()` 正确返回 false）

### 3.4 现有测试用例的误判

`authorizer_test.go:82-85` 中的测试用例：
```go
var OAuth2UserClientAClient = Subject{
    ClientID: "a_client",
    IP:       net.ParseIP("127.0.0.1"),
    // 注意: Username 和 Groups 都没设置！
}
```

测试用例 (`authorizer_test.go:370`)：
```go
tester.CheckAuthorizations(s.T(), OAuth2UserClientAClient, 
    "https://protected.example.com/", fasthttp.MethodGet, OneFactor)
```

对应的规则：
```go
WithRule(schema.AccessControlRule{
    Domains:  []string{"protected.example.com"},
    Policy:   oneFactor,
    Subjects: [][]string{{"oauth2:client:a_client"}},
})
```

**测试通过的原因是错误的**：
- 不是因为 `oauth2:client:a_client` 匹配成功
- 而是因为 `OAuth2UserClientAClient.IsAnonymous() == true`，主体检查被跳过了

**验证反例**：如果创建 `Subject{ClientID: "wrong_client"}`，测试同样会通过，因为匿名判断短路了。

### 3.5 Bug 的安全影响

| 场景 | 预期行为 | 实际行为 | 安全影响 |
|------|---------|----------|---------|
| ClientID 正确 | 通过 | 通过 (但原因错误) | - |
| ClientID 错误 | 拒绝 | **通过** | 严重：任何客户端都能绕过 oauth2:client 检查 |
| 客户端访问 deny 规则 | 403 Forbidden | 403 Forbidden | 正确 (因为 authn.Level=OneFactor) |
| 客户端访问 one_factor 规则 | 检查 ClientID | **跳过检查** | 严重 |

---

## 四、Client Credentials 模式下的完整授权流程

### 4.1 Token 获取流程

```
客户端
  POST /api/oidc/token
  Content-Type: application/x-www-form-urlencoded
  
  grant_type=client_credentials
  &client_id=my-app
  &client_secret=xxxx
  &scope=authelia.bearer.authz
    ↓
handler_oauth2_token.go: 处理 token 请求
    ├─ 验证 client_id / client_secret
    └─ 调用 HandleTokenEndpointRequest()
        ↓
oidc 包: Client Credentials 流程
    └─ HydrateClientCredentialsFlowSessionWithAccessRequest()  [oidc/util.go:285]
        ├─ session.Subject = ""
        ├─ session.ClientID = "my-app"
        ├─ session.Claims.Subject = "my-app"
        └─ session.ClientCredentials = true  ← 关键标记
            ↓
返回 access_token
  {
    "access_token": "xxx",
    "token_type": "bearer",
    "expires_in": 3600
  }
```

### 4.2 使用 Token 访问受保护资源

```
客户端
  GET /api/protected
  Authorization: Bearer xxx
    ↓
HeaderAuthnStrategy.Get()  [handler_authz_authn.go:207]
    ├─ value = "Bearer xxx"
    ├─ authz.ParseBytes(value)  → scheme=Bearer
    └─ handleVerifyGETAuthorizationBearer(ctx, authn, object)
        ↓
handleVerifyGETAuthorizationBearer()  [handler_authz_authn.go:557]
    ├─ oidc.IsAccessToken(ctx, tokenValue)  → true
    └─ handleVerifyGETAuthorizationBearerIntrospection()
        ↓
handleVerifyGETAuthorizationBearerIntrospection()  [handler_authz_authn.go:573]
    ├─ IntrospectToken(token)  → 验证 token 有效性
    ├─ 检查 scope: 必须包含 authelia.bearer.authz
    ├─ 检查 audience: 必须包含请求的 URL
    ├─ osession, ok = fsession.(*oidc.Session)
    ├─ 检查 client 已注册且包含 authelia.bearer.authz scope
    ├─ osession.ClientCredentials == true
    │
    └─ 返回: username="", clientID=osession.ClientID, ccs=true, level=OneFactor
        ↓
HeaderAuthnStrategy.Get() 继续  [handler_authz_authn.go:266]
    └─ switch:
        case ccs:  // Client Credentials 分支
            authn.ClientID = clientID  // 只设置 ClientID
            // 不设置 Username, Details
        ↓
handler_authz.go:192-200 构造 Subject
    Subject{
        Username: authn.Details.Username,  // ""
        Groups:   authn.Details.Groups,    // []
        ClientID: authn.ClientID,           // "my-app"
        IP:       ctx.RemoteIP(),
    }
        ↓
Authorizer.GetRequiredLevel(subject, object)  [authorizer.go:51]
    for _, rule := range p.rules {
        if rule.IsMatch(subject, object) {
            // 进入匹配逻辑
            ↓
            rule.IsMatch()  [access_control_rule.go:54]
                MatchesDomains()
                MatchesResources()
                MatchesQuery()
                MatchesMethods()
                MatchesNetworks()
                MatchesSubjects(subject)
                    ↓
                    subject.IsAnonymous() → true  ← 此处短路！
                    return true  ← 直接返回
                    // 不检查 oauth2:client:xxx 规则！
            ↓
            return rule.HasSubjects, rule.Policy
        }
    }
        ↓
isAuthzResult(authn.Level, required, ruleHasSubject)
    level = OneFactor  (不是 NotAuthenticated)
    ↓
    required == Denied && (true || ...) → true
    → AuthzResultForbidden  (如果是 deny 策略)
```

### 4.3 关键数据流总结

| 阶段 | Username | Groups | ClientID | IsAnonymous() | authn.Level |
|------|----------|--------|----------|---------------|-------------|
| Token 签发 | "" | N/A | "my-app" | - | - |
| Introspection 后 | "" | N/A | "my-app" | - | - |
| 构造 Authn | "" | [] | "my-app" | - | OneFactor |
| 构造 Subject | "" | [] | "my-app" | **true** | - |

**矛盾点**：
- `authn.Level = OneFactor` 表示已认证
- `subject.IsAnonymous() = true` 表示匿名
- 两者同时成立是逻辑上的矛盾

---

## 五、Bug 修复建议

### 5.1 方案 A：修正 IsAnonymous() 的定义

**问题根源**：`IsAnonymous()` 不考虑 `ClientID`。

**修复方案**：
```go
// 修复前
func (s Subject) IsAnonymous() bool {
    return s.Username == "" && len(s.Groups) == 0
}

// 修复后
func (s Subject) IsAnonymous() bool {
    return s.Username == "" && len(s.Groups) == 0 && s.ClientID == ""
}
```

**影响**：
- Client Credentials 请求的 `IsAnonymous()` 变为 `false`
- `MatchesSubjects()` 会调用 `MatchesSubjectExact()`
- `oauth2:client:xxx` 规则能够正确匹配

### 5.2 方案 B：在 MatchesSubjects 中单独处理客户端身份

保持 `IsAnonymous()` 不变，在 `MatchesSubjects()` 中增加对客户端的判断：

```go
func (acr *AccessControlRule) MatchesSubjects(subject Subject) (match bool) {
    // 客户端身份请求不视为匿名，需要检查主体约束
    if subject.ClientID != "" {
        return acr.MatchesSubjectExact(subject)
    }
    
    if subject.IsAnonymous() {
        return true
    }

    return acr.MatchesSubjectExact(subject)
}
```

### 5.3 方案 C：在 handler 层面确保 Client Credentials 有"虚拟"身份

在构造 Subject 时，为 Client Credentials 模式设置一个非空的 Username（如使用 ClientID 作为 Username）：

```go
// handler_authz.go:192-200
ruleHasSubject, required := ctx.GetProviders().Authorizer.GetRequiredLevel(
    authorization.Subject{
        Username: func() string {
            if authn.ClientID != "" && authn.Details.Username == "" {
                return "client:" + authn.ClientID  // 虚拟用户名
            }
            return authn.Details.Username
        }(),
        Groups:   authn.Details.Groups,
        ClientID: authn.ClientID,
        IP:       ctx.RemoteIP(),
    },
    object,
)
```

---

## 六、完整的主体匹配真值表

### 6.1 当前实现 (有 Bug)

| Subject 状态 | IsAnonymous() | MatchesSubjects | 检查 oauth2:client? |
|--------------|---------------|-----------------|---------------------|
| 真正匿名 (无 token) | true | true (跳过) | ❌ 否 |
| ClientID=xxx, Username="" | **true** | **true (跳过)** | ❌ 否 |
| ClientID="", Username="john" | false | 调用 Exact | ✅ 是 |
| ClientID=xxx, Username="john" | false | 调用 Exact | ✅ 是 |

### 6.2 修复后 (方案 A)

| Subject 状态 | IsAnonymous() | MatchesSubjects | 检查 oauth2:client? |
|--------------|---------------|-----------------|---------------------|
| 真正匿名 (无 token) | true | true (跳过) | ❌ 否 |
| ClientID=xxx, Username="" | **false** | 调用 Exact | ✅ 是 |
| ClientID="", Username="john" | false | 调用 Exact | ✅ 是 |
| ClientID=xxx, Username="john" | false | 调用 Exact | ✅ 是 |

---

## 七、总结

### 7.1 关键发现

1. **Client Credentials 模式下无组信息**：`Subject.Groups` 永远为空，所有 `group:` 规则都不生效
2. **IsAnonymous() 的 Bug**：不检查 `ClientID`，导致有 ClientID 的请求被判定为匿名
3. **oauth2:client 规则从未生效**：由于匿名判断短路，Client Credentials 请求绕过了所有主体约束检查
4. **测试用例误判**：现有测试通过的原因是错误的（匿名跳过而非正确匹配）
5. **authn.Level 与 IsAnonymous 的矛盾**：Client Credentials 既是 `OneFactor` 又是 "匿名"

### 7.2 安全等级

- **严重程度**：高
- **影响范围**：所有使用 `oauth2:client:` 主体规则的部署
- **实际影响**：任何有效的 Client Credentials Token 都能绕过 `oauth2:client:` 限制

### 7.3 临时规避方案

在修复之前，可以通过以下方式规避：

1. **避免使用 oauth2:client 规则**：改用其他匹配条件（域名、路径、网络等）
2. **使用 deny 策略兜底**：deny 策略对 Client Credentials 请求会正确返回 403（因为 authn.Level=OneFactor）
3. **客户端隔离**：为不同客户端使用不同的 scope，在 OAuth2 层面进行限制
