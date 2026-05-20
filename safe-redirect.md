# Authelia 登录后跳转安全检查逻辑分析

## 一、核心安全检查组件分布

安全检查逻辑分散在以下模块中：

| 模块 | 文件路径 | 核心职责 |
|------|----------|----------|
| URL 工具类 | `internal/utils/url.go` | 提供基础的 URL 安全检查和域名匹配工具 |
| 中间件上下文 | `internal/middlewares/authelia_context.go` | 集成安全检查到请求上下文，结合配置判断 |
| 响应处理器 | `internal/handlers/response.go` | 登录成功后的重定向决策与回退逻辑 |
| 配置验证器 | `internal/configuration/validator/session.go` | 验证默认重定向 URL 的安全性 |

---

## 二、三层安全检查机制

### 2.1 第一层：协议安全检查 (`IsURISecure`)

**位置**: `internal/utils/url.go:39-47`

```go
func IsURISecure(uri *url.URL) bool {
    switch uri.Scheme {
    case https, wss:
        return true
    default:
        return false
    }
}
```

**规则**:
- 仅允许 `https` 和 `wss` 两种协议
- `http`、`ftp` 等其他协议均被拒绝
- 常量定义在 `internal/utils/const.go:21-22`

### 2.2 第二层：域名白名单匹配 (`HasDomainSuffix`)

**位置**: `internal/utils/url.go:57-71`

```go
func HasDomainSuffix(domain, domainSuffix string) bool {
    if domainSuffix == "" {
        return false
    }
    if domain == domainSuffix {
        return true
    }
    if (strings.HasPrefix(domainSuffix, period) && strings.HasSuffix(domain, domainSuffix)) || 
       strings.HasSuffix(domain, period+domainSuffix) {
        return true
    }
    return false
}
```

**匹配规则**:
1. **精确匹配**: `domain == domainSuffix`（如 `example.com` == `example.com`）
2. **子域匹配**: 
   - 支持 `.example.com` 格式的后缀匹配
   - 支持 `example.com` 自动匹配 `*.example.com`（通过拼接 `.` 前缀实现）

**示例**:
```
domainSuffix = "example.com"
✓ example.com          → 精确匹配
✓ auth.example.com     → 子域匹配
✗ xexample.com         → 不匹配（缺少点分隔）
✗ example.com.c        → 不匹配（后缀被污染）
```

### 2.3 第三层：结合 Session Cookie 配置的综合判断

**位置**: `internal/middlewares/authelia_context.go:286-296`

```go
func (ctx *AutheliaCtx) IsSafeRedirectionTargetURI(targetURI *url.URL) bool {
    if targetURI == nil {
        return false
    }
    if !utils.IsURISecure(targetURI) {
        return false
    }
    return ctx.GetCookieDomainFromTargetURI(targetURI) != ""
}
```

**串联逻辑**:
1. 先检查协议安全性（调用 `IsURISecure`）
2. 再检查目标域名是否在配置的 Session Cookie 域范围内（调用 `GetCookieDomainFromTargetURI`）
3. 只有两层都通过才返回 `true`

**Cookie 域匹配**: `internal/middlewares/authelia_context.go:251-265`
```go
func (ctx *AutheliaCtx) GetCookieDomainFromTargetURI(targetURI *url.URL) string {
    hostname := targetURI.Hostname()
    for _, domain := range ctx.Configuration.Session.Cookies {
        if utils.HasDomainSuffix(hostname, domain.Domain) {
            return domain.Domain
        }
    }
    return ""
}
```

**命中优先级**:
- 按 `Session.Cookies` 配置的**顺序遍历**，返回第一个匹配的域
- 配置顺序决定了优先级，先配置的域优先匹配
- 多域场景下，每个域可以有独立的默认重定向 URL

**配置示例** (`internal/suites/MultiCookieDomain/configuration.yml:66-77`):
```yaml
session:
  cookies:
    - name: 'authelia_session'
      domain: 'example.com'
      authelia_url: 'https://login.example.com:8080'
    - name: 'example2_session'
      domain: 'example2.com'
      authelia_url: 'https://login.example2.com:8080'
    - name: 'authelia_session'
      domain: 'example3.com'
      authelia_url: 'https://login.example3.com:8080'
```

### 2.4 多 Cookie 域重叠防护

**位置**: `internal/configuration/validator/session.go:154-164`

```go
func validateSessionUniqueCookieDomain(i int, config *schema.Session, domains []string, validator *schema.StructValidator) {
    var d = config.Cookies[i]
    if utils.IsStringInSliceF(d.Domain, domains, utils.HasDomainSuffix) {
        if utils.IsStringInSlice(d.Domain, domains) {
            validator.Push(fmt.Errorf(errFmtSessionDomainDuplicate, sessionDomainDescriptor(i, d)))
        } else {
            validator.Push(fmt.Errorf(errFmtSessionDomainDuplicateCookieScope, sessionDomainDescriptor(i, d)))
        }
    }
}
```

**重叠检测逻辑**:
1. 使用 `HasDomainSuffix` 作为比较函数，检测新域是否与已配置域有包含关系
2. 精确重复 → 报错："domain is a duplicate value"
3. 作用域重叠（如 `example.com` 和 `sub.example.com`）→ 报错："shares the same cookie domain scope"
4. **关键**: 此验证在配置加载阶段执行，运行时不会出现域重叠情况

---

## 三、会话域选择对回退决策的影响

### 3.1 会话域与默认重定向 URL 的绑定关系

**核心机制**: 每个 Session Cookie 域配置可以有独立的 `DefaultRedirectionURL`，当目标 URL 不安全时，回退使用的默认 URL 由**当前请求的会话域**决定，而非目标 URL 的域。

**会话域确定流程**:
```
当前请求
    │
    ▼
GetXOriginalURLOrXForwardedURL()  ── 解析请求的原始 URL
    │
    ▼
GetCookieDomainFromTargetURI()    ── 匹配 Cookie 域（按配置顺序）
    │
    ▼
GetSessionProvider()              ── 获取该域的会话提供程序
    │
    ▼
provider.Config.DefaultRedirectionURL  ── 该域对应的默认重定向 URL
```

**关键代码** (`internal/middlewares/authelia_context.go:330-345`):
```go
func (ctx *AutheliaCtx) GetSessionProvider() (provider *session.Session, err error) {
    if ctx.session == nil {
        var targetURI *url.URL
        if targetURI, err = ctx.GetXOriginalURLOrXForwardedURL(); err != nil {
            return nil, fmt.Errorf("unable to retrieve session cookie domain: %w", err)
        }
        if ctx.session, err = ctx.GetSessionProviderByTargetURI(targetURI); err != nil {
            return nil, err
        }
    }
    return ctx.session, nil
}
```

**测试验证** (`internal/middlewares/authelia_context_blackbox_test.go:1239-1257`):
```go
// X-Original-URL: https://auth.example.com/consent
// → 匹配 example.com 域
// → 返回该域的 DefaultRedirectionURL: https://www.example.com
assert.Equal(t, &url.URL{Scheme: "https", Host: "www.example.com"}, 
             mock.Ctx.GetDefaultRedirectionURL())

// X-Original-URL: https://auth.example2.com/consent  
// → 匹配 example2.com 域
// → 返回该域的 DefaultRedirectionURL: https://www.example2.com
assert.Equal(t, &url.URL{Scheme: "https", Host: "www.example2.com"}, 
             mock2.Ctx.GetDefaultRedirectionURL())
```

### 3.2 回退决策的域上下文依赖

**场景**: 用户访问 `https://app.example.com/secret` 被重定向到登录页，登录后 targetURL 为外部恶意地址 `https://evil.com`

**决策链**:
1. `IsSafeRedirectionTargetURI(https://evil.com)` → `false`（域名不匹配）
2. 触发回退逻辑：`GetDefaultRedirectionURL()`
3. `GetDefaultRedirectionURL()` 使用**当前请求的会话域**（从 X-Original-URL 或 X-Forwarded-* 头获取），而非 targetURL 的域
4. 如果当前会话域是 `example.com`，则回退到 `example.com` 配置的默认 URL

**安全意义**:
- 防止攻击者通过构造恶意 targetURL 影响回退目标
- 回退决策始终基于可信的请求上下文（代理设置的 X-Forwarded 头），而非用户可控的 targetURL

### 3.3 1FA 登录响应处理 (`Handle1FAResponse`)

**位置**: `internal/handlers/response.go:26-91`

**决策流程图**:

```
用户登录成功
    │
    ▼
targetURI 是否为空? ──是──► 使用默认重定向 URL
    │否                          │
    ▼                           ▼
解析 targetURL 失败? ──是──► 返回认证失败
    │否
    ▼
需要 2FA 认证? ──是──► 不重定向，返回 OK
    │否
    ▼
IsSafeRedirectionTargetURI? ──否──► 尝试默认重定向 URL
    │是                          │
    ▼                           ▼
返回重定向到 targetURI    默认 URL 存在且无需 2FA? ──是──► 重定向到默认 URL
                                    │否
                                    ▼
                                返回 OK（不重定向）
```

### 3.4 2FA 登录响应处理 (`Handle2FAResponse`)

**位置**: `internal/handlers/response.go:93-136`

**决策流程**:
```
2FA 验证成功
    │
    ▼
targetURI 是否为空? ──是──► 尝试默认重定向 URL
    │否                          │
    ▼                           ▼
解析 targetURL 失败? ──是──► 返回验证失败       默认 URL 存在? ──是──► 重定向到默认 URL
    │否                          │否              │否
    ▼                           ▼               ▼
IsSafeRedirectionTargetURI? ──是──► 重定向到 targetURI  返回 OK（不重定向）
    │否
    ▼
返回 OK（不重定向）
```

### 3.5 关键代码片段（外链回退处置）

**位置**: `internal/handlers/response.go:68-84`

```go
if !ctx.IsSafeRedirectionTargetURI(targetURL) {
    ctx.Logger.Debugf("Redirection URL %s is not safe", targetURI)
    
    defaultRedirectionURL := ctx.GetDefaultRedirectionURL()
    
    if !ctx.Providers.Authorizer.IsSecondFactorEnabled() && defaultRedirectionURL != nil {
        if err = ctx.SetJSONBody(redirectResponse{Redirect: defaultRedirectionURL.String()}); err != nil {
            ctx.Logger.Errorf("Unable to set default redirection URL in body: %s", err)
        }
        return
    }
    
    ctx.ReplyOK()
    return
}
```

**外链回退规则**:
1. 当目标 URL 不安全时，不直接报错，而是尝试优雅降级
2. 降级条件：未启用 2FA **且** 配置了默认重定向 URL
3. 降级策略：重定向到配置的默认 URL
4. 无默认 URL 时：返回 `{"status": "OK"}`，由前端决定跳转

### 3.6 相对地址或缺失协议的处理分支

**核心机制**: Authelia 使用 `url.ParseRequestURI` 解析 targetURL，该函数接受**绝对路径**（以 `/` 开头）或**完整 URL**（包含 scheme）。

**1FA 场景处理** (`internal/handlers/response.go:43-49`):
```go
var targetURL *url.URL
if targetURL, err = url.ParseRequestURI(targetURI); err != nil {
    ctx.Error(fmt.Errorf("unable to parse target URL %s: %w", targetURI, err), 
              messageAuthenticationFailed)
    return
}
```

**2FA 场景处理** (`internal/handlers/response.go:113-121`):
```go
if parsedURI, err = url.ParseRequestURI(targetURI); err != nil {
    ctx.Error(fmt.Errorf("unable to determine if URI '%s' is safe to redirect to: failed to parse URI '%s': %w", 
              targetURI, targetURI, err), messageMFAValidationFailed)
    return
}
```

**被拒场景与真实处置**:

| 输入示例 | `url.ParseRequestURI` 结果 | 1FA 处理分支 | 2FA 处理分支 |
|----------|---------------------------|-------------|-------------|
| `secret.html` (相对路径) | ❌ 解析失败 | 认证失败，无回退 | 验证失败，无回退 |
| `#https://bad` (无效格式) | ❌ 解析失败 | 认证失败，无回退 | 验证失败，无回退 |
| `/secret.html` (绝对路径) | ✅ 解析成功 (scheme="", path="/secret.html") | 安全检查失败 → 进入回退逻辑 | 安全检查失败 → 直接返回 OK |
| `//evil.com/secret` (协议相对) | ✅ 解析成功 (scheme="", host="evil.com", path="/secret") | 安全检查失败 → 进入回退逻辑 | 安全检查失败 → 直接返回 OK |
| `http://secure.example.com` | ✅ 解析成功 (scheme="http") | 安全检查失败 → 进入回退逻辑 | 安全检查失败 → 直接返回 OK |
| `https://evil.com` (外部域名) | ✅ 解析成功 (scheme="https") | 安全检查失败 → 进入回退逻辑 | 安全检查失败 → 直接返回 OK |

**关键差异 (核心修正)**:

1. **绝对路径 `/secret.html` 会解析成功**：
   - `url.ParseRequestURI` 接受以 `/` 开头的绝对路径作为合法的请求 URI
   - 解析后 scheme 为空字符串，`IsURISecure` 检查失败
   - 在 1FA 中进入回退逻辑，**不会直接报认证失败**

2. **双斜杠地址 `//evil.com/secret` 也会解析成功**：
   - Go 的 `url.ParseRequestURI` 将 `//` 开头的 URL 解析为协议相对 URL
   - 解析结果：scheme="", host="evil.com", path="/secret"
   - `IsURISecure` 检查失败（scheme 为空），进入安全检查与回退逻辑
   - **不会直接报认证失败**

3. **1FA 与 2FA 的回退逻辑不同**：
   - **1FA 流程**：解析成功但不安全 → 尝试回退到默认 URL（如果不需要 2FA 且有默认 URL）
   - **2FA 流程**：解析成功但不安全 → **直接返回 OK，不回退** (`internal/handlers/response.go:135`)

4. **解析失败才会直接报错**：
   - 只有当 `url.ParseRequestURI` 返回错误时，才会直接返回认证/验证失败
   - 这类场景包括：相对路径 `secret.html`、无效格式 `#https://bad`、`https//invalid-url`（缺少冒号）等

**测试验证** (`internal/handlers/handler_firstfactor_password_test.go:582-617`):
```go
// targetURL: "#https://23kjnm412jk3" → 解析失败 → 返回认证失败
s.mock.Assert200KO(s.T(), "Authentication failed. Check your credentials.")
```

**测试验证** (`internal/handlers/handler_checks_safe_redirection_test.go:100-118`):
```go
// URI: "https//invalid-url" → 解析失败（缺少冒号）→ 返回操作失败
mock.Assert200KO(t, "Operation failed.")
```

**错误消息**:
- 1FA 解析失败: `"Authentication failed. Check your credentials."`
- 2FA 解析失败: `"Authentication failed, please retry later."`

---

## 四、默认重定向 URL 的安全约束

### 4.1 配置验证规则

**位置**: `internal/configuration/validator/session.go:199-216`

默认重定向 URL 在配置阶段就会被验证，确保其自身是安全的：

| 验证项 | 要求 | 不满足时的处理 |
|--------|------|----------------|
| 绝对 URL | 必须包含协议和主机 | 报错 |
| 协议安全 | 必须是 https/wss | 报错 |
| 域范围 | 必须在 Session Cookie 域内 | 多域配置：警告并置空；单域配置：报错 |
| 重复配置 | 不能与 AutheliaURL 相同 | 报错 |

### 4.2 默认重定向 URL 的获取

**位置**: `internal/middlewares/authelia_context.go:439-446`

```go
func (ctx *AutheliaCtx) GetDefaultRedirectionURL() *url.URL {
    if provider, err := ctx.GetSessionProvider(); err == nil {
        return provider.Config.DefaultRedirectionURL
    }
    return nil
}
```

---

## 五、安全检查的调用链

### 5.1 完整的重定向决策树

```
targetURI 输入
    │
    ├─► targetURI 为空? ──是──► 使用当前域的 DefaultRedirectionURL
    │                          │
    │                          ├─► 1FA: 存在且无需 2FA? ──是──► 重定向到默认 URL
    │                          ├─► 2FA: 存在? ──是──► 重定向到默认 URL
    │                          └─► 否则 ──► 返回 OK
    │
    └─► targetURI 非空
          │
          ├─► url.ParseRequestURI() 失败? ──是──► 返回认证失败（无回退）
          │                                     （如: secret.html、#https://bad）
          │
          └─► 解析成功（如: /secret.html、//evil.com/、http://...、https://...）
                │
                ├─► 1FA 场景
                │     │
                │     ├─► 需要 2FA? ──是──► 返回 OK（等待 2FA）
                │     │
                │     └─► IsSafeRedirectionTargetURI()
                │           │
                │           ├─► 安全? ──是──► 重定向到 targetURI
                │           │
                │           └─► 不安全 ──► 外链回退逻辑
                │                       │
                │                       ├─► 无需 2FA 且有默认 URL? ──是──► 重定向到当前域的默认 URL
                │                       └─► 否则 ──► 返回 OK
                │
                └─► 2FA 场景
                      │
                      └─► IsSafeRedirectionTargetURI()
                            │
                            ├─► 安全? ──是──► 重定向到 targetURI
                            │
                            └─► 不安全 ──► 直接返回 OK（无回退！）
```

### 5.2 登录成功后的完整调用链

```
FirstFactorPasswordPOST
    │
    └── Handle1FAResponse(targetURI, ...)
          │
          ├── url.ParseRequestURI(targetURI)
          │     └── 失败直接返回认证失败（相对地址等）
          │
          ├── IsSafeRedirectionTargetURI(targetURL)
          │     ├── IsURISecure(targetURI)
          │     │     └── 检查 scheme ∈ {https, wss}
          │     │
          │     └── GetCookieDomainFromTargetURI(targetURI)
          │           └── 按配置顺序遍历 Cookies，返回第一个匹配的域
          │
          └── 安全检查失败时: GetDefaultRedirectionURL()
                └── 使用当前请求的会话域（从 X-Forwarded 头获取）
```

### 5.3 登出时的安全检查

**位置**: `internal/handlers/handler_logout.go:33-36`

```go
redirectionURL, err := url.ParseRequestURI(body.TargetURL)
if err == nil {
    responseBody.SafeTargetURL = ctx.IsSafeRedirectionTargetURI(redirectionURL)
}
```

登出时同样执行安全检查，但仅返回安全标志，由前端决定是否跳转。

### 5.4 API 级别的安全检查

**位置**: `internal/handlers/handler_checks_safe_redirection.go:42`

```go
if err = ctx.SetJSONBody(checkURIWithinDomainResponseBody{
    OK: ctx.IsSafeRedirectionTargetURI(targetURI)
}); err != nil {
    // ...
}
```

提供独立的 API 端点供前端预检查重定向 URL 的安全性。

---

## 六、测试场景验证

**位置**: `internal/suites/scenario_redirection_check_test.go:48-57`

测试用例明确了安全边界：

```go
var redirectionAuthorizations = map[string]bool{
    "https://www.google.fr":                          false, // 外部域名
    "https://public.example.com.a:8080/secret.html":  false, // 域名后缀污染
    "http://secure.example.com:8080/secret.html":     false, // 非 https 协议
    "https://secure.example.com:8080/secret.html":    true,  // 安全的内部域名
}
```

---

## 七、设计特点总结

### 7.1 安全设计优点

1. **分层防御**: 协议检查 + 域名白名单 + 配置验证，多层防护
2. **优雅降级**: 外链不直接报错，而是回退到默认 URL 或让前端处理
3. **一致复用**: `IsSafeRedirectionTargetURI` 在登录、登出、API 检查中复用
4. **配置强校验**: 默认重定向 URL 在启动时就验证安全性
5. **域隔离**: 多 cookie 域场景下，每个域的默认重定向 URL 独立配置，互不影响
6. **可信上下文**: 回退决策基于 X-Forwarded 头（代理设置），而非用户可控的 targetURL
7. **前置防护**: 配置阶段就检测 cookie 域重叠，避免运行时优先级混乱

### 7.2 关键安全边界（最终修正）

| 场景 | 1FA 处置方式 | 1FA 是否回退 | 2FA 处置方式 | 2FA 是否回退 |
|------|-------------|-------------|-------------|-------------|
| 相对路径 `secret.html` | 解析失败 → 认证失败 | ❌ 无回退 | 解析失败 → 验证失败 | ❌ 无回退 |
| 无效格式 `#https://bad` | 解析失败 → 认证失败 | ❌ 无回退 | 解析失败 → 验证失败 | ❌ 无回退 |
| 无效 URL `https//invalid-url` | 解析失败 → 认证失败 | ❌ 无回退 | 解析失败 → 验证失败 | ❌ 无回退 |
| 绝对路径 `/secret.html` | 解析成功 → 安全检查失败 → 回退 | ✅ 有回退 | 解析成功 → 安全检查失败 → 返回 OK | ❌ 无回退 |
| 协议相对 `//evil.com/secret` | 解析成功 → 安全检查失败 → 回退 | ✅ 有回退 | 解析成功 → 安全检查失败 → 返回 OK | ❌ 无回退 |
| HTTP 协议 `http://internal.com` | 解析成功 → 安全检查失败 → 回退 | ✅ 有回退 | 解析成功 → 安全检查失败 → 返回 OK | ❌ 无回退 |
| 外部域名 `https://evil.com` | 解析成功 → 安全检查失败 → 回退 | ✅ 有回退 | 解析成功 → 安全检查失败 → 返回 OK | ❌ 无回退 |
| 2FA 认证中（1FA 后） | 等待 2FA 完成 → 返回 OK | ❌ 不重定向 | - | - |

### 7.3 注意事项

1. **域名匹配是后缀匹配**:
   - `example.com` 不会匹配 `example.com.attacker.com`
   - 正确边界：`auth.example.com` ✓，`xexample.com` ✗

2. **多域优先级**:
   - 按 `Session.Cookies` 配置顺序匹配，先配置的域优先
   - 配置阶段已防止域重叠，运行时无歧义

3. **回退目标的安全性**:
   - 默认重定向 URL 也受安全规则约束，必须是 https 且在 cookie 域内
   - 回退目标由当前请求的会话域决定，与 targetURL 无关

4. **1FA 与 2FA 的回退逻辑差异（核心修正）**:
   - **1FA 流程**：解析成功但不安全 → 尝试回退到默认 URL（如果不需要 2FA 且有默认 URL）
   - **2FA 流程**：解析成功但不安全 → 直接返回 OK，**不回退** (`internal/handlers/response.go:135`)
   - 只有解析失败时，两者都会直接返回错误（无回退）

5. **绝对路径的特殊处理**:
   - `/secret.html` 这种绝对路径会被 `url.ParseRequestURI` 成功解析
   - 解析后 scheme 为空，安全检查失败，在 1FA 中会进入回退逻辑

6. **协议相对 URL 的特殊处理**:
   - `//evil.com/secret` 这种双斜杠地址会被 `url.ParseRequestURI` 成功解析
   - 解析结果：scheme 为空，host 为 `evil.com`，path 为 `/secret`
   - 安全检查失败后进入回退逻辑，**不会直接报认证失败**
   - 这是因为 `url.ParseRequestURI` 将 `//` 开头的 URL 视为合法的协议相对 URL

7. **2FA 场景**:
   - 1FA 成功后若需要 2FA，不会自动重定向
   - 必须等 2FA 完成后才执行最终跳转决策
