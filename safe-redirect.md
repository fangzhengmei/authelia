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

---

## 三、登录后重定向决策流程

### 3.1 1FA 登录响应处理 (`Handle1FAResponse`)

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

### 3.2 2FA 登录响应处理 (`Handle2FAResponse`)

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

### 3.3 关键代码片段（外链回退处置）

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

### 5.1 登录成功后的完整调用链

```
FirstFactorPasswordPOST
    │
    └── Handle1FAResponse(targetURI, ...)
          │
          ├── url.ParseRequestURI(targetURI)
          │
          ├── IsSafeRedirectionTargetURI(targetURL)
          │     ├── IsURISecure(targetURI)
          │     │     └── 检查 scheme ∈ {https, wss}
          │     │
          │     └── GetCookieDomainFromTargetURI(targetURI)
          │           └── HasDomainSuffix(hostname, cookieDomain)
          │                 └── 域名后缀匹配
          │
          └── 安全检查失败时: GetDefaultRedirectionURL()
```

### 5.2 登出时的安全检查

**位置**: `internal/handlers/handler_logout.go:33-36`

```go
redirectionURL, err := url.ParseRequestURI(body.TargetURL)
if err == nil {
    responseBody.SafeTargetURL = ctx.IsSafeRedirectionTargetURI(redirectionURL)
}
```

登出时同样执行安全检查，但仅返回安全标志，由前端决定是否跳转。

### 5.3 API 级别的安全检查

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

### 7.2 注意事项

1. 域名匹配是**后缀匹配**，需注意 `example.com` 会匹配 `example.com.attacker.com` 吗？
   - 不会，因为 `HasDomainSuffix` 检查的是 `.example.com` 后缀
   - 正确的安全边界：`auth.example.com` ✓，`xexample.com` ✗

2. 默认重定向 URL 也受安全规则约束，不能配置为外部 URL

3. 2FA 场景下不会自动重定向，必须等 2FA 完成后才执行跳转决策
