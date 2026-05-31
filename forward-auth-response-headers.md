# Authelia Forward-Auth 模式代码链路分析

## 一、整体架构

Forward-Auth 模式下，反向代理（Traefik/Caddy/Skipper 等）将用户请求转发给 Authelia 验证端点，Authelia 根据认证状态和访问控制策略返回 200/302/401/403 状态码，代理根据响应决定放行、重定向或拒绝。

```
用户请求 → 反向代理 → Authelia /api/authz/forward-auth
                     ↑           ↓
                     └── 200/302/401/403 + 响应头 ──┘
```

## 二、请求头解析链路（按代码执行顺序）

### 2.1 入口：Authz Handler 主流程

**文件**: `internal/handlers/handler_authz.go:142-238`

```go
func (authz *Authz) Handler(ctx AuthzContext) {
    // 步骤1: 解析目标对象（URL + Method）
    object, err = authz.handleGetObject(ctx)
    
    // 步骤2: 检查 URL 安全性（必须是 https/wss）
    if !utils.IsURISecure(object.URL) { ... }
    
    // 步骤3: 获取 Session Manager
    manager, err = ctx.GetSessionManagerByTargetURI(object.URL)
    
    // 步骤4: 获取 Authelia 门户 URL
    autheliaURL, err = authz.getAutheliaURL(ctx, manager)
    
    // 步骤5: 执行认证策略链
    authn, strategy, err = authz.authn(ctx, manager, &object)
    
    // 步骤6: 获取访问控制策略要求的认证级别
    ruleHasSubject, required := ctx.GetProviders().Authorizer.GetRequiredLevel(
        authorization.Subject{
            Username: authn.Details.Username,
            Groups:   authn.Details.Groups,
            IP:       ctx.RemoteIP(),  // 注意：这里使用解析后的客户端 IP
        }, object)
    
    // 步骤7: 根据认证结果处理响应
    switch isAuthzResult(authn.Level, required, ruleHasSubject) {
    case AuthzResultForbidden:  ctx.ReplyForbidden()    // 403
    case AuthzResultUnauthorized: handler(ctx, authn, redirectionURL) // 302/401
    case AuthzResultAuthorized:   authz.handleAuthorized(ctx, authn)  // 200 + 头
    }
}
```

### 2.2 Forward-Auth 模式的对象解析

**文件**: `internal/handlers/handler_authz_impl_forwardauth.go:12-33`

```go
func handleAuthzGetObjectForwardAuth(ctx AuthzContext) (object authorization.Object, err error) {
    // 读取三个核心转发头
    protocol := ctx.XForwardedProto()  // X-Forwarded-Proto
    host     := ctx.XForwardedHost()   // X-Forwarded-Host
    uri      := ctx.XForwardedURI()    // X-Forwarded-URI
    
    // 拼接成完整 URL: protocol + "://" + host + uri
    targetURL, err = getRequestURIFromForwardedHeaders(protocol, host, uri)
    
    // 读取方法头
    method = ctx.XForwardedMethod()    // X-Forwarded-Method
    if len(method) == 0 {
        return object, fmt.Errorf("header 'X-Forwarded-Method' is empty")
    }
    
    // 方法字符校验：必须是大写 A-Z
    if hasInvalidMethodCharacters(method) {
        return object, fmt.Errorf("header 'X-Forwarded-Method' with value '%s' has invalid characters", method)
    }
    
    return authorization.NewObjectRaw(targetURL, method), nil
}
```

**方法字符校验** (`internal/handlers/handler_authz_common.go:105-113`):
```go
func hasInvalidMethodCharacters(v []byte) bool {
    for _, c := range v {
        if c < 0x41 || c > 0x5A {  // ASCII 'A' (65) to 'Z' (90)
            return true
        }
    }
    return false
}
```

### 2.3 各请求头的解析约束

| 头名称 | 解析函数 | 约束条件 | 回退机制 |
|--------|---------|---------|---------|
| `X-Forwarded-Proto` | `XForwardedProto()` | 无强制校验 | 空则根据 TLS 状态回退为 `https` 或 `http` |
| `X-Forwarded-Host` | `XForwardedHost()` | 不能为空（`getXForwardedURL` 中校验） | `GetXForwardedHost()` 会回退到 `Host` 头 |
| `X-Forwarded-URI` | `XForwardedURI()` | 无强制校验 | `GetXForwardedURI()` 会回退到当前请求 URI |
| `X-Forwarded-Method` | `XForwardedMethod()` | 不能为空，必须全大写 A-Z | 无回退 |
| `X-Forwarded-For` | `RequestCtxRemoteIP()` | 取逗号分隔的第一个 IP | 空则使用直接连接 IP |

### 2.4 客户端 IP 解析

**文件**: `internal/middlewares/wrap.go:32-44`

```go
func RequestCtxRemoteIP(ctx *fasthttp.RequestCtx) net.IP {
    if header := ctx.Request.Header.PeekBytes(headerXForwardedFor); len(header) != 0 {
        ips := strings.SplitN(string(header), ",", 2)
        
        if len(ips) != 0 {
            if ip := net.ParseIP(strings.Trim(ips[0], " ")); ip != nil {
                return ip
            }
        }
    }
    
    return ctx.RemoteIP()  // 直接连接的 TCP 远端 IP
}
```

**关键细节**：
- 只取 `X-Forwarded-For` 中**第一个** IP（最左侧）
- 没有受信代理白名单检查（见第三节）
- 解析失败则回退到 TCP 连接的远端 IP

## 三、受信代理白名单机制

### 3.1 当前版本的实现状态

**重要结论**：**此版本 Authelia 代码中没有受信代理白名单（TrustedProxies）配置！**

代码搜索结果：
- 无 `TrustedProxies` 配置项
- 无 `X-Forwarded-For` 头的来源 IP 校验
- `RequestCtxRemoteIP()` 无条件信任 `X-Forwarded-For` 头的第一个值

### 3.2 安全影响与责任划分

由于 Authelia 不做受信代理校验，**必须由反向代理确保**：
1. 清理客户端发来的 `X-Forwarded-*` 系列头，防止伪造
2. 只有代理自己能设置这些头
3. 代理本身在网络层确保只有可信来源能访问 Authelia 验证端点

### 3.3 各代理头的信任模型

| 头 | 信任级别 | 说明 |
|----|---------|------|
| `X-Forwarded-Proto` | 完全信任 | 直接使用，无校验 |
| `X-Forwarded-Host` | 完全信任 | 直接使用，仅判空 |
| `X-Forwarded-URI` | 完全信任 | 直接使用，无校验 |
| `X-Forwarded-Method` | 字符级校验 | 仅检查是否为大写字母 |
| `X-Forwarded-For` | 完全信任 | 取第一个 IP，无校验 |
| `X-Original-URL` | 完全信任 | AuthRequest 模式使用 |
| `X-Original-Method` | 字符级校验 | AuthRequest 模式使用 |

## 四、不同 Authz 实现的请求头对比

**文件**: `internal/handlers/handler_authz_builder.go:128-146`

| 实现模式 | 适用代理 | 依赖的请求头 | 未授权状态码 |
|---------|---------|-------------|-------------|
| **ForwardAuth** | Traefik, Caddy, Skipper | `X-Forwarded-Proto`<br>`X-Forwarded-Host`<br>`X-Forwarded-URI`<br>`X-Forwarded-Method` | GET/HEAD/OPTIONS → 302<br>其他方法 → 303<br>XHR → 401 |
| **AuthRequest** | NGINX | `X-Original-URL`<br>`X-Original-Method` | 始终 401 + Location |
| **ExtAuthz** | Envoy | 内部 gRPC 协议，无需 HTTP 头 | 视配置而定 |
| **Legacy** | 通用（兼容） | 优先 `X-Original-URL`<br>回退 `X-Forwarded-*` | 视请求类型而定 |

### ForwardAuth vs AuthRequest 未授权处理对比

**ForwardAuth** (`handler_authz_impl_forwardauth.go:35-59`):
```go
func handleAuthzUnauthorizedForwardAuth(...) {
    switch {
    case ctx.IsXHR() || !ctx.AcceptsMIME("text/html"):
        statusCode = 401  // Unauthorized
    default:
        switch authn.Object.Method {
        case GET, OPTIONS, HEAD:
            statusCode = 302  // Found
        default:
            statusCode = 303  // See Other
        }
    }
    // 重定向到登录页，带 rd 和 rm 参数
}
```

**AuthRequest** (`handler_authz_impl_authrequest.go:39-48`):
```go
func handleAuthzUnauthorizedAuthRequest(...) {
    // 始终返回 401 + Location 头
    ctx.SpecialRedirect(redirectionURL.String(), 401)
}
```

## 五、认证策略执行链

**文件**: `internal/handlers/handler_authz.go:290-316`

```go
func (authz *Authz) authn(ctx AuthzContext, manager session.Manager, object *authorization.Object) (authn *Authn, strategy AuthnStrategy, err error) {
    for _, strategy = range authz.strategies {
        authn, err = strategy.Get(ctx, manager, object)
        if err != nil {
            authn.Level = authentication.NotAuthenticated
            if strategy.CanHandleUnauthorized() {
                return authn, strategy, err
            }
            return authn, nil, err
        }
        if authn.Level != authentication.NotAuthenticated {
            break  // 认证成功，跳出循环
        }
    }
    return authn, strategy, err
}
```

### ForwardAuth 默认策略链

**文件**: `internal/handlers/handler_authz_builder.go:123-125`

```go
case AuthzImplForwardAuth:
    authz.strategies = []AuthnStrategy{
        NewHeaderProxyAuthorizationAuthnStrategy(0, "basic"),
        NewCookieSessionAuthnStrategy(config.RefreshInterval),
    }
```

#### 策略1: HeaderProxyAuthorization

**文件**: `internal/handlers/handler_authz_authn.go:52-62, 207-295`

检查 `Proxy-Authorization` 请求头：
- 支持 `Basic` 和 `Bearer` 两种 scheme
- Basic: 用户名密码验证，调用 `UserProvider.CheckUserPassword`
- Bearer: OIDC Access Token 内省验证
- 认证失败返回 407 Proxy Auth Required

#### 策略2: CookieSession

**文件**: `internal/handlers/handler_authz_authn.go:90-147`

检查 Session Cookie：
- 从 Cookie 中读取会话信息
- 验证会话有效性、活跃度、刷新时间
- 检查 `Session-Username` 头防止 Cookie 劫持
- 认证级别：1FA 或 2FA

## 六、授权成功响应头（200 OK）

**文件**: `internal/handlers/handler_authz_common.go:60-75`

```go
func handleAuthzAuthorizedStandard(ctx AuthzContext, authn *Authn) {
    ctx.ReplyStatusCode(fasthttp.StatusOK)  // 200
    
    if authn.Details.Username != "" {
        // 用户名
        ctx.SetResponseHeaderValue(headerRemoteUser, authn.Details.Username)
        // 用户组（逗号分隔）
        ctx.SetResponseHeaderValue(headerRemoteGroups, strings.Join(authn.Details.Groups, ","))
        // 显示名称
        ctx.SetResponseHeaderValue(headerRemoteName, authn.Details.DisplayName)
        // 邮箱（第一个）
        switch len(authn.Details.Emails) {
        case 0:
            ctx.SetResponseHeaderValue(headerRemoteEmail, "")
        default:
            ctx.SetResponseHeaderValue(headerRemoteEmail, authn.Details.Emails[0])
        }
    }
}
```

**头常量定义** (`internal/handlers/const.go:27-31`):
```go
headerRemoteUser   = []byte("Remote-User")
headerRemoteGroups = []byte("Remote-Groups")
headerRemoteName   = []byte("Remote-Name")
headerRemoteEmail  = []byte("Remote-Email")
```

### 6.1 响应头详情

| 响应头 | 值来源 | 格式 | 说明 |
|--------|-------|------|------|
| `Remote-User` | `authn.Details.Username` | 字符串 | 登录用户名 |
| `Remote-Groups` | `authn.Details.Groups` | 逗号分隔字符串 | 用户所属组列表 |
| `Remote-Name` | `authn.Details.DisplayName` | 字符串 | 用户显示名称 |
| `Remote-Email` | `authn.Details.Emails[0]` | 字符串 | 用户主邮箱 |

### 6.2 反向代理如何回填这些头

Authelia 返回这些响应头后，反向代理需要将其**回填到转发给后端服务的请求头**中。各代理配置示例：

**Traefik**:
```yaml
labels:
  - "traefik.http.middlewares.authelia.forwardauth.authResponseHeaders=Remote-User, Remote-Groups, Remote-Name, Remote-Email"
  - "traefik.http.middlewares.authelia.forwardauth.authResponseHeadersRegex=^"
```

**NGINX**:
```nginx
auth_request_set $remote_user $upstream_http_remote_user;
auth_request_set $remote_groups $upstream_http_remote_groups;
proxy_set_header Remote-User $remote_user;
proxy_set_header Remote-Groups $remote_groups;
```

**Caddy**:
```caddyfile
forward_auth authelia:9091 {
    header_up X-Forwarded-Method {method}
    header_up X-Forwarded-Proto {scheme}
    header_up X-Forwarded-Host {host}
    header_up X-Forwarded-URI {uri}
    copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
}
```

## 七、未授权响应头（302/401）

### 7.1 重定向 URL 构造

**文件**: `internal/handlers/handler_authz.go:266-288`

```go
func (authz *Authz) getRedirectionURL(object *authorization.Object, autheliaURL *url.URL) (redirectionURL *url.URL) {
    redirectionURL, _ = url.ParseRequestURI(autheliaURL.String())
    
    qry := redirectionURL.Query()
    qry.Set(queryArgRD, object.URL.String())  // rd = 目标URL
    qry.Set(queryArgRM, object.Method)       // rm = 请求方法
    redirectionURL.RawQuery = qry.Encode()
    
    return redirectionURL
}
```

### 7.2 响应头

| 场景 | 状态码 | 响应头 |
|------|-------|-------|
| 浏览器请求 GET/HEAD/OPTIONS | 302 | `Location: https://auth.example.com/?rd=https%3A%2F%2Fapp.example.com%2F&rm=GET` |
| 浏览器请求 POST/PUT/DELETE | 303 | `Location: https://auth.example.com/?rd=...&rm=POST` |
| XHR/API 请求 | 401 | 无 Location 头 |
| AuthRequest 模式（所有） | 401 | `Location: https://auth.example.com/?rd=...&rm=GET` |

### 7.3 特殊重定向实现

**文件**: `internal/middlewares/authelia_context.go:655-674`

```go
func (ctx *AutheliaCtx) setSpecialRedirect(uri string, statusCode int) ([]byte, int) {
    // 允许 401 作为重定向状态码（标准 fasthttp 不允许）
    if statusCode < 301 || (statusCode > 303 && statusCode != 307 && statusCode != 308 && statusCode != 401) {
        statusCode = 302
    }
    
    ctx.SetStatusCode(statusCode)
    
    u := fasthttp.AcquireURI()
    ctx.URI().CopyTo(u)
    u.Update(uri)
    raw := u.FullURI()
    
    ctx.Response.Header.SetBytesKV(headerLocation, raw)  // 设置 Location 头
    
    return raw, statusCode
}
```

## 八、完整调用时序

```
1. 反向代理接收用户请求
   ↓
2. 代理设置 X-Forwarded-* 头，转发给 Authelia
   ├─ X-Forwarded-Proto: https
   ├─ X-Forwarded-Host: app.example.com
   ├─ X-Forwarded-URI: /protected
   ├─ X-Forwarded-Method: GET
   └─ X-Forwarded-For: 203.0.113.9, 10.0.0.1
   ↓
3. Authelia handleAuthzGetObjectForwardAuth()
   ├─ 拼接目标 URL: https://app.example.com/protected
   └─ 方法: GET
   ↓
4. Authelia authn() 执行认证策略链
   ├─ 策略1: 检查 Proxy-Authorization 头（无，跳过）
   └─ 策略2: 检查 Session Cookie
       ├─ 有 Cookie → 认证成功，级别 2FA
       └─ 无 Cookie → 认证失败，级别 NotAuthenticated
   ↓
5. Authelia GetRequiredLevel() 查访问控制策略
   ├─ 匹配规则: /protected 需要 two_factor
   └─ required = TwoFactor
   ↓
6. isAuthzResult() 判断结果
   ├─ 已认证 2FA + required 2FA → AuthzResultAuthorized (200)
   └─ 未认证 + required 2FA → AuthzResultUnauthorized (302)
   ↓
7. 生成响应
   ├─ 200 OK: 设置 Remote-User, Remote-Groups, Remote-Name, Remote-Email 头
   └─ 302 Found: 设置 Location 头到登录页，带 rd 和 rm 参数
   ↓
8. 反向代理处理 Authelia 响应
   ├─ 200: 回填 Remote-* 头到请求，转发给后端服务
   ├─ 302: 将 302 响应返回给浏览器
   └─ 401/403: 直接返回给客户端
```

## 九、关键代码位置索引

| 功能 | 文件路径 | 行号 |
|------|---------|------|
| ForwardAuth 对象解析 | `internal/handlers/handler_authz_impl_forwardauth.go` | 12-33 |
| AuthRequest 对象解析 | `internal/handlers/handler_authz_impl_authrequest.go` | 13-37 |
| Legacy 对象解析 | `internal/handlers/handler_authz_impl_legacy.go` | 12-31 |
| 主 Handler 流程 | `internal/handlers/handler_authz.go` | 142-238 |
| 认证策略链 | `internal/handlers/handler_authz.go` | 290-316 |
| 授权成功响应头 | `internal/handlers/handler_authz_common.go` | 60-75 |
| ForwardAuth 未授权处理 | `internal/handlers/handler_authz_impl_forwardauth.go` | 35-59 |
| AuthRequest 未授权处理 | `internal/handlers/handler_authz_impl_authrequest.go` | 39-48 |
| X-Forwarded-* 头常量 | `internal/middlewares/const.go` | 16-24 |
| Remote-* 响应头常量 | `internal/handlers/const.go` | 27-31 |
| 客户端 IP 解析 | `internal/middlewares/wrap.go` | 32-44 |
| XForwardedProto 解析 | `internal/middlewares/authelia_context.go` | 138-150 |
| XForwardedHost 解析 | `internal/middlewares/authelia_context.go` | 153-166 |
| XForwardedURI 解析 | `internal/middlewares/authelia_context.go` | 169-182 |
| Authz Builder 构建 | `internal/handlers/handler_authz_builder.go` | 107-149 |
| Header 认证策略 | `internal/handlers/handler_authz_authn.go` | 207-295 |
| Cookie 认证策略 | `internal/handlers/handler_authz_authn.go` | 90-147 |
| 重定向 URL 构造 | `internal/handlers/handler_authz.go` | 266-288 |
| 方法字符校验 | `internal/handlers/handler_authz_common.go` | 105-113 |

## 十、安全注意事项

1. **无受信代理白名单**：Authelia 无条件信任所有 `X-Forwarded-*` 头，必须由反向代理确保这些头不被客户端伪造
2. **方法仅做字符校验**：`X-Forwarded-Method` 只检查是否为大写字母，不校验是否为合法 HTTP 方法
3. **URL 拼接安全**：`getRequestURIFromForwardedHeaders` 使用 `url.ParseRequestURI` 解析，能防止大部分 URL 伪造攻击
4. **Session-Username 头校验**：Cookie 认证时会检查 `Session-Username` 请求头与会话用户名是否一致，防止 Cookie 劫持
5. **HTTPS 强制**：目标 URL 必须是 `https` 或 `wss` 协议，确保 Session Cookie 安全传输
