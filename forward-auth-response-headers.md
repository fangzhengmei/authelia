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
| ACL 网络规则匹配 | `internal/authorization/types.go` | 14-26 |
| ACL 规则总匹配 | `internal/authorization/access_control_rule.go` | 54-80 |
| Authorizer.GetRequiredLevel | `internal/authorization/authorizer.go` | 51-68 |
| Subject 结构体定义 | `internal/authorization/types.go` | 49-54 |
| Regulation IP 封禁检查 | `internal/regulation/regulator.go` | 135-163 |
| Regulation IP 封禁写入 | `internal/regulation/regulator.go` | 57-95 |
| Regulation 登录尝试记录 | `internal/regulation/regulator.go` | 26-55 |
| IP 速率限制桶 | `internal/middlewares/rate_limiting.go` | 98-163 |
| IP 速率限制 FetchCtx | `internal/middlewares/rate_limiting.go` | 153-155 |
| 错误处理 getRemoteIP | `internal/server/handlers.go` | 33-45 |
| AutheliaCtx.RemoteIP 委托 | `internal/middlewares/authelia_context.go` | 518-520 |
| XFF 解析测试用例 | `internal/middlewares/authelia_context_blackbox_test.go` | 34-63 |
| **会话提升 IP 绑定检查** | `internal/middlewares/require_auth.go` | 104-136 |
| 会话提升 IP 二次校验 | `internal/handlers/handler_session_elevation.go` | 88-93 |
| 会话提升 OTC 签发 | `internal/model/one_time_code.go` | 19-45 |
| 会话提升 OTC 验证查询 | `internal/handlers/handler_session_elevation.go` | 270-273 |
| 会话提升 OTC 消耗 | `internal/model/one_time_code.go` | 64-68 |
| **OIDC 授权 ACL 判定** | `internal/handlers/handler_oauth2_authorization_consent_core.go` | 35 |
| OIDC 同意授权 ACL 检查 | `internal/handlers/handler_oauth2_consent.go` | 230, 520, 694, 767 |
| OIDC 设备授权 ACL 检查 | `internal/handlers/handler_oauth2_device_authorization.go` | 162 |
| **1FA/2FA 重定向策略** | `internal/handlers/response.go` | 51-57 |
| 2FA 重定向 ACL 检查 | `internal/handlers/response.go` | 282 |
| 未授权重定向 ACL 检查 | `internal/handlers/response.go` | 404 |
| **Duo 2FA IP 传递** | `internal/handlers/handler_sign_duo.go` | 105 |
| **身份验证 JWT IP 绑定** | `internal/middlewares/identity_verification.go` | 56 |
| JWT 消耗 IP 记录 | `internal/middlewares/identity_verification.go` | 256 |
| **邮件通知 IP 记录** | `internal/handlers/util.go` | 63 |
| RequireElevated 中间件 | `internal/middlewares/require_auth.go` | 23-56 |

## 十、X-Forwarded-For 信任链深度分析

### 10.1 X-Forwarded-For 从解析到策略判定的完整代码路径

X-Forwarded-For 头解析出的客户端 IP 在 Authelia 中被**广泛用于认证与授权决策**。以下是 forward-auth 授权端点中的四个核心消费方：

```
X-Forwarded-For 头
       ↓
RequestCtxRemoteIP()  ← 取逗号分隔的第一个 IP
       ↓
AutheliaCtx.RemoteIP()
       ↓
   ┌───┴────────────────────┬────────────────────┬──────────────────────┐
   ↓                        ↓                    ↓                      ↓
ACL 网络规则匹配      Regulation IP 封禁      IP 速率限制           日志记录
(Subject.IP)         (BanCheck)             (IPRateLimitBucket)    (getRemoteIP)
```

#### 消费方1: ACL 网络规则匹配（影响授权决策）

**调用链**:
```
handler_authz.go:192-200  →  Authorizer.GetRequiredLevel()
                                ↓
authorizer.go:51-68       →  rule.IsMatch(subject, object)
                                ↓
access_control_rule.go:71 →  acr.MatchesNetworks(subject)
                                ↓
access_control_rule.go:144→  acr.Networks.IsMatch(subject)
                                ↓
types.go:14-26            →  network.Contains(subject.IP)
```

**关键代码** (`handler_authz.go:192-200`):
```go
ruleHasSubject, required := ctx.GetProviders().Authorizer.GetRequiredLevel(
    authorization.Subject{
        Username: authn.Details.Username,
        Groups:   authn.Details.Groups,
        ClientID: authn.ClientID,
        IP:       ctx.RemoteIP(),  // ← 来自 X-Forwarded-For 第一个 IP
    },
    object,
)
```

**关键代码** (`authorization/types.go:14-26`):
```go
func (a AccessControlNetworks) IsMatch(subject Subject) bool {
    if len(a) == 0 {
        return true  // 规则未配置 networks 字段 → 不做 IP 过滤，直接匹配
    }
    for _, network := range a {
        if network.Contains(subject.IP) {  // ← subject.IP 就是 X-Forwarded-For 解析值
            return true
        }
    }
    return false
}
```

**影响范围**: 当 ACL 规则配置了 `networks` 字段时，X-Forwarded-For 的值直接决定请求是否被放行/拒绝。

#### 消费方2: Regulation IP 封禁（影响登录尝试）

**调用链**:
```
handler_firstfactor_password.go:50  →  Regulator.BanCheck(ctx, username)
                                          ↓
regulator.go:136                    →  ip := model.NewIP(ctx.RemoteIP())
                                          ↓
regulator.go:140                    →  store.LoadBannedIP(ctx, ip)
                                          ↓
regulator.go:57-95                  →  handleAttemptPossibleBannedIP()
                                          ↓
regulator.go:67                     →  ip := model.NewIP(ctx.RemoteIP())
                                          ↓
regulator.go:71                     →  store.LoadRegulationRecordsByIP(ctx, ip, ...)
```

**影响范围**:
- 封禁检查：如果 X-Forwarded-For 伪造的 IP 恰好在封禁列表中，合法用户也无法登录
- 封禁记录：如果 X-Forwarded-For 伪造的 IP 不在封禁列表中，被攻击的账号不会触发 IP 封禁
- 封禁写入：封禁记录以伪造 IP 写入数据库，导致封禁完全无效

#### 消费方3: IP 速率限制（影响请求放行）

**调用链**:
```
rate_limiting.go:153-155  →  IPRateLimitBucket.FetchCtx(ctx)
                                  ↓
rate_limiting.go:154       →  l.Fetch(ctx.RemoteIP().String())
                                  ↓
rate_limiting.go:123-135   →  bucket[key]  // key = X-Forwarded-For 解析的 IP
```

**影响范围**: 速率限制以 X-Forwarded-For 解析的 IP 为键。伪造可让攻击者绕过限制，也可让伪造 IP 的合法用户被误限。

#### 消费方4: 日志记录（影响审计追踪）

**调用链**:
```
server/handlers.go:35-45  →  getRemoteIP(ctx)
                                  ↓
server/handlers.go:36-44   →  取 X-Forwarded-For 第一个 IP / RemoteIP()
                                  ↓
logging.Logger().WithField("remote_ip", getRemoteIP(ctx))
```

**影响范围**: 日志中的 IP 可能被伪造，导致安全审计时追踪到错误的来源。

### 10.2 多层代理场景下 X-Forwarded-For 的拼接语义

#### 各代理对 X-Forwarded-For 的处理行为

**单层代理（标准场景）**:
```
客户端 (203.0.113.9) → 反向代理 → Authelia
                              ↓
X-Forwarded-For: 203.0.113.9
TCP RemoteIP: 10.0.0.1 (代理内网 IP)
Authelia 解析: 203.0.113.9 ✓ 正确
```

**双层代理（CDN + 反向代理）**:
```
客户端 (203.0.113.9) → CDN (198.51.100.1) → 反向代理 → Authelia
                              ↓                    ↓
X-Forwarded-For: 203.0.113.9       X-Forwarded-For: 203.0.113.9, 198.51.100.1
TCP RemoteIP: CDN IP                                      TCP RemoteIP: 代理内网 IP
Authelia 解析: 203.0.113.9 ✓ 正确
```

Authelia 用 `SplitN(header, ",", 2)` 只取第一个值，因此在双层代理**正确拼接**的场景下仍然能得到真实客户端 IP。

#### Authelia 的 SplitN 策略分析

**关键代码** (`internal/middlewares/wrap.go:34`):
```go
ips := strings.SplitN(string(header), ",", 2)  // 最多分成 2 段
if len(ips) != 0 {
    if ip := net.ParseIP(strings.Trim(ips[0], " ")); ip != nil {
        return ip  // 只取第一段
    }
}
```

`SplitN(header, ",", 2)` 意味着：
- `"203.0.113.9"` → `["203.0.113.9"]` → 取 `203.0.113.9`
- `"203.0.113.9, 198.51.100.1"` → `["203.0.113.9", " 198.51.100.1"]` → 取 `203.0.113.9`
- `"203.0.113.9, 198.51.100.1, 10.0.0.1"` → `["203.0.113.9", " 198.51.100.1, 10.0.0.1"]` → 取 `203.0.113.9`

**结论**: 无论链路有多少层代理，只要每层代理按规范**追加**（append）到 X-Forwarded-For 末尾，Authelia 始终取最左侧（最原始）的 IP。

#### 三层及以上代理的场景

```
客户端 (203.0.113.9) → CDN → WAF → 反向代理 → Authelia

X-Forwarded-For: 203.0.113.9, 198.51.100.1, 10.0.0.5
                  ↑              ↑             ↑
                  客户端真实IP    CDN节点IP     WAF节点IP

Authelia 解析: 203.0.113.9 ✓ 仍然正确
```

**前提**: 每一层代理都必须清除客户端自行设置的 X-Forwarded-For，再追加上一跳的 IP。

### 10.3 代理侧 trusted proxies 配置不当的复现现象与风险边界

#### 风险场景1: 反向代理未清除客户端自带的 X-Forwarded-For（最常见）

**复现步骤**:
```bash
# 攻击者直接在请求中注入 X-Forwarded-For 头
curl -H "X-Forwarded-For: 10.0.0.1" \
     -H "X-Forwarded-Host: internal.example.com" \
     -H "X-Forwarded-Proto: https" \
     https://app.example.com/protected
```

**代理未清除时的头传递**:
```
客户端请求:  X-Forwarded-For: 10.0.0.1 (伪造)
代理追加后: X-Forwarded-For: 10.0.0.1, 203.0.113.9 (真实客户端IP追加到末尾)
Authelia 解析: 10.0.0.1 ← 取了伪造的值！
```

**复现现象**:
1. **ACL 绕过**: 如果规则 `networks: [10.0.0.0/8]` 允许内网访问，攻击者伪造 `10.0.0.1` 后直接绕过
2. **Regulation 绕过**: 攻击者每次请求伪造不同 IP，Regulation 的 IP 封禁完全失效
3. **速率限制绕过**: 攻击者每次请求伪造不同 IP，IP 速率限制完全失效
4. **日志污染**: 审计日志中记录的 IP 全部是伪造的，无法溯源

#### 风险场景2: Traefik `trustedIPs` 配置不完整

Traefik 的 `forwardingTimeouts` 和入口点配置中有 `trustedIPs`，决定是否信任上游传来的 X-Forwarded-For：

```yaml
# Traefik 配置示例
entryPoints:
  web:
    forwardedHeaders:
      trustedIPs:
        - "127.0.0.1/32"
        - "10.0.0.0/8"
```

**配置不当的情况**:

| 配置状态 | 客户端自带 XFF | Traefik 行为 | 传给 Authelia 的 XFF | 风险 |
|---------|--------------|-------------|---------------------|------|
| 未配置 trustedIPs | 有 | 信任并追加 | `伪造IP, 真实IP` | **高危**: Authelia 取伪造IP |
| trustedIPs 包含 CDN IP | 有 | CDN 传来的 XFF 被信任 | `原始客户端IP, CDN IP, 真实IP` | **正常** |
| trustedIPs 不含 CDN IP | 有 | 不信任，覆盖 XFF | `真实IP` | **安全但丢失原始IP** |
| trustedIPs = 0.0.0.0/0 | 有 | 信任所有来源 | `伪造IP, 真实IP` | **高危**: 等同于未配置 |

##### 风险场景2.5: trustedIPs 遗漏 CDN 节点 IP（多层代理场景的风险边界）

**架构背景**：
```
客户端 (203.0.113.9) → CDN (198.51.100.0/24 集群) → Traefik → Authelia
                          ↑
                     多个出口IP
```

**正确配置**（trustedIPs 包含所有 CDN 节点网段）：
```yaml
entryPoints:
  web:
    forwardedHeaders:
      trustedIPs:
        - "198.51.100.0/24"   # CDN 节点网段，必须完整包含所有出口
        - "10.0.0.0/8"        # 内网
```

**配置不当**（trustedIPs 遗漏 CDN 节点）：
```yaml
entryPoints:
  web:
    forwardedHeaders:
      trustedIPs:
        - "10.0.0.0/8"        # 只信任内网，遗漏 CDN 网段
```

**风险边界分析（分层说明）**：

| 子系统 | 遗漏 CDN IP 后的行为 | 可利用性 | 业务影响 | 故障排除特征 |
|--------|---------------------|---------|---------|-------------|
| **ACL 网络规则** | Traefik 不信任 CDN 传来的 XFF，会**清空并覆盖**为直接连接的 IP（即 CDN 节点 IP）。Authelia 所有请求看到的 IP 都是 CDN 出口 IP。如果规则配置了 `networks: [203.0.113.0/24]`（仅允许某办公网访问），由于所有请求看起来都来自 CDN IP，规则永远不匹配。 | ❌ 无法绕过身份验证 | ⚠️ 所有用户都被拒绝 | 快速验证：同一内网用户，经 CDN 访问被拒，直连 Traefik 正常 |
| **Regulation IP 封禁** | 登录失败尝试和封禁记录都以 CDN 节点 IP 写入。攻击者可通过切换 CDN 节点（不同出口 IP）绕过 IP 封禁。正常用户如果不巧使用了被封禁的 CDN 节点，也会被牵连拒绝。 | ⚠️ 可绕过封禁 | ⚠️ 防御降级 | 观察 `banned_ips` 表中 IP 是否都是 CDN 网段 IP |
| **IP 速率限制** | 速率限制以 CDN 节点 IP 为键。所有经同一 CDN 节点的请求共享配额，可能导致：1) 正常用户被误限（并发太多）；2) 攻击者切换节点可绕过。 | ⚠️ 可绕过限制 | ❌ 无直接安全风险 | 监控速率限制日志中的 IP 是否集中在少数几个 CDN IP |
| **日志审计** | 所有日志中 `remote_ip` 字段都是 CDN 节点 IP。安全事件发生后**完全无法溯源**到真实客户端。 | ❌ 无法绕过 | ⚠️ 合规风险 | 随机抽查日志，看 IP 是否全为 CDN 出口 IP |
| **会话提升 IP 绑定** | 会话提升时记录的 IP 是 CDN IP。CDN 智能路由可能将用户请求调度到不同节点，导致会话提升无缘无故失效。 | ❌ 无法绕过 | ❌ 用户体验问题 | 用户反馈"操作超时"，日志显示 IP 变化但会话未过期 |
| **Duo 2FA IP 传递** | Duo 风控系统收到的 IP 是 CDN 节点 IP。可能导致 Duo 风险评估异常（认为登录地点异常）。 | ❌ 无法绕过 | ❌ 可能触发额外验证 | Duo 后台日志中显示登录 IP 全为 CDN IP |

**关键边界结论**：
- ✅ **无身份伪造风险**：遗漏 CDN IP 时，Traefik 用直接连接的 IP 覆盖 XFF，**绝不会**接受客户端伪造的 IP
- ⚠️ **功能层面全面失效**：所有依赖客户端真实 IP 的功能均以 CDN 节点 IP 为准，造成 ACL 误拒、封禁失效、审计丢失
- 🔍 **故障排除快速判断法**：取一条日志的 `remote_ip`，用 `whois` 查询。如果是 CDN 厂商 IP 而非用户 ISP IP，说明配置遗漏

#### 风险场景3: Caddy `trusted_proxies` 配置不当

Caddy v2 的 `trusted_proxies` 是**站点/全局级别**指令，控制哪些上游代理的 X-Forwarded-For 被信任：

```caddyfile
# 正确位置：站点块顶部或全局 options，不是 forward_auth 块内部
trusted_proxies 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7

app.example.com {
    forward_auth authelia:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
    }
    reverse_proxy app:80
}
```

**Caddy 未配置 trusted_proxies 时的行为**：Caddy 默认不信任任何代理，会自动**清除**客户端自带的 `X-Forwarded-*` 头，再以直接连接的 IP 重新生成。这是安全的默认行为，无需额外配置即可防止客户端伪造 XFF。

**Caddy 配置不当的情况**：如果将 `trusted_proxies` 设置为 `0.0.0.0/0`（信任所有来源），等同于完全禁用防护，客户端可随意伪造 XFF。

#### 风险场景4: Authelia 端口直接暴露

如果 Authelia 的监听端口可以被非代理来源直接访问：

```
攻击者 → Authelia:9091 (直连，不经代理)
X-Forwarded-For: 10.0.0.1 (任意伪造)
TCP RemoteIP: 攻击者真实IP
Authelia 解析: 10.0.0.1 ← 取了伪造的值
```

**复现**:
```bash
# 如果 Authelia 端口未做网络隔离
curl -H "X-Forwarded-For: 10.0.0.1" \
     http://authelia-internal:9091/api/authz/forward-auth
```

#### 各场景风险等级汇总

| 风险场景 | 前提条件 | ACL 绕过 | Regulation 绕过 | 速率限制绕过 | 日志污染 | 风险等级 |
|---------|---------|---------|----------------|------------|---------|---------|
| 代理未清除客户端 XFF | 代理配置缺失 | ✅ | ✅ | ✅ | ✅ | **严重** |
| Traefik trustedIPs 过宽 | 0.0.0.0/0 | ✅ | ✅ | ✅ | ✅ | **严重** |
| Traefik trustedIPs 遗漏 CDN | 不含 CDN IP | ❌ | ⚠️ 可绕过 | ⚠️ 可绕过 | ✅ | **中-高** |
| Authelia 端口直连 | 网络隔离缺失 | ✅ | ✅ | ✅ | ✅ | **严重** |
| Caddy 未配 trusted_proxies | 默认行为 | ❌ | ❌ | ❌ | ❌ | **低** |

### 10.4 为什么 Authelia 不实现 TrustedProxies

通过代码分析，Authelia 选择不在应用层实现 TrustedProxies 的原因：

1. **架构设计哲学**: forward-auth 模式下，Authelia 只接收来自反向代理的请求，代理是**唯一**与 Authelia 建立 TCP 连接的对端。Authelia 无法区分代理发来的 X-Forwarded-For 中哪些条目是代理追加的、哪些是客户端自带的。

2. **代码中的唯一 IP 来源** (`wrap.go:32-44`): Authelia 的 `RequestCtxRemoteIP` 只做最简单的"取第一个 IP"，将信任决策完全交给代理层。

3. **server/handlers.go 中的重复实现** (`handlers.go:33-45`): 错误处理函数中有独立的 `getRemoteIP` 实现，逻辑与 `RequestCtxRemoteIP` 完全一致——都无条件取 X-Forwarded-For 的第一个值。

4. **正确的信任边界**: 代理应该：
   - 在收到客户端请求时，**先删除**客户端自带的 X-Forwarded-For
   - 然后**追加**客户端的真实 IP（TCP 连接的远端地址）
   - 这样 Authelia 收到的 X-Forwarded-For 第一个值始终是代理写入的，可信任

### 10.5 各代理的安全配置参考

#### Traefik（最关键）

```yaml
# 正确配置：只信任上一跳代理
entryPoints:
  web:
    forwardedHeaders:
      trustedIPs:
        - "10.0.0.0/8"      # 内网 CDN/WAF
        - "172.16.0.0/12"    # 内网 Docker 网络
    proxyProtocol:
      trustedIPs:
        - "10.0.0.0/8"

# forward-auth 中间件
http:
  middlewares:
    authelia:
      forwardAuth:
        address: "http://authelia:9091/api/authz/forward-auth"
        authResponseHeaders:
          - Remote-User
          - Remote-Groups
          - Remote-Name
          - Remote-Email
```

#### Caddy

**重要**：`trusted_proxies` 是**站点/全局级别**的指令，不是 `forward_auth` 块内的配置。默认情况下 Caddy **不信任任何代理**，会自动清除客户端伪造的头。仅当有上一跳代理（如 CDN）时才需要配置。

```caddyfile
## 全局/站点级别：仅在有 CDN/WAF 等上一跳代理时才需要配置
## 请务必阅读官方文档：https://www.authelia.com/integration/proxies/caddy/#trusted-proxies-and-integration-security
# trusted_proxies 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7

# Authelia 门户
auth.example.com {
    reverse_proxy authelia:9091
}

# 受保护的应用
app.example.com {
    forward_auth authelia:9091 {
        uri /api/authz/forward-auth
        copy_headers Remote-User Remote-Groups Remote-Email Remote-Name
    }

    reverse_proxy app:80
}
```

**配置说明**（与官方文档对齐）：
- Caddy 默认不信任任何代理，会自动移除客户端伪造的 `X-Forwarded-*` 头，这是安全的默认行为
- `trusted_proxies` 应在**站点块顶部**（或全局 `options` 中）配置，指定上一跳代理的 IP 段
- 官方文档建议精确配置，不要信任整个大网段，除非该网段内只有可信代理
- 受信 IP 示例：`10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7`

#### NGINX

```nginx
# 关键：先清除再设置
location / {
    # 清除客户端自带的头
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # $proxy_add_x_forwarded_for 会自动追加，但不会清除客户端自带的
    # 需要配合 set_real_ip_from 使用

    # 设置受信代理
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    auth_request /authz;
    auth_request_set $remote_user $upstream_http_remote_user;
    proxy_set_header Remote-User $remote_user;
}

location = /authz {
    internal;
    proxy_pass http://authelia:9091/api/authz/forward-auth;
    proxy_set_header X-Forwarded-Method $request_method;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-URI $request_uri;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

### 10.6 验证 X-Forwarded-For 信任链是否安全的检查清单

1. **代理是否清除客户端自带的 X-Forwarded-For？**
   - Traefik: 检查 `forwardedHeaders.trustedIPs` 是否正确配置
   - Caddy: 默认安全（forward_auth 模式下）
   - NGINX: 检查 `set_real_ip_from` + `real_ip_recursive on`

2. **Authelia 端口是否只对代理暴露？**
   - 检查网络策略/防火墙规则
   - Authelia 不应有公网可达的端口

3. **多层代理的 X-Forwarded-For 拼接顺序是否正确？**
   - 每层代理应该追加到末尾，不能前置
   - 用 `curl -v` 检查 Authelia 收到的实际头

4. **ACL 网络规则是否依赖 X-Forwarded-For？**
   - 配置 `networks` 字段的规则要意识到 IP 可能被伪造
   - 对关键资源，优先使用 `subject: [user:xxx, group:xxx]` 而非 `networks`

### 10.7 除 forward-auth 外 ctx.RemoteIP 的关键调用链

ctx.RemoteIP() 的影响范围远不止 forward-auth 授权端点。以下是所有**认证与授权判定**相关的调用链，这些调用直接影响安全决策：

---

#### 调用链A: 会话提升（Session Elevation）IP 绑定检查

**影响**：高安全操作（修改密码、修改邮箱、撤销设备等）会检查当前请求 IP 与会话提升时记录的 IP 是否一致。

**代码链路**:
```
require_auth.go:115                              ← RequireElevated 中间件
  ↓
handler_session_elevation.go:88                  ← 提升状态查询时二次校验
  ↓
if !ctx.RemoteIP().Equal(userSession.Elevations.User.RemoteIP) {
    // IP 不匹配 → 销毁提升状态 → 返回 403 Forbidden
}
```

**关键代码** (`middlewares/require_auth.go:115-119`):
```go
if !ctx.RemoteIP().Equal(userSession.Elevations.User.RemoteIP) {
    invalid = true
    ctx.Logger.WithFields(...).Warn("The user session elevation did not have a matching IP. It will be destroyed and the users access will be forbidden.")
}
```

**伪造 IP 的影响**：
- 攻击者伪造受害者 IP 后发起提升请求 → 检查通过 → 可执行高权限操作
- 合法用户切换网络（如 Wi-Fi → 4G）→ IP 变化 → 提升失效 → 需重新验证

---

#### 调用链B: OIDC 授权流程中的 ACL 策略判定

**影响**：OIDC 授权码模式、客户端凭证模式、设备授权模式均会用 ctx.RemoteIP() 判定访问控制策略。

**代码链路**（授权码流程为例）:
```
handler_oauth2_authorization_consent_core.go:35    ← 授权确认页
  ↓
handler_oauth2_consent.go:230                      ← 同意授权
  ↓
handler_oauth2_consent.go:520                      ← 再次确认
  ↓
policy.GetRequiredLevel(authorization.Subject{
    Username: userSession.Username,
    Groups:   userSession.Groups,
    IP:       ctx.RemoteIP(),    ← ← ← 用于 ACL networks 规则匹配
})
```

**关键代码** (`handler_oauth2_authorization_consent_core.go:35`):
```go
level := policy.GetRequiredLevel(authorization.Subject{
    Username: userSession.Username,
    Groups:   userSession.Groups,
    IP:       ctx.RemoteIP(),  // 直接决定 requiredLevel
})
```

**伪造 IP 的影响**：
- 如果 ACL 规则配置了 `networks: [10.0.0.0/8]`，伪造内网 IP 可绕过 policy 限制
- 影响 OIDC 所有授权模式的认证级别要求（1FA vs 2FA）

---

#### 调用链C: 1FA/2FA 重定向响应中的策略判定

**影响**：用户登录成功后的重定向 URL 安全校验。

**代码链路**:
```
response.go:51-57      ← Handle1FAResponse 1FA 登录后重定向
  ↓
response.go:282        ← Handle2FAResponse 2FA 登录后重定向
  ↓
response.go:404        ← HandleUnauthorizedResponse 未授权重定向
  ↓
_, requiredLevel := ctx.Providers.Authorizer.GetRequiredLevel(
    authorization.Subject{
        Username: username,
        Groups:   groups,
        IP:       ctx.RemoteIP(),  // ← 决定重定向 URL 的安全性
    }, authorization.NewObject(targetURL, requestMethod))
```

**伪造 IP 的影响**：
- 如果目标 URL 的 ACL 规则配置了 `networks`，伪造 IP 可改变 requiredLevel
- 可能导致"需要 2FA 才能访问"的资源被误判为"1FA 即可"

---

#### 调用链D: Duo 2FA 认证中的 IP 传递

**影响**：Duo 第三方 2FA 服务的风险评估。

**代码链路**:
```
handler_sign_duo.go:105
  ↓
remoteIP := ctx.RemoteIP().String()
  ↓
DuoPreAuth(ctx, userSession, duoAPI)  // IP 传给 Duo 做风控
  ↓
PerformDuoAuthentication(ctx, ..., remoteIP, ...)
```

**关键代码** (`handlers/handler_sign_duo.go:105`):
```go
remoteIP := ctx.RemoteIP().String()
if err := PerformDuoAuthentication(ctx, userSession, duoAPI, device, method, remoteIP, bodyJSON); err != nil {
    return err
}
```

**伪造 IP 的影响**：
- Duo 风控系统基于 IP 做地理位置异常检测，伪造 IP 可能绕过检测
- 合规审计时，Duo 日志中的登录 IP 是伪造的

---

#### 调用链E: 一次性代码（One-Time Code）IP 绑定

**影响**：会话提升 OTC 的签发与消耗 IP 记录。

**代码链路**:
```
model/one_time_code.go:39     ← 签发时记录 IssuedIP
  ↓
handler_session_elevation.go:272  ← 验证时按 IssuedIP + Username 查询
  ↓
model/one_time_code.go:67     ← 消耗时记录 ConsumedIP
  ↓
handlers/handler_session_elevation.go:433  ← 撤销时记录 RevokedIP
```

**关键代码** (`model/one_time_code.go:36-44`):
```go
return &OneTimeCode{
    PublicID:  publicID,
    IssuedAt:  ctx.GetClock().Now(),
    IssuedIP:  NewIP(ctx.RemoteIP()),  // ← 签发时绑定 IP
    ExpiresAt: ctx.GetClock().Now().Add(duration),
    Username:  username,
    Intent:    OTCIntentUserSessionElevation,
    Code:      code,
}, nil
```

**查询代码** (`handlers/handler_session_elevation.go:272`):
```go
if code, err = ctx.Providers.StorageProvider.LoadOneTimeCode(
    ctx, userSession.Username,
    model.NewIP(ctx.RemoteIP()),  // ← 验证时必须 IP 匹配
    model.OTCIntentUserSessionElevation, bodyJSON.OneTimeCode); err != nil {
```

**伪造 IP 的影响**：
- 必须同时伪造 **签发时 IP + 消耗时 IP** 才能用窃取的 OTC
- 如果攻击者在签发和消耗时伪造同一 IP → 绑定失效
- 合法用户 IP 变化 → OTC 无法使用

---

#### 调用链F: 身份验证 JWT 的 IP 绑定

**影响**：密码重置、邮箱验证等流程的 JWT 签发与消耗。

**代码链路**:
```
identity_verification.go:56   ← 签发 JWT 时记录 IP
  ↓
identity_verification.go:256  ← 消耗 JWT 时记录 IP
  ↓
handler_reset_password.go:125 ← 撤销 JWT 时记录 IP
```

**关键代码** (`middlewares/identity_verification.go:56`):
```go
verification := model.NewIdentityVerification(
    jti, identity.Username, args.ActionClaim,
    ctx.RemoteIP(),  // ← 签发时记录 IP
    ctx.Configuration.IdentityValidation.ResetPassword.JWTExpiration)
```

**伪造 IP 的影响**：
- 与 OTC 类似，签发和消耗 IP 必须匹配（由业务逻辑校验）
- 伪造 IP 可绕过 IP 绑定保护

---

#### 调用链G: 邮件通知中的 IP 记录

**影响**：用户安全通知邮件中的登录 IP 显示。

**代码链路**:
```
handlers/util.go:63
  ↓
mailOpts := session.SendLoginEventNotificationOptions{
    ...
    RemoteIP:    ctx.RemoteIP().String(),  // ← 邮件中显示的 IP
    ...
}
```

**伪造 IP 的影响**：
- 用户收到的"新设备登录"邮件中显示伪造 IP → 用户可能误以为是自己登录的
- 合规审计时，通知记录中的 IP 无效

---

#### 非 forward-auth 调用链汇总表

| 调用链 | 代码位置 | 伪造 IP 的后果 | 故障排除特征 |
|--------|---------|--------------|-------------|
| **会话提升 IP 绑定** | `require_auth.go:115` | 高权限操作可被伪造 IP 执行 | 日志出现 "session elevation did not have a matching IP" |
| **OIDC 授权 ACL** | `handler_oauth2_consent.go` | ACL networks 规则被绕过 | OIDC 应用的 2FA 要求失效 |
| **1FA/2FA 重定向策略** | `response.go:51` | 重定向 URL 安全校验被绕过 | 登录后跳转异常 |
| **Duo 2FA IP 传递** | `handler_sign_duo.go:105` | Duo 风控绕过，审计失效 | Duo 后台登录 IP 异常 |
| **OTC IP 绑定** | `one_time_code.go:39` | 会话提升 OTC IP 绑定失效 | OTC 验证失败，IP 不匹配 |
| **身份验证 JWT** | `identity_verification.go:56` | 密码重置 IP 绑定失效 | 密码重置邮件 IP 异常 |
| **邮件通知 IP** | `util.go:63` | 安全通知邮件显示伪造 IP | 用户投诉登录通知 IP 不对 |

### 10.8 分层风险影响与故障排除指南

#### 风险分层模型

根据 X-Forwarded-For 伪造可造成的影响深度，将风险分为三层：

```
┌─────────────────────────────────────────────────────────┐
│  L3: 身份伪造层 (High)                                  │
│  ACL 规则绕过 → 直接获取未授权资源访问权限               │
│  OIDC 授权 ACL 绕过 → 绕过 2FA 要求                     │
├─────────────────────────────────────────────────────────┤
│  L2: 防御绕过层 (Medium)                                │
│  Regulation 封禁绕过 → 暴力破解防护失效                  │
│  速率限制绕过 → 接口滥用防护失效                         │
│  会话提升 IP 绑定绕过 → 高权限操作防护失效               │
│  OTC/JWT IP 绑定绕过 → 令牌保护失效                     │
├─────────────────────────────────────────────────────────┤
│  L1: 日志与审计层 (Low)                                 │
│  日志污染 → 攻击溯源失效                                 │
│  邮件通知 IP 伪造 → 用户误导                             │
│  Duo IP 伪造 → 第三方风控失效                           │
└─────────────────────────────────────────────────────────┘
```

#### 各层故障排除步骤

**L3 层故障（身份伪造）排查**:
1. **现象**：内网资源被外网用户访问，或 2FA 要求的资源可直接用 1FA 访问
2. **第一步**：检查访问控制规则是否配置了 `networks` 字段
3. **第二步**：在 Authelia 日志中找 `method=GET path=/api/authz/forward-auth` 的请求，看 `remote_ip` 是否为真实客户端 IP
4. **第三步**：抓包或在代理日志中验证传给 Authelia 的 `X-Forwarded-For` 头
5. **第四步**：如果 IP 不正确，检查代理 `trustedIPs` / `trusted_proxies` 配置
6. **验证修复**：
   ```bash
   # 从外网发起请求，伪造内网 IP 头
   curl -H "X-Forwarded-For: 10.0.0.1" https://app.example.com/protected
   # 预期：被拒绝（返回 302 或 401）
   # 实际：如果返回 200 说明配置错误
   ```

**L2 层故障（防御绕过）排查**:
1. **现象**：大量登录失败但未触发 IP 封禁，或接口被高频调用未被限流
2. **第一步**：查询 `authelia.banned_ips` 表，看封禁的 IP 是否有规律（如全为伪造 IP 段）
3. **第二步**：查询 `authelia.regulation` 表，看 `attempted_at` 时间戳是否在短时间内有大量尝试
4. **第三步**：检查速率限制日志 `level=info msg="Request exceeded rate limit"`，看被限的 IP 是否为伪造 IP
5. **第四步**：检查会话提升日志中是否有 `did not have a matching IP` 警告
6. **验证修复**：
   ```bash
   # 发起登录失败请求，每次伪造不同 IP
   for i in {1..10}; do
     curl -H "X-Forwarded-For: 192.0.2.$i" -d "username=test&password=wrong" https://auth.example.com/api/firstfactor
   done
   # 预期：5 次失败后 IP 被封禁
   # 实际：如果未封禁说明 Regulation 被绕过
   ```

**L1 层故障（日志审计）排查**:
1. **现象**：安全事件后溯源时，日志中 IP 与实际不符
2. **第一步**：随机抽取 10 条日志，对 `remote_ip` 执行 `whois` 查询
3. **第二步**：如果查询结果是 CDN/云厂商 IP 而非用户 ISP IP，说明配置遗漏
4. **第三步**：检查用户反馈的"新设备登录"邮件中的 IP 是否异常
5. **验证修复**：
   ```bash
   # 从已知 IP 发起请求
   curl -v https://app.example.com/protected
   # 查看 Authelia 日志中的 remote_ip 是否匹配你的公网 IP
   ```

#### 故障排除决策树

```
收到"IP 配置可能有问题"报告
     │
     ├─→ 是否有安全事件？
     │    ├─ 是 → 走 L3 排查 → 检查 ACL 规则和授权日志
     │    └─ 否 → 继续
     │
     ├─→ 是否有登录攻击？
     │    ├─ 是 → 走 L2 排查 → 检查 banned_ips 和 regulation 表
     │    └─ 否 → 继续
     │
     ├─→ 用户是否反馈邮件 IP 不对？
     │    ├─ 是 → 走 L1 排查 → 验证日志 IP 真实性
     │    └─ 否 → 继续
     │
     └─→ 定期安全检查？
          └─→ 按 L1→L2→L3 顺序做全面验证
```

#### 常见误报排除

| 现象 | 可能原因 | 非配置问题的场景 |
|------|---------|-----------------|
| 日志中 IP 全是 10.x 内网 IP | 代理未配置 trustedIPs | 如果是纯内网部署，无公网用户 → 正常 |
| Duo 后台登录 IP 是代理 IP | 代理未将真实 IP 传给 Duo | 如果没有 CDN 仅一层代理 → 正常 |
| 会话提升频繁失效 | 用户切换网络（Wi-Fi/4G） | 移动办公场景 → 预期行为，可调整 `elevated_session.expires` |

## 十一、安全注意事项

1. **无受信代理白名单**：Authelia 无条件信任所有 `X-Forwarded-*` 头，必须由反向代理确保这些头不被客户端伪造
2. **方法仅做字符校验**：`X-Forwarded-Method` 只检查是否为大写字母，不校验是否为合法 HTTP 方法
3. **URL 拼接安全**：`getRequestURIFromForwardedHeaders` 使用 `url.ParseRequestURI` 解析，能防止大部分 URL 伪造攻击
4. **Session-Username 头校验**：Cookie 认证时会检查 `Session-Username` 请求头与会话用户名是否一致，防止 Cookie 劫持
5. **HTTPS 强制**：目标 URL 必须是 `https` 或 `wss` 协议，确保 Session Cookie 安全传输
6. **X-Forwarded-For 影响 11 个独立子系统**：
   - **L3 身份伪造层**：ACL 网络规则、OIDC 授权 ACL、1FA/2FA 重定向策略
   - **L2 防御绕过层**：Regulation IP 封禁、IP 速率限制、会话提升 IP 绑定、OTC IP 绑定、JWT IP 绑定
   - **L1 日志审计层**：日志记录、邮件通知 IP、Duo 2FA 风控 IP
7. **XFF 伪造的杀伤力不取决于 ACL 配置**：即使未使用 `networks` 规则，L2 层的 Regulation 封禁、速率限制、会话提升保护始终受影响
8. **Caddy trusted_proxies 位置易错**：`trusted_proxies` 是站点/全局级别指令，**不能**配置在 `forward_auth` 块内部
9. **多层代理必须完整配置 trustedIPs**：遗漏 CDN 节点 IP 不会导致身份伪造，但会导致所有依赖真实客户端 IP 的功能全面降级（ACL 误拒、封禁失效、审计丢失）
10. **会话提升 IP 绑定是双刃剑**：IP 绑定防止了会话劫持，但也导致移动办公场景下用户频繁被要求重新验证，需根据实际场景权衡是否通过 `elevated_session.inactivity` 调整策略
