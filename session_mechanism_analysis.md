# Authelia 会话机制源码分析

本文档对 Authelia 项目中会话凭据的发放、域名匹配、后端存储及续期机制进行源码层面的梳理。

## 1. Cookie 属性根据多站点配置的组装逻辑

### 1.1 配置结构

会话配置采用分层结构，支持多域名独立配置：

```go
// internal/configuration/schema/session.go:10-42
type Session struct {
    SessionCookieCommon `koanf:",squash"`
    Secret  string          // 加密密钥
    Cookies []SessionCookie // 多域名cookie配置
    Redis   *SessionRedis   // Redis存储配置
}

type SessionCookie struct {
    SessionCookieCommon `koanf:",squash"`
    Domain                string   // Cookie域名
    AutheliaURL           *url.URL // Authelia服务URL
    DefaultRedirectionURL *url.URL // 默认重定向URL
}

type SessionCookieCommon struct {
    Name       string        // Cookie名称，默认authelia_session
    SameSite   string        // SameSite策略：lax/strict/none
    Expiration time.Duration // 会话过期时间，默认1小时
    Inactivity time.Duration // 非活动超时，默认5分钟
    RememberMe time.Duration // Remember Me过期时间，默认30天
}
```

### 1.2 Cookie 属性组装流程

**入口函数**：`NewProviderConfig()` [internal/session/provider_config.go:22-74]

```go
func NewProviderConfig(config schema.SessionCookie, providerName string, serializer Serializer) ProviderConfig {
    c := session.NewDefaultConfig()
    
    // 1. 会话ID生成器：32字节安全随机数
    c.SessionIDGeneratorFunc = func() []byte {
        bytes := make([]byte, 32)
        _, _ = rand.Read(bytes)
        // 映射到安全字符集
        for i, b := range bytes {
            bytes[i] = randomSessionChars[b%byte(len(randomSessionChars))]
        }
        return bytes
    }
    
    // 2. 基础属性设置
    c.CookieName = config.Name           // Cookie名称
    c.Domain = config.Domain             // Cookie域名
    c.Expiration = config.Expiration     // 过期时间
    
    // 3. SameSite策略映射
    switch config.SameSite {
    case "strict":
        c.CookieSameSite = fasthttp.CookieSameSiteStrictMode
    case "none":
        c.CookieSameSite = fasthttp.CookieSameSiteNoneMode
    case "lax":
    default:
        c.CookieSameSite = fasthttp.CookieSameSiteLaxMode
    }
    
    // 4. 强制安全设置
    c.Secure = true  // 仅HTTPS传输
    c.IsSecureFunc = func(*fasthttp.RequestCtx) bool {
        return true  // 始终视为安全连接
    }
    
    // 5. 序列化器（仅Redis模式启用加密）
    if serializer != nil {
        c.EncodeFunc = serializer.Encode
        c.DecodeFunc = serializer.Decode
    }
    
    return ProviderConfig{c, providerName}
}
```

### 1.3 多站点会话提供者初始化

**入口函数**：`NewProvider()` [internal/session/provider.go:19-47]

```go
func NewProvider(config schema.Session, certPool *x509.CertPool) *Provider {
    // 创建存储后端和序列化器
    name, p, s, err := NewSessionProvider(config, certPool)
    
    provider := &Provider{
        sessions: map[string]*Session{},
    }
    
    // 为每个域名创建独立的会话实例
    for _, dconfig := range config.Cookies {
        _, holder, _ := NewProviderConfigAndSession(dconfig, name, s, p)
        provider.sessions[dconfig.Domain] = &Session{
            Config:        dconfig,
            sessionHolder: holder,
        }
    }
    
    return provider
}
```

**关键特性**：
- 每个域名对应独立的 `*Session` 实例
- 多个域名可以共享同一个存储后端（Redis）
- 每个域名有独立的cookie配置（名称、过期时间等）

---

## 2. 不同存储后端的抽象及其差异

### 2.1 Provider 接口抽象

Authelia 使用 `github.com/fasthttp/session/v2` 库的 `Provider` 接口：

```go
// 由fasthttp/session库定义的接口
type Provider interface {
    Get(id []byte) ([]byte, error)
    Save(id, data []byte, expiration time.Duration) error
    Regenerate(id, newID []byte, expiration time.Duration) error
    Destroy(id []byte) error
    Count() (count int)
    NeedGC() bool
    GC() error
}
```

### 2.2 内存存储后端 (Memory Provider)

**实现文件**：`internal/session/memory/provider.go`

```go
type Provider struct {
    config Config
    db     Map  // 并发安全的Map（基于sync.Map优化）
}

type item struct {
    data           []byte        // 会话数据
    lastActiveTime int64         // 最后活动时间（纳秒）
    expiration     time.Duration // 过期时长
}
```

**核心方法**：

| 方法 | 实现要点 |
|------|---------|
| `Get()` | 从sync.Map读取，O(1)复杂度 |
| `Save()` | 存储到sync.Map，更新lastActiveTime |
| `Regenerate()` | 原子操作：LoadAndDelete旧key + Store新key |
| `Destroy()` | LoadAndDelete，对象池复用item |
| `NeedGC()` | 始终返回true |
| `GC()` | 遍历所有条目，删除过期会话（lastActiveTime + expiration < now） |

**特点**：
- 基于Go标准库 `sync.Map` 优化实现（`internal/session/memory/stdlib.go`）
- 使用对象池 `sync.Pool` 复用 `item` 对象，减少GC压力
- 单实例适用，不支持分布式部署
- 无持久化，进程重启会话丢失

### 2.3 Redis 存储后端

**实现**：`github.com/fasthttp/session/v2/providers/redis`

**配置入口**：`NewSessionProvider()` [internal/session/provider_config.go:96-178]

```go
func NewSessionProvider(config schema.Session, certPool *x509.CertPool) (name string, provider session.Provider, serializer Serializer, err error) {
    switch {
    case config.Redis != nil:
        // Redis模式启用加密序列化器
        serializer = NewEncryptingSerializer(config.Secret)
        
        // 支持TLS配置
        var tlsConfig *tls.Config
        if config.Redis.TLS != nil {
            tlsConfig = utils.NewTLSConfig(config.Redis.TLS, certPool)
        }
        
        // 高可用模式（Redis Sentinel）
        if config.Redis.HighAvailability != nil && config.Redis.HighAvailability.SentinelName != "" {
            name = "redis-sentinel"
            provider, err = redis.NewFailover(redis.FailoverConfig{
                MasterName:       config.Redis.HighAvailability.SentinelName,
                SentinelAddrs:    addrs,
                Username:         config.Redis.Username,
                Password:         config.Redis.Password,
                DB:               config.Redis.DatabaseIndex,
                KeyPrefix:        "authelia-session",
                // ... 连接池配置
            })
        } else {
            // 普通Redis模式
            name = "redis"
            provider, err = redis.New(redis.Config{
                Network:  network,  // tcp或unix
                Addr:     addr,
                KeyPrefix: "authelia-session",
                // ... 其他配置
            })
        }
    default:
        // 默认内存模式
        name = "memory"
        provider, err = memory.New(memory.Config{})
    }
    return
}
```

### 2.4 加密序列化器

**实现文件**：`internal/session/encrypting_serializer.go`

```go
type EncryptingSerializer struct {
    key [32]byte  // AES-256密钥
}

func NewEncryptingSerializer(secret string) *EncryptingSerializer {
    key := sha256.Sum256([]byte(secret))  // 派生密钥
    return &EncryptingSerializer{key}
}

// 编码流程：Msgpack序列化 -> AES-GCM加密
func (e *EncryptingSerializer) Encode(src session.Dict) (data []byte, err error) {
    dst, _ := src.MarshalMsg(nil)           // Msgpack序列化
    data, err = utils.Encrypt(dst, &e.key)  // AES-GCM加密
    return
}

// 解码流程：AES-GCM解密 -> Msgpack反序列化
func (e *EncryptingSerializer) Decode(dst *session.Dict, src []byte) (err error) {
    data, _ := utils.Decrypt(src, &e.key)   // AES-GCM解密
    _, err = dst.UnmarshalMsg(data)         // Msgpack反序列化
    return
}
```

### 2.5 存储后端对比

| 特性 | Memory | Redis | Redis Sentinel |
|------|--------|-------|---------------|
| 分布式支持 | ❌ | ✅ | ✅ |
| 持久化 | ❌ | ✅（RDB/AOF） | ✅ |
| 数据加密 | ❌ | ✅（AES-GCM-256） | ✅（AES-GCM-256） |
| 高可用 | ❌ | ❌（单节点） | ✅ |
| 连接池 | ❌ | ✅ | ✅ |
| 适用场景 | 开发测试 | 单实例生产 | 高可用生产 |
| 会话共享 | 单实例 | 多实例共享 | 多实例共享 |

---

## 3. 跨域共享会话的安全限制

### 3.1 域名匹配机制

**域名匹配入口**：`GetCookieDomainFromTargetURI()` [internal/middlewares/authelia_context.go:251-265]

```go
func (ctx *AutheliaCtx) GetCookieDomainFromTargetURI(targetURI *url.URL) string {
    hostname := targetURI.Hostname()
    
    // 遍历配置的所有cookie域名，按配置顺序匹配
    for _, domain := range ctx.Configuration.Session.Cookies {
        if utils.HasDomainSuffix(hostname, domain.Domain) {
            return domain.Domain
        }
    }
    return ""
}
```

**域名后缀匹配算法**：`HasDomainSuffix()` [internal/utils/url.go:57-71]

```go
func HasDomainSuffix(domain, domainSuffix string) bool {
    if domainSuffix == "" {
        return false
    }
    // 精确匹配
    if domain == domainSuffix {
        return true
    }
    // 后缀匹配：支持 .example.com 或 example.com 匹配子域名
    if (strings.HasPrefix(domainSuffix, ".") && strings.HasSuffix(domain, domainSuffix)) || 
       strings.HasSuffix(domain, "."+domainSuffix) {
        return true
    }
    return false
}
```

**匹配示例**：
- `example.com` 匹配 `example.com`、`app.example.com`、`sub.app.example.com`
- `.example.com` 匹配 `app.example.com`、`sub.app.example.com`，但不匹配 `example.com`

### 3.2 会话域绑定验证

**验证位置1**：`GetSession()` [internal/middlewares/authelia_context.go:392-404]

```go
func (ctx *AutheliaCtx) GetSession() (userSession session.UserSession, err error) {
    // ... 获取会话 ...
    
    // 验证会话中存储的CookieDomain与当前请求域名是否匹配
    if userSession.CookieDomain != provider.Config.Domain {
        ctx.Logger.Warnf("Destroying session cookie as the cookie domain '%s' does not match "+
            "the requests detected cookie domain '%s' which may be a sign a user tried to move "+
            "this cookie from one domain to another", 
            userSession.CookieDomain, provider.Config.Domain)
        
        // 销毁可疑会话并创建新会话
        provider.DestroySession(ctx.RequestCtx)
        userSession = provider.NewDefaultUserSession()
        provider.SaveSession(ctx.RequestCtx, userSession)
    }
    return
}
```

**验证位置2**：`CookieSessionAuthnStrategy.Get()` [internal/handlers/handler_authz_authn.go:103-115]

```go
func (s *CookieSessionAuthnStrategy) Get(ctx AuthzContext, manager session.Manager, _ *authorization.Object) (authn *Authn, err error) {
    // ... 获取会话 ...
    
    // 同样的域绑定验证
    if userSession.CookieDomain != manager.GetSessionConfig().Domain {
        manager.DestroySession()
        // ... 创建新会话 ...
    }
    // ...
}
```

**安全设计意图**：
- 防止用户将一个域的cookie手动迁移到另一个域
- 每个域的会话相互隔离，即使cookie值相同也无法跨域使用
- CookieDomain在会话创建时设置，后续不可修改

### 3.3 Cookie 安全属性强制

| 属性 | 强制值 | 说明 |
|------|--------|------|
| Secure | `true` | 仅通过HTTPS传输，防止中间人攻击窃取 |
| SameSite | `lax`/`strict`/`none` | 防止CSRF攻击，none时必须配合Secure |
| HttpOnly | 由fasthttp/session库设置 | 防止XSS攻击读取cookie |
| Domain | 配置值 | 限制cookie作用域 |
| Path | `/` | 由fasthttp/session库默认设置 |

---

## 4. 注销与失效的传播路径

### 4.1 主动注销流程

**入口**：`LogoutPOST()` [internal/handlers/handler_logout.go:19-46]

```go
func LogoutPOST(ctx *middlewares.AutheliaCtx) {
    body := logoutBody{}
    ctx.ParseBody(&body)
    
    // 核心注销操作
    err = ctx.DestroySession()
    
    // 安全重定向检查
    redirectionURL, _ := url.ParseRequestURI(body.TargetURL)
    responseBody.SafeTargetURL = ctx.IsSafeRedirectionTargetURI(redirectionURL)
    
    ctx.SetJSONBody(responseBody)
}
```

**调用链**：

```
LogoutPOST() [handler_logout.go:19]
  ↓
ctx.DestroySession() [authelia_context.go:430]
  ↓
provider.DestroySession(ctx.RequestCtx) [session.go:86]
  ↓
sessionHolder.Destroy(ctx) [fasthttp/session库]
  ↓
provider.Destroy(sessionID) [memory/redis provider]
  ↓
  ├─ Memory: db.LoadAndDelete(key) [memory/provider.go:101]
  └─ Redis: DEL key [redis provider]
  ↓
fasthttp/session库设置过期cookie（Max-Age=-1）清除浏览器cookie
```

### 4.2 被动失效场景

#### 4.2.1 非活动超时失效

**检查函数**：`handleAuthnCookieValidateInactivity()` [internal/handlers/handler_authz_authn.go:486-496]

```go
func handleAuthnCookieValidateInactivity(ctx AuthzContext, manager session.Manager, userSession *session.UserSession, isAnonymous bool) (invalid bool) {
    config := manager.GetSessionConfig()
    
    // 匿名用户或Remember Me用户不检查非活动超时
    if isAnonymous || userSession.KeepMeLoggedIn || int64(config.Inactivity.Seconds()) == 0 {
        return false
    }
    
    // 检查：最后活动时间 + 非活动时长 < 当前时间
    return time.Unix(userSession.LastActivity, 0).Add(config.Inactivity).Before(ctx.GetClock().Now())
}
```

**LastActivity 更新逻辑**：[internal/handlers/handler_authz_authn.go:477-481]

```go
// 非Remember Me会话每次请求更新活动时间
if !userSession.KeepMeLoggedIn {
    modified = true
    userSession.LastActivity = ctx.GetClock().Now().Unix()
}
```

#### 4.2.2 用户被删除/禁用

**检查函数**：`handleSessionValidateRefresh()` [internal/handlers/handler_authz_authn.go:498-555]

```go
func handleSessionValidateRefresh(ctx AuthzContext, userSession *session.UserSession, refresh schema.RefreshIntervalDuration) (modified, invalid bool) {
    // ... 检查是否需要刷新 ...
    
    // 从认证后端获取最新用户信息
    details, err := ctx.GetProviders().UserProvider.GetDetails(userSession.Username)
    if err != nil {
        if errors.Is(err, authentication.ErrUserNotFound) {
            // 用户不存在，标记会话无效
            return false, true
        }
        return false, false
    }
    
    // 更新用户信息（邮箱、组、显示名）
    userSession.Emails, userSession.Groups, userSession.DisplayName = details.Emails, details.Groups, details.DisplayName
    return true, false
}
```

#### 4.2.3 Session-Username 头部劫持检测

**检查位置**：[internal/handlers/handler_authz_authn.go:471-475]

```go
// 检查请求头中的Session-Username与会话用户名是否匹配
if username := ctx.GetRequestHeaderValue(headerSessionUsername); username != nil && 
   !strings.EqualFold(string(username), userSession.Username) {
    ctx.Logger.Warnf("Session for user does not match the Session-Username header "+
        "which could be a sign of a cookie hijack")
    return modified, true  // 标记会话无效
}
```

#### 4.2.4 认证级别异常

**检查位置**：[internal/handlers/handler_authz_authn.go:455-459]

```go
// 匿名用户不应有非零认证级别
if isAnonymous && userSession.AuthenticationLevel(...) != authentication.NotAuthenticated {
    ctx.Logger.Errorf("Session for user has an invalid authentication level: "+
        "this may be a sign of a compromise")
    return modified, true  // 标记会话无效
}
```

### 4.3 失效后的处理流程

**统一处理**：`handleAuthnCookieValidate()` 调用链 [internal/handlers/handler_authz_authn.go:451-484]

```go
func handleAuthnCookieValidate(ctx AuthzContext, manager session.Manager, userSession *session.UserSession, ...) (modified, invalid bool) {
    // 1. 认证级别异常检查
    // 2. 非活动超时检查
    // 3. 用户信息刷新检查
    // 4. Session-Username头部检查
    
    if invalid {
        return modified, true  // 向上传递invalid标记
    }
    // ...
}
```

**上层处理**：[internal/handlers/handler_authz_authn.go:117-129]

```go
if modified, invalid := handleAuthnCookieValidate(ctx, manager, &userSession, s.refresh); invalid {
    // 销毁无效会话
    if err = manager.DestroySession(); err != nil {
        ctx.Logger.WithError(err).Errorf("Unable to destroy user session")
    }
    
    // 创建新的匿名会话
    userSession = manager.NewDefaultUserSession()
    userSession.LastActivity = ctx.GetClock().Now().Unix()
    
    if err = manager.SaveSession(userSession); err != nil {
        ctx.Logger.WithError(err).Error("Unable to save updated user session")
    }
    
    return authn, nil  // 返回未认证状态
}
```

---

## 5. 会话续期机制

### 5.1 Remember Me 续期

**登录时设置**：`FirstFactorPasswordPOST()` [internal/handlers/handler_firstfactor_password.go:123-136]

```go
// Check if bodyJSON.KeepMeLoggedIn can be deref'd and derive the value based on the configuration and JSON data.
keepMeLoggedIn := !provider.Config.DisableRememberMe && bodyJSON.KeepMeLoggedIn != nil && *bodyJSON.KeepMeLoggedIn

// Set the cookie to expire if remember me is enabled and the user has asked us to.
if keepMeLoggedIn {
    err = provider.UpdateExpiration(ctx.RequestCtx, provider.Config.RememberMe)
    // ...
}

userSession.SetOneFactorPassword(ctx.GetClock().Now(), details, keepMeLoggedIn)
```

**UpdateExpiration 实现**：[internal/session/session.go:91-104]

```go
func (p *Session) UpdateExpiration(ctx *fasthttp.RequestCtx, expiration time.Duration) (err error) {
    store, _ := p.sessionHolder.Get(ctx)
    err = store.SetExpiration(expiration)  // 更新存储中的过期时间
    return p.sessionHolder.Save(ctx, store) // 保存并更新cookie
}
```

### 5.2 常规会话续期

**非Remember Me会话**：
- 每次请求更新 `LastActivity` 时间戳
- Cookie过期时间保持不变（由Expiration配置决定）
- 超过 `Inactivity` 时间无活动则失效

**Remember Me会话**：
- 不更新 `LastActivity`（不检查非活动超时）
- Cookie过期时间为 `RememberMe` 配置（默认30天）
- 会话有效期内持续有效，直到Cookie自然过期

### 5.3 用户信息刷新续期

**刷新机制**：`handleSessionValidateRefresh()` [internal/handlers/handler_authz_authn.go:498-555]

```go
func handleSessionValidateRefresh(ctx AuthzContext, userSession *session.UserSession, refresh schema.RefreshIntervalDuration) (modified, invalid bool) {
    // 不需要刷新或匿名用户跳过
    if refresh.Never() || userSession.IsAnonymous() {
        return false, false
    }
    
    // 未到刷新时间跳过
    if !refresh.Always() && userSession.RefreshTTL.After(ctx.GetClock().Now()) {
        return false, false
    }
    
    // 从后端获取最新用户信息
    details, err := ctx.GetProviders().UserProvider.GetDetails(userSession.Username)
    // ... 错误处理 ...
    
    // 更新下次刷新时间
    if !refresh.Always() {
        modified = true
        userSession.RefreshTTL = ctx.GetClock().Now().Add(refresh.Value())
    }
    
    // 检测到信息变更则更新会话
    if diffEmails || diffGroups || diffDisplayName {
        userSession.Emails, userSession.Groups, userSession.DisplayName = details.Emails, details.Groups, details.DisplayName
        return true, false
    }
    
    return modified, false
}
```

---

## 6. 登录时会话发放流程

**完整流程**：`FirstFactorPasswordPOST()` [internal/handlers/handler_firstfactor_password.go:89-149]

```go
// 1. 获取会话提供者
provider, _ := ctx.GetSessionProvider()

// 2. 销毁现有会话（防止会话固定攻击）
provider.DestroySession(ctx.RequestCtx)

// 3. 创建新的空会话
userSession := provider.NewDefaultUserSession()
provider.SaveSession(ctx.RequestCtx, userSession)

// 4. 重新生成会话ID（会话固定保护）
provider.RegenerateSession(ctx.RequestCtx)

// 5. 根据Remember Me设置cookie过期时间
if keepMeLoggedIn {
    provider.UpdateExpiration(ctx.RequestCtx, provider.Config.RememberMe)
}

// 6. 设置用户认证信息
userSession.SetOneFactorPassword(ctx.GetClock().Now(), details, keepMeLoggedIn)

// 7. 设置信息刷新TTL
if ctx.Configuration.AuthenticationBackend.RefreshInterval.Update() {
    userSession.RefreshTTL = ctx.GetClock().Now().Add(ctx.Configuration.AuthenticationBackend.RefreshInterval.Value())
}

// 8. 保存最终会话
provider.SaveSession(ctx.RequestCtx, userSession)
```

**安全设计**：
- 登录前销毁旧会话：防止会话固定攻击
- 重新生成会话ID：即使旧ID泄露也无效
- 会话数据绑定CookieDomain：防止跨域迁移

---

## 7. 核心数据结构

### 7.1 UserSession 结构

```go
// internal/session/types.go:20-48
type UserSession struct {
    CookieDomain string  // 会话绑定的域名
    
    Username    string
    DisplayName string
    Groups      []string
    Emails      []string
    
    KeepMeLoggedIn bool  // Remember Me标记
    LastActivity   int64 // 最后活动时间（Unix秒）
    
    FirstFactorAuthnTimestamp  int64  // 1FA认证时间
    SecondFactorAuthnTimestamp int64  // 2FA认证时间
    
    AuthenticationMethodRefs authorization.AuthenticationMethodsReferences
    
    WebAuthn *WebAuthn  // WebAuthn注册会话数据
    TOTP     *TOTP      // TOTP注册会话数据
    
    PasswordResetUsername *string  // 密码重置验证标记
    
    RefreshTTL time.Time  // 用户信息刷新时间
    
    Elevations Elevations  // 会话提升（如sudo模式）
}
```

### 7.2 会话数据存储结构

```
fasthttp/session Store (Dict)
  └─ Key: "UserSession"
     └─ Value: JSON序列化的UserSession对象
```

**Redis存储时**：
- Key: `authelia-session<session-id>`
- Value: AES-GCM加密(Msgpack序列化(Dict))
- 过期时间：会话Expiration配置

---

## 8. 关键安全设计总结

| 安全机制 | 实现位置 | 防护目标 |
|---------|---------|---------|
| 会话固定保护 | 登录时Destroy + Regenerate | 防止会话固定攻击 |
| 域绑定验证 | GetSession()时检查CookieDomain | 防止cookie跨域迁移 |
| Session-Username头部验证 | handleAuthnCookieValidate() | 检测cookie劫持 |
| 强制Secure标志 | NewProviderConfig()中c.Secure=true | 防止HTTP明文传输cookie |
| SameSite策略 | 可配置Strict/Lax/None | 防止CSRF攻击 |
| Redis存储加密 | EncryptingSerializer | 防止Redis数据泄露 |
| 非活动超时 | handleAuthnCookieValidateInactivity() | 减少遗忘会话风险 |
| 用户信息刷新 | handleSessionValidateRefresh() | 及时感知用户删除/禁用 |
| 安全随机ID | SessionIDGeneratorFunc | 防止会话ID猜测 |

---

## 9. 代码引用索引

| 功能 | 文件位置 |
|------|---------|
| 会话配置定义 | `internal/configuration/schema/session.go:10-75` |
| Cookie属性组装 | `internal/session/provider_config.go:22-74` |
| 多域名提供者初始化 | `internal/session/provider.go:19-47` |
| 存储后端创建 | `internal/session/provider_config.go:96-178` |
| 加密序列化器 | `internal/session/encrypting_serializer.go:12-66` |
| 内存存储实现 | `internal/session/memory/provider.go` |
| 域名匹配算法 | `internal/utils/url.go:57-71` |
| 域绑定验证 | `internal/middlewares/authelia_context.go:392-404` |
| 注销处理器 | `internal/handlers/handler_logout.go:19-46` |
| 会话验证逻辑 | `internal/handlers/handler_authz_authn.go:451-555` |
| 登录会话发放 | `internal/handlers/handler_firstfactor_password.go:89-149` |
| UserSession结构 | `internal/session/types.go:20-48` |
