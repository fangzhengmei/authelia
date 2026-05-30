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

### 1.4 多cookie域重叠时的配置顺序命中行为

**匹配算法**：`GetCookieDomainFromTargetURI()` [internal/middlewares/authelia_context.go:251-265]

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

**核心机制**：**按配置顺序遍历，返回第一个匹配的域名**

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

**重叠场景分析**：

假设配置顺序为：
```yaml
session:
  cookies:
    - domain: "example.com"
    - domain: "sub.example.com"
```

当请求 `app.sub.example.com` 时：
1. 首先匹配 `example.com` → `HasDomainSuffix("app.sub.example.com", "example.com")` → 返回 `true`
2. 直接返回 `example.com`，不会继续匹配 `sub.example.com`

**正确的配置顺序**（子域名在前）：
```yaml
session:
  cookies:
    - domain: "sub.example.com"  # 更具体的域名优先
    - domain: "example.com"      # 通用域名在后
```

**安全影响**：

| 配置顺序问题 | 安全风险 | 影响范围 |
|------------|---------|---------|
| 父域名配置在子域名之前 | 子域名请求被错误路由到父域名的会话配置 | 会话隔离失效，可能导致权限泄露 |
| 子域名使用不同的过期策略 | 子域名继承父域名的过期时间，违背安全预期 | 会话有效期不符合设计 |
| 子域名禁用Remember Me但父域名启用 | 子域名用户仍可使用Remember Me功能 | 会话持久化风险 |
| 不同域名使用相同cookie名称 | 浏览器cookie覆盖，导致会话混乱 | 用户体验问题，会话状态异常 |

**配置最佳实践**：
1. 子域名配置在前，父域名配置在后
2. 不同域名使用不同的cookie名称
3. 明确每个域名的安全策略，避免隐式继承

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

### 2.5 会话数据存储的实际形态

**重要修正**：会话数据在 store 中的存储经历两次序列化，且存在持久化时机和类型不一致的问题。

#### 2.5.1 fasthttp/session 库的工作机制

在深入分析之前，需要理解 `sessionHolder`（即 `*session.Session`）的核心行为：

| 方法 | 行为 |
|------|------|
| `sessionHolder.Get(ctx)` | 1. 从请求 cookie 读取 session ID<br>2. 从后端存储加载数据到内存 store<br>3. 如果没有 session ID 或加载失败，创建新的空 store<br>4. **可能设置新的 session cookie**（如果是新会话） |
| `sessionHolder.Save(ctx, store)` | 1. 将内存中的 store 序列化（如果有 EncodeFunc）<br>2. 保存到后端存储<br>3. 设置/更新 session cookie（包括过期时间） |

**关键洞察**：`sessionHolder.Get()` 可能已经设置了 cookie，但如果不调用 `sessionHolder.Save()`，数据不会持久化到后端。

#### 2.5.2 Authelia 层面的存储流程

**写入流程**：`SaveSession()` [internal/session/session.go:57-78]

```go
func (p *Session) SaveSession(ctx *fasthttp.RequestCtx, userSession UserSession) (err error) {
    var (
        store           *session.Store
        userSessionJSON []byte
    )

    if store, err = p.sessionHolder.Get(ctx); err != nil {
        return err
    }

    // 第一次序列化：UserSession -> JSON []byte
    if userSessionJSON, err = json.Marshal(userSession); err != nil {
        return err
    }

    // 存储到 Dict 中，Key 为 "UserSession"，Value 为 JSON []byte
    store.Set(userSessionStorerKey, userSessionJSON)

    // ✅ 持久化到后端
    if err = p.sessionHolder.Save(ctx, store); err != nil {
        return err
    }

    return nil
}
```

**读取流程**：`GetSession()` [internal/session/session.go:30-54]

```go
func (p *Session) GetSession(ctx *fasthttp.RequestCtx) (userSession UserSession, err error) {
    var store *session.Store

    if store, err = p.sessionHolder.Get(ctx); err != nil {
        return p.NewDefaultUserSession(), err
    }

    // 尝试读取 []byte 类型
    userSessionJSON, ok := store.Get(userSessionStorerKey).([]byte)

    if !ok {
        // 会话不存在时，创建新会话
        userSession = p.NewDefaultUserSession()

        // ⚠️ 注意1：这里存储的是 UserSession 对象（结构体），不是 []byte
        store.Set(userSessionStorerKey, userSession)

        // ⚠️ 注意2：**没有调用** p.sessionHolder.Save(ctx, store)
        // 数据只在内存中，未持久化到后端

        return userSession, nil
    }

    // JSON反序列化
    if err = json.Unmarshal(userSessionJSON, &userSession); err != nil {
        return p.NewDefaultUserSession(), err
    }

    return userSession, nil
}
```

#### 2.5.3 会话重建的两种场景分析

##### 场景1：未持久化导致重建（主要场景，约99%）

**时序**：

```
请求1（新用户首次访问）
  ↓
sessionHolder.Get(ctx)
  ├─ 无 session cookie，创建新的空 store
  └─ 可能设置新的 session cookie（取决于库实现）
  ↓
store.Get("UserSession") → 不存在，ok=false
  ↓
创建默认 UserSession
  ↓
store.Set("UserSession", userSession) → 存储 UserSession 对象（内存中）
  ↓
❌ 未调用 sessionHolder.Save() → 数据未持久化到后端
  ↓
返回 userSession
  ↓
请求结束

========== 分割线 ==========

请求2（同一用户，携带 session cookie）
  ↓
sessionHolder.Get(ctx)
  ├─ 从 cookie 读取 session ID
  └─ 从后端加载数据 → 空数据（因为请求1未持久化）
  ↓
创建新的空 store
  ↓
store.Get("UserSession") → 不存在，ok=false
  ↓
重新走初始化路径
```

**根本原因**：`GetSession()` 只修改了内存中的 store，没有调用 `sessionHolder.Save()` 将数据持久化到后端。

**触发条件**：
- 新用户首次访问
- 只调用 `GetSession()` 而后续代码路径没有调用 `SaveSession()`
- 例如：访问 bypass 策略的公开页面，只读取会话但不修改

---

##### 场景2：已持久化但类型不匹配导致失败（边缘场景，约1%）

**时序**：

```
请求1（新用户访问）
  ↓
sessionHolder.Get(ctx) → 创建新 store，可能设置 cookie
  ↓
store.Get("UserSession") → 不存在，ok=false
  ↓
store.Set("UserSession", userSession) → 存储 UserSession 对象（内存中）
  ↓
✅ 某个代码路径调用了 sessionHolder.Save(store)
  ├─ 例如：UpdateExpiration() 被调用
  └─ 注意：UpdateExpiration() 只更新过期时间，但会 Save 整个 store
  ↓
UserSession 对象被序列化（Msgpack + AES-GCM）并持久化到后端
  ↓
请求结束

========== 分割线 ==========

请求2（同一用户，携带 session cookie）
  ↓
sessionHolder.Get(ctx)
  ├─ 从 cookie 读取 session ID
  └─ 从后端加载数据 → 获取到序列化后的 UserSession 对象
  ↓
反序列化后，store.Get("UserSession") 返回的是 UserSession 对象
  ↓
类型断言 .([]byte) 失败 → ok=false
  ↓
重新走初始化路径
```

**根本原因**：
1. `GetSession()` 存储的是 `UserSession` 对象
2. `SaveSession()` 存储的是 `json.Marshal()` 后的 `[]byte`
3. 如果某个路径（如 `UpdateExpiration()`）在 `GetSession()` 之后调用了 `sessionHolder.Save()`，就会将错误类型持久化

**触发条件**：
- 先调用 `GetSession()`（创建新会话）
- 然后调用 `UpdateExpiration()`（会间接调用 `sessionHolder.Save()`）
- 但没有先调用 `SaveSession()`（将 UserSession 转为 `[]byte`）

**代码验证**：

```go
// UpdateExpiration 实现 [session.go:91-104]
func (p *Session) UpdateExpiration(ctx *fasthttp.RequestCtx, expiration time.Duration) (err error) {
    var store *session.Store

    if store, err = p.sessionHolder.Get(ctx); err != nil {
        return err
    }

    err = store.SetExpiration(expiration)
    if err != nil {
        return err
    }

    // ⚠️ 这里会 Save 整个 store，如果 store 中存储的是 UserSession 对象而不是 []byte，
    // 就会持久化错误的类型
    return p.sessionHolder.Save(ctx, store)
}
```

**正常流程保护**：

在登录流程中，由于先调用 `SaveSession()` 再调用 `UpdateExpiration()`，所以不会出现类型不匹配：

```go
// FirstFactorPasswordPOST 中的正确顺序
provider.SaveSession(ctx.RequestCtx, userSession)  // ✅ 先转为 []byte 并持久化
provider.RegenerateSession(ctx.RequestCtx)

if keepMeLoggedIn {
    provider.UpdateExpiration(ctx.RequestCtx, provider.Config.RememberMe)  // ✅ 此时 store 中已经是 []byte
}
```

#### 2.5.4 两种场景对比总结

| 维度 | 场景1：未持久化导致重建 | 场景2：类型不匹配导致失败 |
|------|------------------------|--------------------------|
| 发生概率 | 极高（新用户首次访问未登录页面） | 极低（特定调用顺序） |
| 后端数据 | 空（从未持久化） | 有数据但类型错误 |
| 触发条件 | 只调用 GetSession() 不调用 SaveSession() | GetSession() → UpdateExpiration()，跳过 SaveSession() |
| 根本原因 | 缺少 sessionHolder.Save() 调用 | 先存储 UserSession 对象，后持久化 |
| 后续影响 | 每次请求都重新初始化 | 一次错误持久化，后续持续失败 |
| 恢复方式 | 调用 SaveSession() 后正常 | 调用 SaveSession() 覆盖错误数据后恢复 |

#### 2.5.5 fasthttp/session 层面的序列化

当配置了序列化器（Redis模式）时，`EncodeFunc` 和 `DecodeFunc` 会被调用：

**完整存储链路（Redis模式）**：

```
UserSession 对象
    ↓ json.Marshal [internal/session/session.go:67]
JSON []byte
    ↓ store.Set("UserSession", jsonBytes) [session.go:71]
Dict{KV: map["UserSession"]: jsonBytes}
    ↓ EncryptingSerializer.Encode [encrypting_serializer.go:30]
    ├─ Dict -> Msgpack 序列化
    └─ Msgpack -> AES-GCM 加密
AES-GCM(Msgpack(Dict))
    ↓ provider.Save()
Redis存储 (key: "authelia-session<session-id>")
```

**完整读取链路（Redis模式）**：

```
Redis存储
    ↓ provider.Get()
AES-GCM(Msgpack(Dict))
    ↓ EncryptingSerializer.Decode [encrypting_serializer.go:48]
    ├─ AES-GCM 解密
    └─ Msgpack 反序列化
Dict{KV: map["UserSession"]: jsonBytes}
    ↓ store.Get("UserSession").([]byte) [session.go:37]
JSON []byte
    ↓ json.Unmarshal [session.go:49]
UserSession 对象
```

#### 2.5.6 内存模式 vs Redis 模式对比

| 层级 | Memory模式 | Redis模式 |
|------|-----------|----------|
| Authelia层面 | UserSession → JSON → Dict | UserSession → JSON → Dict |
| 序列化器 | 无（Dict直接存储在内存） | Dict → Msgpack → AES-GCM |
| 存储介质 | sync.Map（内存） | Redis |
| 数据加密 | ❌ | ✅ AES-GCM-256 |
| 持久化 | ❌ | ✅ |

### 2.6 存储后端对比

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

**匹配示例**：
- `example.com` 匹配 `example.com`、`app.example.com`、`sub.app.example.com`
- `.example.com` 匹配 `app.example.com`、`sub.app.example.com`，但不匹配 `example.com`

### 3.2 会话域绑定验证

**验证位置1**：`GetSession()` [internal/middlewares/authelia_context.go:392-404]

```go
func (ctx *AutheliaCtx) GetSession() (userSession session.UserSession, err error) {
    var provider *session.Session

    if provider, err = ctx.GetSessionProvider(); err != nil {
        return userSession, err
    }

    if userSession, err = provider.GetSession(ctx.RequestCtx); err != nil {
        ctx.Logger.Error("Unable to retrieve user session")
        return provider.NewDefaultUserSession(), nil
    }

    // 验证会话中存储的CookieDomain与当前请求域名是否匹配
    if userSession.CookieDomain != provider.Config.Domain {
        ctx.Logger.Warnf("Destroying session cookie as the cookie domain '%s' does not match "+
            "the requests detected cookie domain '%s' which may be a sign a user tried to move "+
            "this cookie from one domain to another", 
            userSession.CookieDomain, provider.Config.Domain)
        
        // 销毁可疑会话并创建新会话
        if err = provider.DestroySession(ctx.RequestCtx); err != nil {
            ctx.Logger.WithError(err).Error("Error occurred trying to destroy the session cookie")
        }

        userSession = provider.NewDefaultUserSession()

        if err = provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
            ctx.Logger.WithError(err).Error("Error occurred trying to save the new session cookie")
        }
    }
    return
}
```

**验证位置2**：`CookieSessionAuthnStrategy.Get()` [internal/handlers/handler_authz_authn.go:103-115]

```go
func (s *CookieSessionAuthnStrategy) Get(ctx AuthzContext, manager session.Manager, _ *authorization.Object) (authn *Authn, err error) {
    var userSession session.UserSession

    authn = &Authn{
        Type:     AuthnTypeCookie,
        Level:    authentication.NotAuthenticated,
        Username: anonymous,
    }

    if userSession, err = manager.GetSession(); err != nil {
        return authn, fmt.Errorf("failed to retrieve user session: %w", err)
    }

    // 同样的域绑定验证
    if userSession.CookieDomain != manager.GetSessionConfig().Domain {
        ctx.GetLogger().Warnf("Destroying session cookie as the cookie domain '%s' does not match "+
            "the requests detected cookie domain '%s' which may be a sign a user tried to move "+
            "this cookie from one domain to another", 
            userSession.CookieDomain, manager.GetSessionConfig().Domain)

        if err = manager.DestroySession(); err != nil {
            ctx.GetLogger().WithError(err).Error("Error occurred trying to destroy the session cookie")
        }

        userSession = manager.NewDefaultUserSession()

        if err = manager.SaveSession(userSession); err != nil {
            ctx.GetLogger().WithError(err).Error("Error occurred trying to save the new session cookie")
        }
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

#### 4.2.2 用户资料刷新的失效策略

**检查函数**：`handleSessionValidateRefresh()` [internal/handlers/handler_authz_authn.go:498-555]

```go
func handleSessionValidateRefresh(ctx AuthzContext, userSession *session.UserSession, refresh schema.RefreshIntervalDuration) (modified, invalid bool) {
    if refresh.Never() || userSession.IsAnonymous() {
        return false, false
    }

    ctx.GetLogger().WithField("username", userSession.Username).Trace("Checking if we need check the authentication backend for an updated profile for user")

    if !refresh.Always() && userSession.RefreshTTL.After(ctx.GetClock().Now()) {
        return false, false
    }

    ctx.GetLogger().WithField("username", userSession.Username).Debug("Checking the authentication backend for an updated profile for user")

    var (
        details *authentication.UserDetails
        err     error
    )
    if details, err = ctx.GetProviders().UserProvider.GetDetails(userSession.Username); err != nil {
        // 错误处理分支
        if errors.Is(err, authentication.ErrUserNotFound) {
            // 情况1：用户明确不存在（被删除/禁用）
            ctx.GetLogger().WithField("username", userSession.Username).Error(
                "Error occurred while attempting to update user details for user: " +
                "the user was not found indicating they were deleted, disabled, " +
                "or otherwise no longer authorized to login")

            return false, true  // 标记会话无效
        }

        // 情况2：后端临时异常（网络问题、LDAP连接失败等）
        ctx.GetLogger().WithError(err).WithField("username", userSession.Username).Error(
            "Error occurred while attempting to update user details for user")

        return false, false  // 不标记无效，继续使用现有会话
    }

    // ... 用户信息更新逻辑 ...
}
```

**两种错误情况的策略对比**：

| 错误类型 | 判定条件 | 失效策略 | 设计考量 |
|---------|---------|---------|---------|
| 用户不存在 | `errors.Is(err, authentication.ErrUserNotFound)` | ✅ 立即失效（invalid=true） | 用户被明确删除/禁用，授权已撤销 |
| 后端临时异常 | 其他所有错误（网络超时、LDAP连接失败、数据库错误等） | ❌ 不失效（invalid=false） | 避免因后端抖动导致用户大规模掉线，保证可用性 |

**设计权衡**：
- **安全性**：用户被删除/禁用时立即失效，防止越权访问
- **可用性**：后端临时故障时保持用户登录状态，避免雪崩效应
- **风险控制**：配合 `RefreshInterval` 配置，定期检查，最终会在下一次成功检查时发现问题

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
    // 3. 用户信息刷新检查（含错误处理）
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
} else if modified {
    if err = manager.SaveSession(userSession); err != nil {
        ctx.Logger.WithError(err).Error("Unable to save updated user session")
    }
}
```

---

## 5. 域名匹配、重定向安全检查、会话销毁与重建的完整约束链路

### 5.1 完整约束链路图

```
请求到达
  ↓
1. 获取目标URL (X-Original-URL / X-Forwarded-* 头)
  ↓
2. 域名匹配 [GetCookieDomainFromTargetURI()]
  ├─ 按配置顺序遍历cookies
  ├─ 调用 HasDomainSuffix() 匹配
  └─ 返回第一个匹配的域名 / 无匹配返回空
  ↓
3. 匹配失败处理
  ├─ 返回错误："no configured session cookie domain matches"
  └─ 终止后续流程
  ↓
4. 获取会话提供者 [GetSessionProviderByTargetURI()]
  ↓
5. 获取会话 [GetSession()]
  ├─ 从cookie读取sessionID
  ├─ 从存储后端读取会话数据
  ├─ 反序列化为UserSession
  ↓
6. 域绑定验证
  ├─ 检查 userSession.CookieDomain == provider.Config.Domain
  ├─ 不匹配 → 销毁会话 → 创建新匿名会话 → 继续流程
  └─ 匹配 → 继续流程
  ↓
7. 会话有效性验证 [handleAuthnCookieValidate()]
  ├─ 7.1 认证级别异常检查
  ├─ 7.2 非活动超时检查
  ├─ 7.3 用户信息刷新检查（含两种错误处理）
  ├─ 7.4 Session-Username头部检查
  ├─ 无效 → 销毁会话 → 创建新匿名会话 → 返回未认证
  └─ 有效 → 继续流程
  ↓
8. 重定向安全检查 [IsSafeRedirectionTargetURI()]
  ├─ 检查URL是否为HTTPS
  ├─ 调用 GetCookieDomainFromTargetURI() 检查域名是否在配置中
  └─ 不安全 → 拒绝重定向 / 安全 → 允许重定向
  ↓
9. 正常业务处理
```

### 5.2 关键约束节点详解

#### 5.2.1 节点1：域名匹配

**入口**：`GetCookieDomainFromTargetURI()` [authelia_context.go:251]

**约束**：
- 必须配置至少一个匹配的cookie域名
- 按配置顺序匹配，第一个匹配生效
- 匹配失败则所有后续操作无法进行

**错误处理**：
```go
if domain == "" {
    return nil, fmt.Errorf("no configured session cookie domain matches the url '%s'", targetURL)
}
```

#### 5.2.2 节点2：域绑定验证

**入口**：`GetSession()` [authelia_context.go:392] 和 `CookieSessionAuthnStrategy.Get()` [handler_authz_authn.go:103]

**约束**：
- 会话中存储的 `CookieDomain` 必须与当前请求域名完全一致
- 即使cookie值相同，跨域使用也会被检测到

**安全动作**：
- 销毁可疑会话
- 创建新的匿名会话
- 记录警告日志

#### 5.2.3 节点3：重定向安全检查

**入口**：`IsSafeRedirectionTargetURI()` [authelia_context.go:286]

**约束**：
```go
func (ctx *AutheliaCtx) IsSafeRedirectionTargetURI(targetURI *url.URL) bool {
    if targetURI == nil {
        return false
    }
    // 约束1：必须是HTTPS
    if !utils.IsURISecure(targetURI) {
        return false
    }
    // 约束2：必须在配置的cookie域名范围内
    return ctx.GetCookieDomainFromTargetURI(targetURI) != ""
}
```

**调用场景**：
- 注销后的重定向目标检查
- 登录后的重定向目标检查
- 所有涉及外部跳转的场景

#### 5.2.4 节点4：会话销毁与重建

**销毁入口**：
- 主动注销：`ctx.DestroySession()` → `provider.DestroySession()`
- 域绑定验证失败：`provider.DestroySession()`
- 会话验证失效：`manager.DestroySession()`

**销毁流程**：
```
DestroySession()
  ↓
sessionHolder.Destroy(ctx)  // fasthttp/session库
  ↓
provider.Destroy(sessionID)  // 存储后端
  ├─ Memory: db.LoadAndDelete(key)
  └─ Redis: DEL key
  ↓
设置过期cookie（Max-Age=-1）清除浏览器cookie
```

**重建流程**：
```
NewDefaultUserSession()
  ↓
userSession.CookieDomain = p.Config.Domain  // 绑定当前域名
  ↓
SaveSession()  // 保存到存储后端
  ↓
返回新的匿名会话
```

### 5.3 约束链路的安全设计

| 约束节点 | 防护目标 | 绕过后果 |
|---------|---------|---------|
| 域名匹配 | 确保请求在预期的域名范围内 | 未配置的域名无法创建会话 |
| 域绑定验证 | 防止cookie跨域迁移 | 攻击者可将A域cookie用于B域 |
| 会话验证 | 检测多种会话异常状态 | 过期/失效会话继续有效 |
| 重定向安全检查 | 防止钓鱼攻击 | 用户被重定向到恶意网站 |
| 显式持久化 | 只有调用SaveSession才持久化 | 避免意外修改被永久保存 |

**设计特点**：
1. **多层防御**：每个节点独立校验，失败即终止
2. **fail-close**：校验失败时创建匿名会话而非放行
3. **可观测性**：所有安全事件都有日志记录
4. **一致性**：多个入口（GetSession / CookieSessionAuthnStrategy）采用相同验证逻辑
5. **显式控制**：只有调用 `SaveSession()` 才会触发 `sessionHolder.Save()` 持久化到后端

#### 5.3.1 约束链路中的持久化时机

在完整的约束链路中，只有以下场景会触发持久化：

1. **登录流程**：
   ```
   DestroySession() → SaveSession()（空会话）→ RegenerateSession()
   → UpdateExpiration()（可选）→ SaveSession()（最终会话）
   ```

2. **授权验证流程**：
   - 域绑定验证失败 → DestroySession() → SaveSession()（新匿名会话）
   - 会话验证失败（invalid=true）→ DestroySession() → SaveSession()（新匿名会话）
   - 会话有修改（modified=true）→ SaveSession()（更新会话）

3. **Remember Me 续期**：
   - UpdateExpiration() → sessionHolder.Save()（持久化整个store）

**注意**：如果在约束链路中只调用 `GetSession()` 而没有触发上述持久化场景，会话数据将只存在于内存中，不会被持久化到后端，导致下次请求重新初始化（详见 2.5.3 节场景1）。

---

## 6. 会话续期机制

### 6.1 Remember Me 续期

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
    var store *session.Store

    if store, err = p.sessionHolder.Get(ctx); err != nil {
        return err
    }

    err = store.SetExpiration(expiration)  // 更新存储中的过期时间
    if err != nil {
        return err
    }

    return p.sessionHolder.Save(ctx, store) // 保存并更新cookie
}
```

**重要注意**：`UpdateExpiration()` 会调用 `sessionHolder.Save()` 持久化整个 store。如果在调用 `UpdateExpiration()` 之前只调用了 `GetSession()` 而没有调用 `SaveSession()`，那么 store 中存储的是 `UserSession` 对象而不是 `[]byte`，这会导致类型不匹配的错误持久化（详见 2.5.3 节场景2）。

在登录流程中，由于先调用 `SaveSession()` 再调用 `UpdateExpiration()`，因此避免了这个问题。

### 6.2 常规会话续期

**非Remember Me会话**：
- 每次请求更新 `LastActivity` 时间戳
- Cookie过期时间保持不变（由Expiration配置决定）
- 超过 `Inactivity` 时间无活动则失效

**Remember Me会话**：
- 不更新 `LastActivity`（不检查非活动超时）
- Cookie过期时间为 `RememberMe` 配置（默认30天）
- 会话有效期内持续有效，直到Cookie自然过期

### 6.3 用户信息刷新续期

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
    // ... 错误处理（详见4.2.2节） ...
    
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

## 7. 登录时会话发放流程

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

## 8. 核心数据结构

### 8.1 UserSession 结构

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

### 8.2 会话数据存储结构（修正后）

#### 8.2.1 正常持久化后的结构（经过 SaveSession）

```
Authelia Store (Dict)
  └─ Key: "UserSession"
     └─ Value: JSON([]byte) 序列化的 UserSession 对象
           ├─ CookieDomain: "example.com"
           ├─ Username: "john"
           ├─ ... 其他字段
```

**Redis存储时**：
- Key: `authelia-session<session-id>`
- Value: AES-GCM(Msgpack(Dict{
    "UserSession": JSON(UserSession)
  }))
- 过期时间：会话 Expiration 配置

#### 8.2.2 未持久化的临时状态（仅 GetSession 未 SaveSession）

```
内存 Store (Dict)
  └─ Key: "UserSession"
     └─ Value: UserSession 对象（结构体，未序列化）
           ├─ CookieDomain: "example.com"
           ├─ Username: ""
           ├─ ... 其他默认字段
```

**特点**：
- 仅存在于内存中，未持久化到后端
- 存储类型为 `UserSession` 结构体，不是 `[]byte`
- 下次请求时，由于后端无数据，会重新初始化

#### 8.2.3 类型不匹配的错误持久化状态

```
后端存储（Redis/Memory）
  └─ Key: "authelia-session<session-id>"
     └─ Value: AES-GCM(Msgpack(Dict{
         "UserSession": UserSession 对象（Msgpack序列化的结构体）
       }))
```

**读取时**：
- 反序列化后 `store.Get("UserSession")` 返回 `UserSession` 对象
- 类型断言 `.([]byte)` 失败 → `ok=false` → 重新初始化
- 需要调用 `SaveSession()` 覆盖为正确的 `[]byte` 类型

---

## 9. 关键安全设计总结

| 安全机制 | 实现位置 | 防护目标 |
|---------|---------|---------|
| 会话固定保护 | 登录时Destroy + Regenerate | 防止会话固定攻击 |
| 域绑定验证 | GetSession()时检查CookieDomain | 防止cookie跨域迁移 |
| Session-Username头部验证 | handleAuthnCookieValidate() | 检测cookie劫持 |
| 强制Secure标志 | NewProviderConfig()中c.Secure=true | 防止HTTP明文传输cookie |
| SameSite策略 | 可配置Strict/Lax/None | 防止CSRF攻击 |
| Redis存储加密 | EncryptingSerializer | 防止Redis数据泄露 |
| 非活动超时 | handleAuthnCookieValidateInactivity() | 减少遗忘会话风险 |
| 用户信息刷新错误分类 | handleSessionValidateRefresh() | 平衡安全性与可用性 |
| 重定向安全检查 | IsSafeRedirectionTargetURI() | 防止钓鱼攻击 |
| 配置顺序匹配 | GetCookieDomainFromTargetURI() | 确保正确的域名路由 |
| 安全随机ID | SessionIDGeneratorFunc | 防止会话ID猜测 |
| 显式持久化控制 | SaveSession() 才调用 sessionHolder.Save() | 确保只有显式修改才持久化 |

**注意**：代码中存在两个潜在问题（非安全漏洞，但影响可靠性）：
1. `GetSession()` 新会话未立即持久化（详见 2.5.3 节场景1）
2. `GetSession()` 与 `SaveSession()` 存储类型不一致（详见 2.5.3 节场景2）

---

## 10. 代码引用索引

| 功能 | 文件位置 |
|------|---------|
| 会话配置定义 | `internal/configuration/schema/session.go:10-75` |
| Cookie属性组装 | `internal/session/provider_config.go:22-74` |
| 多域名提供者初始化 | `internal/session/provider.go:19-47` |
| 存储后端创建 | `internal/session/provider_config.go:96-178` |
| 加密序列化器 | `internal/session/encrypting_serializer.go:12-66` |
| 内存存储实现 | `internal/session/memory/provider.go` |
| 域名匹配算法 | `internal/utils/url.go:57-71` |
| 域名匹配入口 | `internal/middlewares/authelia_context.go:251-265` |
| 域绑定验证 | `internal/middlewares/authelia_context.go:392-404` |
| 域绑定验证（授权路径） | `internal/handlers/handler_authz_authn.go:103-115` |
| 重定向安全检查 | `internal/middlewares/authelia_context.go:286-296` |
| 注销处理器 | `internal/handlers/handler_logout.go:19-46` |
| 会话验证逻辑 | `internal/handlers/handler_authz_authn.go:451-555` |
| 用户刷新错误处理 | `internal/handlers/handler_authz_authn.go:515-525` |
| 登录会话发放 | `internal/handlers/handler_firstfactor_password.go:89-149` |
| 会话读写逻辑 | `internal/session/session.go:30-78` |
| 会话过期更新 | `internal/session/session.go:91-104` |
| UserSession结构 | `internal/session/types.go:20-48` |
| 多cookie域测试配置 | `internal/suites/MultiCookieDomain/configuration.yml` |
| 会话提供者测试 | `internal/session/provider_test.go` |
