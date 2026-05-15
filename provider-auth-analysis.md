# Authelia 用户提供者认证链路分析报告

## 概述

本文档详细分析了 Authelia 系统中两种用户数据提供者（File Provider 和 LDAP Provider）从配置驱动选择、用户数据获取、认证策略执行到最终认证决策的完整处理链路。

---

## 一、核心架构总览

### 1.1 认证决策流程

```
配置初始化
    ↓
[配置驱动选择]
    ├─ AuthenticationBackend.File != nil → FileUserProvider
    └─ AuthenticationBackend.LDAP != nil → LDAPUserProvider
    ↓
[认证策略层]
    ├─ CookieSession 策略 (会话认证)
    ├─ HeaderAuthorization 策略 (Basic/Bearer)
    ├─ HeaderProxyAuthorization 策略
    └─ HeaderLegacy 策略
    ↓
[用户提供者层]
    ├─ CheckUserPassword() 密码验证
    ├─ GetDetails() 用户基本信息
    └─ GetDetailsExtended() 用户扩展信息
    ↓
[授权决策层]
    ├─ Authorizer.GetRequiredLevel()
    └─ 访问控制规则匹配
    ↓
[最终响应 (四种实现差异)]
    ├─ Legacy: 唯一带 WWW-Authenticate 的实现
    ├─ AuthRequest: 统一 401 + Location 重定向
    ├─ ForwardAuth: 智能选择 302/303/401
    └─ ExtAuthz: 同 ForwardAuth
```

---

## 二、配置驱动的 Provider 选择机制

### 2.1 选择入口点

**文件位置**: `internal/middlewares/util.go:85-95`

```go
// NewAuthenticationProvider returns a new authentication.UserProvider.
func NewAuthenticationProvider(config *schema.Configuration, caCertPool *x509.CertPool) (provider authentication.UserProvider) {
    switch {
    case config.AuthenticationBackend.File != nil:
        return authentication.NewFileUserProvider(config.AuthenticationBackend.File)
    case config.AuthenticationBackend.LDAP != nil:
        return authentication.NewLDAPUserProvider(config.AuthenticationBackend, caCertPool)
    default:
        return nil
    }
}
```

### 2.2 配置结构定义

**文件位置**: `internal/configuration/schema/authentication.go:9-19`

```go
type AuthenticationBackend struct {
    PasswordReset  AuthenticationBackendPasswordReset
    PasswordChange AuthenticationBackendPasswordChange
    RefreshInterval RefreshIntervalDuration

    // 互斥配置：只能配置一个
    File *AuthenticationBackendFile  // 文件认证
    LDAP *AuthenticationBackendLDAP  // LDAP 认证
}
```

### 2.3 Provider 注入链

```
1. 服务启动 → NewProviders()
    ↓ internal/middlewares/util.go:37
2. NewAuthenticationProvider() 根据配置选择
    ↓
3. Providers.UserProvider = 具体实现
    ↓
4. AutheliaCtx.Providers.UserProvider 供所有 handler 使用
```

---

## 三、用户提供者接口与实现

### 3.1 UserProvider 接口定义

**文件位置**: `internal/authentication/user_provider.go`

```go
type UserProvider interface {
    // 检查用户密码（登录验证）
    CheckUserPassword(username string, password string) (valid bool, err error)

    // 获取用户基本信息（组、邮箱等）
    GetDetails(username string) (details *UserDetails, err error)

    // 获取用户扩展信息
    GetDetailsExtended(username string) (details *UserDetailsExtended, err error)

    // 更新用户密码
    UpdatePassword(username string, newPassword string) (err error)

    // 修改密码（需验证旧密码）
    ChangePassword(username string, oldPassword string, newPassword string) (err error)

    // 关闭连接（LDAP用）
    Close() (err error)
}
```

### 3.2 用户数据模型

```go
type UserDetails struct {
    Username    string   // 用户名
    DisplayName string   // 显示名称
    Emails      []string // 邮箱列表
    Groups      []string // 用户组列表
}

type UserDetailsExtended struct {
    GivenName      string          // 名
    FamilyName     string          // 姓
    MiddleName     string          // 中间名
    Nickname       string          // 昵称
    Profile        *url.URL        // 个人资料URL
    Picture        *url.URL        // 头像URL
    Website        *url.URL        // 网站URL
    Gender         string          // 性别
    Birthdate      string          // 生日
    ZoneInfo       string          // 时区
    Locale         *language.Tag   // 语言设置
    PhoneNumber    string          // 电话号码
    PhoneExtension string          // 电话分机
    Address        *UserDetailsAddress
    Extra          map[string]any
    UserDetails                    // 内嵌基本信息
}
```

---

## 四、File Provider 详细分析

### 4.1 架构概述

**文件位置**: `internal/authentication/file_user_provider.go`
**数据库实现**: `internal/authentication/file_user_provider_database.go`

```go
type FileUserProvider struct {
    config        *schema.AuthenticationBackendFile
    hash          algorithm.Hash              // 密码哈希算法
    database      FileUserProviderDatabase     // 数据库接口
    mutex         sync.Mutex                   // 重载互斥锁
    timeoutReload time.Time                    // 重载冷却时间
}
```

### 4.2 FileUserDatabase 数据加载流程

```go
type FileUserDatabase struct {
    *sync.RWMutex
    Users  map[string]FileUserDatabaseUserDetails  // 用户映射
    Path   string                                  // YAML文件路径
    Emails map[string]string                       // 邮箱反向映射
    Aliases map[string]string                      // 用户名大小写不敏感映射

    SearchEmail bool  // 是否支持邮箱搜索登录
    SearchCI    bool  // 是否大小写不敏感搜索
    Extra       map[string]expression.ExtraAttribute
}
```

#### 数据加载时序

```
Load() 被调用
    ↓
1. 读取 YAML 文件内容 → os.ReadFile()
    ↓
2. YAML 反序列化 → yaml.Unmarshal()
    ↓
3. 验证结构有效性 → govalidator.ValidateStruct()
    ↓
4. 转换用户数据
    ├─ 解码密码哈希 → crypt.Decode()
    ├─ 解析 URI 类型属性 (Website/Profile/Picture)
    ├─ 验证额外属性类型
    └─ 构建 Users map (用户名→详情)
    ↓
5. 构建反向映射索引
    ├─ Emails map: email → username (SearchEmail=true时)
    └─ Aliases map: lowercase(username) → username (SearchCI=true时)
    ↓
返回成功/错误
```

### 4.3 密码验证流程

```go
func (p *FileUserProvider) CheckUserPassword(username, password string) (bool, error)
```

**执行步骤**:
1. **用户查找**（按优先级）:
   - 邮箱搜索: `database.Emails[strings.ToLower(username)]`
   - 大小写不敏感: `database.Aliases[strings.ToLower(username)]`
   - 精确匹配: `database.Users[username]`

2. **禁用检查**: 如 `details.Disabled == true` 返回 `ErrUserNotFound`

3. **密码匹配**: `details.Password.MatchAdvanced(password)`
   - 支持算法: Argon2, SHA2Crypt, PBKDF2, Scrypt, Bcrypt

### 4.4 动态重新加载机制

```go
func (p *FileUserProvider) Reload() (reloaded bool, err error)
```

**特性**:
- **冷却时间保护**: `timeoutReload` 防止频繁重载（默认半秒）
- **原子替换**: 使用互斥锁保证线程安全
- **File Watcher**: `internal/service/file_watcher.go` 监听文件变更自动触发

### 4.5 配置示例

```yaml
authentication_backend:
  file:
    path: /config/users.yml
    watch: true                      # 启用文件监听自动重载
    search:
      email: true                    # 允许用邮箱登录
      case_insensitive: true         # 用户名大小写不敏感
    password:
      algorithm: argon2id
      argon2:
        iterations: 3
        memory: 65536
        parallelism: 4
        key_length: 32
        salt_length: 16

# users.yml 内容
users:
  john:
    password: "$argon2id$v=19$m=65536,t=3,p=2$..."
    displayname: "John Doe"
    email: john@example.com
    groups: ["admins", "devs"]
    disabled: false
    given_name: "John"
    family_name: "Doe"
```

---

## 五、LDAP Provider 详细分析

### 5.1 架构概述

**文件位置**: `internal/authentication/ldap_user_provider.go`

```go
type LDAPUserProvider struct {
    config  *schema.AuthenticationBackendLDAP
    log     *logrus.Logger
    factory LDAPClientFactory  // 连接工厂（标准/连接池）
    clock   clock.Provider

    disableResetPassword bool

    // 动态计算的配置值
    usersBaseDN           string
    usersAttributes       []string
    usersFilterReplacement  map[string]bool

    groupsBaseDN          string
    groupsAttributes      []string
    groupsFilterReplacement map[string]bool
}
```

### 5.2 LDAP 客户端工厂模式

#### Standard vs Pooled

```go
// 配置决定使用哪种工厂
if config.LDAP.Pooling.Enable {
    factory = NewPooledLDAPClientFactory(...)  // 连接池模式
} else {
    factory = NewStandardLDAPClientFactory(...) // 标准模式
}
```

**连接池配置**:
```go
type AuthenticationBackendLDAPPooling struct {
    Enable  bool          // 启用连接池
    Count   int           // 连接数 (默认5)
    Retries int           // 获取连接重试次数 (默认2)
    Timeout time.Duration // 获取连接超时 (默认10秒)
}
```

### 5.3 用户密码验证流程

```go
func (p *LDAPUserProvider) CheckUserPassword(username, password string) (bool, error)
```

**执行步骤**:

```
1. 获取管理连接 → factory.GetClient()
    ↓
2. 搜索用户 DN
    ↓ p.getUserProfile(client, username)
    ├─ 替换过滤器占位符 {input}
    ├─ 执行 LDAP Search (baseDN + usersFilter)
    ├─ 检查结果数必须 == 1
    └─ 解析用户 DN 和属性
    ↓
3. 使用用户凭证绑定验证
    ↓ factory.GetClient(WithDN, WithPassword)
    ├─ 绑定成功 → 返回 true
    └─ 绑定失败 → 返回 LDAP 错误
    ↓
4. 释放连接回池
```

### 5.4 用户 Profile 获取

**关键过滤器占位符**:
```go
{input}                    → 用户输入的用户名/邮箱
{date-time}                → 当前时间 (Generalized)
{date-time-epoch}          → Unix 时间戳
{date-time-msepoch}        → Microsoft NT 时间戳
```

**实现预置过滤器示例** (Active Directory):
```go
"(&(|({username_attribute}={input})({mail_attribute}={input}))" +
"(sAMAccountType=805306368)" +  // 用户对象类型
"(!(userAccountControl:1.2.840.113556.1.4.803:=2))" + // 非禁用
"(!(pwdLastSet=0))" +           // 已设置密码
"(|(!(accountExpires=*))(accountExpires=0)(accountExpires>={date-time:microsoft-nt})))"
```

### 5.5 用户组获取流程

#### 两种组搜索模式

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| **filter** | 独立搜索组条目，匹配成员属性 | 大多数 LDAP 服务器 (默认) |
| **memberof** | 利用用户的 memberOf 属性反向匹配组 | Active Directory |

#### 组过滤器占位符
```go
{input}                    → 原始用户名
{username}                 → LDAP 用户名属性值
{dn}                       → 用户完整 DN
{memberof_dn}              → 展开为多值 OR 过滤器 (所有 memberOf DN)
{memberof_rdn}             → 展开为 RDN 过滤器
```

### 5.6 密码修改流程

**三种实现方式**:

| LDAP 类型 | 实现方式 | 说明 |
|----------|----------|------|
| **Active Directory** | LDAP Modify | 修改 `unicodePwd` 属性，需 SSL/TLS |
| **支持 RFC 3062** | Password Modify Extended Op | 标准扩展操作，支持旧密码验证 |
| **其他** | LDAP Modify | 直接修改 `userPassword` 属性 |

### 5.7 Referral 处理机制

- 自动跟随 LDAP Referral 引用
- 递归搜索多个 LDAP 服务器
- 合并多服务器搜索结果
- 去重处理重复条目
- 可配置开关: `permit_referrals: true/false`

---

## 六、认证策略层分析

### 6.1 策略接口定义

**文件位置**: `internal/handlers/handler_authz_types.go:109-114`

```go
type AuthnStrategy interface {
    // 获取认证信息（核心方法）
    Get(ctx *middlewares.AutheliaCtx, provider *session.Session, object *authorization.Object) (*Authn, error)

    // 是否能处理未授权情况
    CanHandleUnauthorized() bool

    // 是否为头部策略
    HeaderStrategy() bool

    // 处理未授权响应
    HandleUnauthorized(ctx *middlewares.AutheliaCtx, authn *Authn, redirectionURL *url.URL)
}
```

### 6.2 CookieSession 认证策略

**文件位置**: `internal/handlers/handler_authz_authn.go:86-158`

#### 核心流程

```
1. 从 Cookie 中读取 Session ID
    ↓
2. 加载 Session 数据
    ↓ session.GetSession()
3. 验证 Session 有效性
    ├─ Cookie Domain 匹配检查
    ├─ 会话过期检查
    ├─ 最后活动时间检查
    └─ Refresh TTL: 定期从 Provider 刷新用户信息
    ↓
4. 刷新用户信息（如需要）
    ↓ UserProvider.GetDetails(username)
    ├─ 比较 Email/Group/DisplayName 变更
    └─ 更新 Session 中的用户信息
    ↓
5. 构建 Authn 对象
    ├─ Level: OneFactor/TwoFactor/NotAuthenticated
    ├─ Details: UserDetails (用户名、组、邮箱等)
    └─ Username: 友好显示名
```

#### Session 刷新机制

**配置控制**: `authentication_backend.refresh_interval`

| 模式 | 行为 |
|------|------|
| `always` | 每次请求都刷新用户信息 |
| `disable` | 从不刷新 |
| `duration` | 按指定间隔刷新 (如 5m, 1h) |

### 6.3 Header Authorization 认证策略

#### Basic Auth 处理流程

```go
func DefaultBasicAuthHandler(ctx, authorization) (valid bool, cached bool, err error)
```

```
1. 解析 Authorization: Basic <base64> 头部
    ↓ Base64 解码 → username:password
2. 监管检查 (Regulator)
    ├─ 检查用户是否被封禁
    ├─ 记录认证尝试
    └─ 失败次数计数 → 超过阈值自动封禁
    ↓
3. UserProvider.CheckUserPassword(username, password)
    ├─ FileProvider: 本地哈希匹配
    └─ LDAPProvider: LDAP BIND 操作
    ↓
4. 成功 → 缓存结果（如启用缓存）
    ↓
5. 返回认证级别: OneFactor
```

#### Bearer Token (OIDC) 处理流程

```
1. 解析 Authorization: Bearer <token> 头部
    ↓
2. Token 内省验证
    ↓ OpenIDConnect.IntrospectToken()
    ├─ 验证 Token 签名有效性
    ├─ 检查 Token 是否过期
    ├─ 验证 Scope (需包含 authelia.bearer.authz)
    └─ 验证 Audience (目标 URL)
    ↓
3. 提取 Session 信息
    ├─ Username
    ├─ Authentication Methods References (amr)
    └─ Client ID (客户端凭证模式)
    ↓
4. 确定认证级别
    ├─ 客户端凭证模式 → OneFactor
    ├─ amr 包含 mfa → TwoFactor
    └─ 其他 → OneFactor
```

### 6.4 策略选择与执行链

**文件位置**: `internal/handlers/handler_authz.go:160-186`

```go
func (authz *Authz) authn(ctx, provider, object) (*Authn, AuthnStrategy, error) {
    for _, strategy = range authz.strategies {
        authn, err = strategy.Get(ctx, provider, object)
        if err != nil {
            // 错误处理...
        }
        // 第一个成功认证的策略胜出
        if authn.Level != authentication.NotAuthenticated {
            break
        }
    }
    return authn, strategy, err
}
```

**策略执行顺序** (AuthzBuilder 配置):
1. CookieSession (最高优先级，先检查已有会话)
2. HeaderAuthorization
3. HeaderProxyAuthorization
4. HeaderLegacy

---

## 七、授权决策层分析

### 7.1 Authorizer 核心组件

**文件位置**: `internal/authorization/authorizer.go`

```go
type Authorizer struct {
    defaultPolicy Level          // 默认策略
    rules         []*AccessControlRule  // 访问控制规则列表
    mfa           bool           // 是否需要 MFA
}
```

### 7.2 访问控制规则匹配

```go
func (p *Authorizer) GetRequiredLevel(subject Subject, object Object) (hasSubjects bool, level Level)
```

#### Subject (请求主体)
```go
type Subject struct {
    Username string   // 用户名
    Groups   []string // 用户组
    ClientID string   // OIDC 客户端 ID
    IP       net.IP   // 客户端 IP
}
```

#### Object (访问对象)
```go
type Object struct {
    URL    *url.URL // 目标 URL
    Domain string   // 域名
    Method string   // HTTP 方法
}
```

#### 规则匹配算法

```
遍历规则列表（按配置顺序，先匹配优先）:
    for rule in rules:
        if !rule.MatchesDomain(object.Domain): continue
        if !rule.MatchesResources(object.URL.Path): continue
        if !rule.MatchesMethods(object.Method): continue
        if !rule.MatchesNetworks(subject.IP): continue

        // 匹配到规则，返回策略级别
        hasSubjects = rule.HasSubjects()
        return hasSubjects, rule.Policy

// 无匹配规则，应用默认策略
return false, p.defaultPolicy
```

### 7.3 认证级别比较决策

**文件位置**: `internal/handlers/handler_authz.go:93-109`

```go
switch isAuthzResult(actual authentication.Level, required authorization.Level, hasSubjects bool) {
case AuthzResultAuthorized:     // 200
case AuthzResultUnauthorized:   // 401 或 302 重定向（视实现而定）
case AuthzResultForbidden:      // 403
}
```

#### 决策矩阵详解

| 实际认证级别 | 要求级别 | hasSubjects | 结果 | 说明 |
|-------------|----------|-------------|------|------|
| `NotAuthenticated` | `Bypass` | `false` | **Authorized** | 匿名绕过，无需认证 |
| `NotAuthenticated` | `Bypass` | `true` | **Unauthorized** | 规则有用户限制，需认证 |
| `NotAuthenticated` | `OneFactor` | * | **Unauthorized** | 需要1FA认证 |
| `NotAuthenticated` | `TwoFactor` | * | **Unauthorized** | 需要2FA认证 |
| `NotAuthenticated` | `Deny` | * | **Forbidden** | 拒绝访问 |
| `OneFactor` | `Bypass` | * | **Authorized** | 已认证，级别足够 |
| `OneFactor` | `OneFactor` | * | **Authorized** | 级别匹配 |
| `OneFactor` | `TwoFactor` | * | **Unauthorized** | 需要升级到2FA |
| `OneFactor` | `Deny` | * | **Forbidden** | 拒绝访问 |
| `TwoFactor` | `Bypass` | * | **Authorized** | 级别足够 |
| `TwoFactor` | `OneFactor` | * | **Authorized** | 级别足够 |
| `TwoFactor` | `TwoFactor` | * | **Authorized** | 级别匹配 |
| `TwoFactor` | `Deny` | * | **Forbidden** | 拒绝访问 |

---

## 八、四种授权实现：未授权响应详细对比

### 8.1 概述

⚠️ **重要修正**: 之前结论"401 都带 WWW-Authenticate 挑战头"是错误的。

**正确结论**: **只有 Legacy 实现在 Authorization 头部认证场景下才会设置 WWW-Authenticate 头部**。其他三种实现（AuthRequest、ForwardAuth、ExtAuthz）的 401 响应仅带 Location 重定向头，**不会设置 WWW-Authenticate**。

---

### 8.2 四种实现代码位置

| 实现方式 | 处理函数 | 文件位置 | 适用反向代理 |
|---------|---------|---------|-------------|
| **Legacy** | `handleAuthzUnauthorizedLegacy` | `handler_authz_impl_legacy.go:34-70` | Traefik v1, Nginx |
| **AuthRequest** | `handleAuthzUnauthorizedAuthRequest` | `handler_authz_impl_authrequest.go:39-48` | Nginx auth_request |
| **ForwardAuth** | `handleAuthzUnauthorizedForwardAuth` | `handler_authz_impl_forwardauth.go:36-61` | Traefik v2+ |
| **ExtAuthz** | `handleAuthzUnauthorizedExtAuthz` | `handler_authz_impl_extauthz.go:36-61` | Envoy |

---

### 8.3 触发条件详细对比表

| 场景条件 | Legacy | AuthRequest | ForwardAuth | ExtAuthz |
|---------|--------|-------------|-------------|----------|
| **AuthnTypeAuthorization (Basic/Bearer)** | `401` + **WWW-Authenticate: Basic** | 无此分支 | 无此分支 | 无此分支 |
| **XHR 请求 (XMLHttpRequest)** | `401` + Location | `401` + Location | `401` + Location | `401` + Location |
| **不接受 text/html (Accept 头部)** | `401` + Location | `401` + Location | `401` + Location | `401` + Location |
| **无 redirectionURL** | `401` (无 Location, 纯 401) | `401` + Location | N/A (有 URL) | N/A (有 URL) |
| **GET/OPTIONS/HEAD + 浏览器** | `302 Found` + Location | `401` + Location | `302 Found` + Location | `302 Found` + Location |
| **POST/PUT/DELETE + 浏览器** | `303 See Other` + Location | `401` + Location | `303 See Other` + Location | `303 See Other` + Location |
| **HEAD 请求 (body 处理)** | SpecialRedirectNoBody | SpecialRedirectNoBody | SpecialRedirectNoBody | SpecialRedirectNoBody |
| **WWW-Authenticate 头部** | ✅ **仅 Basic Auth 场景** | ❌ 从不设置 | ❌ 从不设置 | ❌ 从不设置 |

---

### 8.4 各实现核心代码分析

#### 8.4.1 Legacy 实现（唯一带 WWW-Authenticate）

**文件位置**: `handler_authz_impl_legacy.go:34-70`

```go
func handleAuthzUnauthorizedLegacy(ctx, authn, redirectionURL) {
    // 🔑 唯一有 WWW-Authenticate 挑战的分支
    if authn.Type == AuthnTypeAuthorization {
        handleAuthzUnauthorizedAuthorizationBasic(ctx, authn)  // 401 + WWW-Authenticate
        return
    }

    // 状态码选择
    switch {
    case ctx.IsXHR() || !ctx.AcceptsMIME("text/html") || redirectionURL == nil:
        statusCode = 401
    default:
        switch authn.Object.Method {
        case GET/OPTIONS/HEAD/"":
            statusCode = 302  // Found
        default:
            statusCode = 303  // See Other
        }
    }

    if redirectionURL != nil {
        ctx.SpecialRedirect(redirectionURL.String(), statusCode)  // 带 Location 头
    } else {
        ctx.ReplyUnauthorized()  // 纯 401，无重定向
    }
}
```

**WWW-Authenticate 设置代码** (`handler_authz_common.go:78-84`):
```go
func handleAuthzUnauthorizedAuthorizationBasic(ctx, authn) {
    ctx.ReplyUnauthorized()  // 401
    ctx.Response.Header.SetBytesKV(headerWWWAuthenticate, headerValueAuthenticateBasic)
    // 结果: WWW-Authenticate: Basic realm="Authelia"
}
```

#### 8.4.2 AuthRequest 实现（统一 401）

**文件位置**: `handler_authz_impl_authrequest.go:39-48`

```go
func handleAuthzUnauthorizedAuthRequest(ctx, authn, redirectionURL) {
    // ❌ 没有 WWW-Authenticate 分支
    // ❌ 没有状态码选择逻辑，强制 401

    switch authn.Object.Method {
    case HEAD:
        ctx.SpecialRedirectNoBody(redirectionURL.String(), 401)
    default:
        ctx.SpecialRedirect(redirectionURL.String(), 401)
    }
    // 结果: 401 + Location 重定向头（HTML body 带链接）
}
```

**特点**:
- 所有情况统一返回 `401 Unauthorized`
- 始终设置 `Location` 头指向登录门户
- **从不设置 WWW-Authenticate**
- Nginx auth_request 模块期望这种行为

#### 8.4.3 ForwardAuth 实现（智能选择）

**文件位置**: `handler_authz_impl_forwardauth.go:36-61`

```go
func handleAuthzUnauthorizedForwardAuth(ctx, authn, redirectionURL) {
    // ❌ 没有 WWW-Authenticate 分支

    switch {
    case ctx.IsXHR() || !ctx.AcceptsMIME("text/html"):
        statusCode = 401  // API 场景
    default:
        switch authn.Object.Method {
        case GET/OPTIONS/HEAD:
            statusCode = 302  // Found
        default:
            statusCode = 303  // See Other
        }
    }

    ctx.SpecialRedirect(redirectionURL.String(), statusCode)
}
```

**特点**:
- 智能区分浏览器与非浏览器场景
- 浏览器 GET → 302 临时重定向
- 浏览器 POST → 303 See Other（防重复提交）
- API 场景 → 401（带 Location）
- **从不设置 WWW-Authenticate**

#### 8.4.4 ExtAuthz 实现（同 ForwardAuth）

**文件位置**: `handler_authz_impl_extauthz.go:36-61`

```go
// 代码与 ForwardAuth 完全相同
func handleAuthzUnauthorizedExtAuthz(ctx, authn, redirectionURL) {
    switch {
    case ctx.IsXHR() || !ctx.AcceptsMIME("text/html"):
        statusCode = 401
    default:
        switch authn.Object.Method {
        case GET/OPTIONS/HEAD:
            statusCode = 302
        default:
            statusCode = 303
        }
    }
    ctx.SpecialRedirect(redirectionURL.String(), statusCode)
}
```

**特点**:
- 与 ForwardAuth 逻辑完全一致
- 为 Envoy 外部认证设计
- **从不设置 WWW-Authenticate**

---

### 8.5 SpecialRedirect 机制解析

**文件位置**: `middlewares/authelia_context.go:587-621`

```go
func (ctx *AutheliaCtx) SpecialRedirect(uri string, statusCode int) {
    u, statusCode = ctx.setSpecialRedirect(uri, statusCode)

    ctx.SetContentTypeTextHTML()
    ctx.SetBodyString(fmt.Sprintf("<a href=\"%s\">%d %s</a>", ...))
}

func (ctx *AutheliaCtx) setSpecialRedirect(uri string, statusCode int) {
    // 验证状态码合法性，非法则强制改为 302
    if statusCode < 301 || (statusCode > 303 && statusCode != 307 && statusCode != 308 && statusCode != 401) {
        statusCode = 302
    }

    ctx.SetStatusCode(statusCode)
    ctx.Response.Header.SetBytesKV(headerLocation, raw)  // 设置 Location 头
}
```

**关键特性**:
- 允许 `401` 作为重定向状态码（非标准但代理支持）
- 非法状态码自动降级为 `302 Found`
- 始终设置 `Location` 响应头
- HTML body 包含可点击的链接（非 HEAD 请求）

---

### 8.6 响应示例对比

#### Legacy - Basic Auth 场景（唯一带挑战头）
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="Authelia"
Content-Type: text/plain; charset=utf-8

401 Unauthorized
```

#### AuthRequest - 所有场景（401 + Location）
```http
HTTP/1.1 401 Unauthorized
Location: https://auth.example.com/?rd=https%3A%2F%2Fapp.example.com
Content-Type: text/html; charset=utf-8

<a href="https://auth.example.com/?rd=...">401 Unauthorized</a>
```

#### ForwardAuth/ExtAuthz - 浏览器 GET（302 重定向）
```http
HTTP/1.1 302 Found
Location: https://auth.example.com/?rd=https%3A%2F%2Fapp.example.com
Content-Type: text/html; charset=utf-8

<a href="https://auth.example.com/?rd=...">302 Found</a>
```

#### ForwardAuth/ExtAuthz - API 场景（401 + Location）
```http
HTTP/1.1 401 Unauthorized
Location: https://auth.example.com/?rd=https%3A%2F%2Fapp.example.com
Content-Type: text/html; charset=utf-8

<a href="https://auth.example.com/?rd=...">401 Unauthorized</a>
```

---

### 8.7 设计意图与适用场景

| 实现 | 设计理念 | 适用代理 | 推荐场景 |
|-----|---------|---------|---------|
| **Legacy** | 完整 HTTP 语义，支持 Basic Auth 挑战 | Traefik v1, Nginx | 需要支持浏览器 Basic Auth 弹窗 |
| **AuthRequest** | Nginx 模块兼容，统一 401 处理 | Nginx | Nginx auth_request 模块 |
| **ForwardAuth** | Traefik 兼容，智能区分浏览器/API | Traefik v2+ | 现代部署，兼顾用户体验与 API |
| **ExtAuthz** | Envoy 服务网格兼容 | Envoy, Istio | 服务网格架构 |

---

## 九、完整认证-授权链路时序图

```
用户访问受保护资源
    │
    ▼
[反向代理] 发送认证请求到 Authelia
    │
    ▼
1. 解析目标对象 (Object)
   ├─ Legacy: X-Original-URL / X-Forwarded-*
   ├─ AuthRequest: X-Original-URL + X-Original-Method
   ├─ ForwardAuth: X-Forwarded-*
   └─ ExtAuthz: X-Forwarded-* + Host + Path
    │
    ▼
2. 获取 Session Provider
   └─ 根据域名匹配对应的会话配置
    │
    ▼
3. 确定 Authelia 门户 URL
   └─ 用于构造重定向地址
    │
    ▼
4. 执行认证策略链
   ├─ 尝试 CookieSession 策略
   │  └─ 从 Cookie 加载会话 → 有会话 → 返回 Authn
   ├─ 尝试 HeaderAuthorization 策略
   │  ├─ Basic Auth → 验证用户名密码
   │  └─ Bearer Token → OIDC 内省
   ├─ 尝试 HeaderProxyAuthorization 策略
   └─ 尝试 HeaderLegacy 策略
    │
    ▼
5. 计算所需授权级别
   ├─ 构造 Subject (用户/组/IP/ClientID)
   ├─ 遍历访问控制规则匹配
   └─ 返回 required Level (Bypass/OneFactor/TwoFactor/Deny)
    │
    ▼
6. 认证级别比较决策
   └─ isAuthzResult(actual, required, hasSubjects)
    │
    ▼
7. 生成最终响应（视实现而定）
   ├─ Authorized (200)
   │  └─ Remote-User/Remote-Groups/Remote-Name/Remote-Email
   ├─ Unauthorized（四种实现差异）
   │  ├─ Legacy: 302/303/401 (+ WWW-Authenticate 仅 Basic Auth)
   │  ├─ AuthRequest: 统一 401 + Location
   │  ├─ ForwardAuth: 302/303/401 + Location
   │  └─ ExtAuthz: 302/303/401 + Location
   └─ Forbidden (403)
    │
    ▼
[反向代理] 根据响应决定
   ├─ 200 → 转发请求到后端
   ├─ 302/303 → 转发重定向到用户浏览器
   └─ 401/403 → 返回错误给用户
```

---

## 十、两种 Provider 对比总结

| 特性 | File Provider | LDAP Provider |
|------|---------------|---------------|
| **数据存储** | 本地 YAML 文件 | 远程目录服务 |
| **密码验证** | 本地哈希匹配 | LDAP BIND 操作 |
| **性能** | 极高（内存操作） | 网络 IO 依赖 |
| **扩展性** | 有限（静态配置） | 极高（企业级目录） |
| **动态更新** | 文件监听重载 | 实时查询 |
| **组管理** | 用户内联配置 | 独立组条目搜索 |
| **连接池** | 不适用 | 支持 |
| **密码修改** | 支持 | 支持（多种方式） |
| **Referral** | 不适用 | 支持 |
| **适用场景** | 小型部署、测试 | 企业部署、集中认证 |
| **高可用** | 文件复制 | LDAP 多服务器 |
| **用户搜索** | 邮箱/大小写不敏感 | LDAP 过滤器灵活配置 |
| **属性映射** | YAML 直接定义 | LDAP 属性到内部模型映射 |

---

## 十一、关键代码索引

| 功能 | 文件位置 | 核心函数/类型 |
|------|----------|--------------|
| Provider 选择入口 | `internal/middlewares/util.go:85-95` | `NewAuthenticationProvider()` |
| UserProvider 接口 | `internal/authentication/user_provider.go` | `UserProvider` interface |
| File Provider 实现 | `internal/authentication/file_user_provider.go` | `FileUserProvider` |
| File 数据库 | `internal/authentication/file_user_provider_database.go` | `FileUserDatabase.Load()` |
| LDAP Provider 实现 | `internal/authentication/ldap_user_provider.go` | `LDAPUserProvider` |
| 认证策略接口 | `internal/handlers/handler_authz_types.go:109-114` | `AuthnStrategy` interface |
| Cookie 策略 | `internal/handlers/handler_authz_authn.go:86-158` | `CookieSessionAuthnStrategy.Get()` |
| Header 策略 | `internal/handlers/handler_authz_authn.go:165-254` | `HeaderAuthnStrategy.Get()` |
| 授权主处理器 | `internal/handlers/handler_authz.go:15-110` | `Authz.Handler()` |
| 授权决策器 | `internal/authorization/authorizer.go` | `Authorizer.GetRequiredLevel()` |
| Legacy 未授权 | `internal/handlers/handler_authz_impl_legacy.go:34-70` | `handleAuthzUnauthorizedLegacy()` |
| AuthRequest 未授权 | `internal/handlers/handler_authz_impl_authrequest.go:39-48` | `handleAuthzUnauthorizedAuthRequest()` |
| ForwardAuth 未授权 | `internal/handlers/handler_authz_impl_forwardauth.go:36-61` | `handleAuthzUnauthorizedForwardAuth()` |
| ExtAuthz 未授权 | `internal/handlers/handler_authz_impl_extauthz.go:36-61` | `handleAuthzUnauthorizedExtAuthz()` |
| WWW-Authenticate 设置 | `internal/handlers/handler_authz_common.go:78-84` | `handleAuthzUnauthorizedAuthorizationBasic()` |
| SpecialRedirect | `internal/middlewares/authelia_context.go:587-621` | `SpecialRedirect()` |
| 要求认证中间件 | `internal/middlewares/require_auth.go` | `Require1FA()`, `RequireElevated()` |

---

## 十二、扩展点与优化建议

### 12.1 现有扩展机制

1. **额外属性系统**: File Provider 支持自定义额外属性及类型验证
2. **表达式引擎**: 支持基于用户属性的动态策略计算
3. **密码哈希算法**: 可配置多种哈希算法及参数
4. **LDAP 实现预置**: Active Directory/RFC2307bis/FreeIPA/LLDAP/GLAuth

### 12.2 潜在优化方向

1. **File Provider 增量加载**: 当前是全量重载，可考虑差异更新
2. **LDAP 属性缓存**: 减少重复的 LDAP 查询
3. **异步组解析**: 大型部署中组查询可能成为瓶颈
4. **预取策略**: 根据访问模式预测性加载用户数据
5. **多 Provider 支持**: 同时支持 File + LDAP 作为后备
6. **AuthRequest 增加 WWW-Authenticate**: 为 API 场景提供更好的 Basic Auth 支持

---

*报告生成时间: 2026-05-16*
*基于 Authelia 代码库分析*
