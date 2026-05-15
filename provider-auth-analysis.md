# Authelia 用户提供者认证链路分析报告

## 概述

本文档详细分析了 Authelia 系统中两种用户数据提供者（File Provider 和 LDAP Provider）从用户数据获取到认证决策的完整处理链路。

---

## 一、核心架构总览

### 1.1 认证决策流程

```
用户请求
    ↓
[认证策略层]
    ├─ CookieSession 策略
    ├─ HeaderAuthorization 策略 (Basic/Bearer)
    ├─ HeaderProxyAuthorization 策略
    └─ HeaderLegacy 策略
    ↓
[用户提供者层]
    ├─ FileUserProvider (YAML文件)
    └─ LDAPUserProvider (目录服务)
    ↓
[用户详情获取]
    ├─ CheckUserPassword() 密码验证
    ├─ GetDetails() 基本信息
    └─ GetDetailsExtended() 扩展信息
    ↓
[授权决策层]
    ├─ Authorizer.GetRequiredLevel()
    └─ 访问控制规则匹配
    ↓
[最终结果]
    ├─ AuthzResultAuthorized (200)
    ├─ AuthzResultUnauthorized (401)
    └─ AuthzResultForbidden (403)
```

---

## 二、用户提供者接口定义

### 2.1 UserProvider 接口

**文件位置**: `internal/authentication/user_provider.go`

```go
type UserProvider interface {
    // 检查用户密码
    CheckUserPassword(username string, password string) (valid bool, err error)
    
    // 获取用户基本详情
    GetDetails(username string) (details *UserDetails, err error)
    
    // 获取用户扩展详情
    GetDetailsExtended(username string) (details *UserDetailsExtended, err error)
    
    // 更新用户密码
    UpdatePassword(username string, newPassword string) (err error)
    
    // 修改用户密码（需验证旧密码）
    ChangePassword(username string, oldPassword string, newPassword string) (err error)
    
    // 关闭连接
    Close() (err error)
}
```

### 2.2 用户数据模型

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
    Address        *UserDetailsAddress // 地址
    Extra          map[string]any  // 额外属性
    UserDetails                    // 内嵌基本信息
}
```

---

## 三、File Provider 详细分析

### 3.1 架构概述

**文件位置**: `internal/authentication/file_user_provider.go`
**数据库实现**: `internal/authentication/file_user_provider_database.go`

#### 核心组件关系

```
FileUserProvider
    ├─ config *schema.AuthenticationBackendFile  // 配置
    ├─ hash algorithm.Hash                        // 密码哈希算法
    ├─ database FileUserProviderDatabase          // 数据库接口
    └─ mutex sync.Mutex                           // 互斥锁
```

### 3.2 FileUserDatabase 数据加载流程

```go
type FileUserDatabase struct {
    *sync.RWMutex
    Users  map[string]FileUserDatabaseUserDetails  // 用户映射
    Path   string                                  // YAML文件路径
    Emails map[string]string                       // 邮箱反向映射
    Aliases map[string]string                      // 别名反向映射
    
    SearchEmail bool  // 是否支持邮箱搜索
    SearchCI    bool  // 是否大小写不敏感搜索
    Extra       map[string]expression.ExtraAttribute // 额外属性定义
}
```

#### 数据加载时序图

```
Load() 被调用
    ↓
1. 读取 YAML 文件内容
    ↓
2. yaml.Unmarshal 解析到 FileDatabaseModel
    ↓
3. 验证配置结构有效性
    ↓
4. ReadToFileUserDatabase() 转换:
    ├─ 解码密码哈希 (crypt.Decode)
    ├─ 解析 URI 类型属性
    ├─ 验证额外属性类型
    └─ 构建 Users map
    ↓
5. LoadAliases() 构建反向映射:
    ├─ 构建 Emails map (邮箱→用户名)
    └─ 构建 Aliases map (小写用户名→用户名)
    ↓
返回成功/错误
```

### 3.3 密码验证流程

```go
func (p *FileUserProvider) CheckUserPassword(username, password string) (bool, error)
```

**执行步骤**:
1. **获取用户详情**: `database.GetUserDetails(username)`
   - 按顺序检查: 邮箱搜索 → 大小写不敏感搜索 → 精确用户名匹配
2. **禁用检查**: 如用户已禁用，返回 `ErrUserNotFound`
3. **密码匹配**: `details.Password.MatchAdvanced(password)`
   - 支持 Argon2, SHA2Crypt, PBKDF2, Scrypt, Bcrypt 等算法

### 3.4 用户详情获取

```go
func (p *FileUserProvider) GetDetails(username string) (*UserDetails, error)
```

**执行步骤**:
1. 从数据库获取 `FileUserDatabaseUserDetails`
2. 检查用户是否禁用
3. 转换为 `UserDetails` 类型：
   ```go
   return &UserDetails{
       Username:    details.Username,
       DisplayName: details.DisplayName,
       Emails:      emails,  // 从 details.Email 转换
       Groups:      details.Groups,
   }
   ```

### 3.5 动态重新加载机制

```go
func (p *FileUserProvider) Reload() (reloaded bool, err error)
```

**特性**:
- 冷却时间保护：防止频繁重载
- 原子替换：使用互斥锁确保线程安全
- 内容变更检测：仅在实际变更时重载

### 3.6 配置示例

```yaml
# users_database.yml
users:
  john:
    password: "$argon2id$v=19$m=65536,t=3,p=2$..."
    displayname: "John Doe"
    email: john@example.com
    groups:
      - admins
      - devs
    disabled: false
    given_name: "John"
    family_name: "Doe"
```

---

## 四、LDAP Provider 详细分析

### 4.1 架构概述

**文件位置**: `internal/authentication/ldap_user_provider.go`

#### 核心组件关系

```
LDAPUserProvider
    ├─ config *schema.AuthenticationBackendLDAP  // LDAP配置
    ├─ factory LDAPClientFactory                 // LDAP客户端工厂
    │   ├─ StandardLDAPClientFactory (标准模式)
    │   └─ PooledLDAPClientFactory (连接池模式)
    └─ 动态配置解析
        ├─ usersBaseDN       // 用户搜索基准DN
        ├─ usersAttributes   // 用户属性映射
        └─ groupsBaseDN      // 组搜索基准DN
```

### 4.2 LDAP 客户端工厂模式

#### 连接池模式优势
- 复用连接减少握手开销
- 控制并发连接数
- 自动管理连接生命周期

### 4.3 用户密码验证流程

```go
func (p *LDAPUserProvider) CheckUserPassword(username, password string) (bool, error)
```

**执行步骤**:

```
1. 获取 LDAP 客户端连接
    ↓ factory.GetClient()
2. 搜索用户 DN
    ↓ p.getUserProfile(client, username)
    ├─ 使用 usersFilter 模板替换 {input}
    ├─ 执行 LDAP Search 请求
    ├─ 检查返回结果数量 (必须==1)
    └─ 解析返回属性得到用户 DN
    ↓
3. 使用用户 DN 绑定验证
    ↓ factory.GetClient(WithDN, WithPassword)
    ├─ 成功绑定 → 返回 true
    └─ 绑定失败 → 返回错误
    ↓
4. 释放客户端连接回连接池
```

### 4.4 用户 Profile 获取流程

```go
func (p *LDAPUserProvider) getUserProfile(client, username) (*ldapUserProfile, error)
```

**关键过滤器替换**:
```go
// 支持的占位符
{input}              → 用户名输入
{date-time}          → 当前时间 (RFC3339)
{date-time-epoch}    → Unix 时间戳
{date-time-msepoch}  → Microsoft 时间戳
```

**LDAP 属性映射示例**:
```go
type ldapUserProfile struct {
    DN          string   // 用户唯一DN
    Username    string   // 用户名属性
    DisplayName string   // 显示名属性
    Emails      []string // 邮箱属性
    MemberOf    []string // 成员组DN
}
```

### 4.5 用户组获取流程

```go
func (p *LDAPUserProvider) getUserGroups(client, username, profile) ([]string, error)
```

#### 两种组搜索模式

| 模式 | 说明 | 适用场景 |
|------|------|----------|
| **filter** | 独立搜索组条目，匹配成员属性 | 大多数LDAP服务器 |
| **memberof** | 利用用户的 memberOf 属性反向匹配组 | Active Directory |

#### 组搜索过滤器占位符
```go
{input}              → 原始用户名
{username}           → LDAP用户名属性
{dn}                 → 用户完整DN
{memberof_dn}        → 展开为多值OR过滤器
{memberof_rdn}       → 展开为RDN过滤器
```

### 4.6 密码修改流程

```go
func (p *LDAPUserProvider) setPassword(client, profile, username, old, new) error
```

**三种实现方式**:

| LDAP类型 | 实现方式 | 说明 |
|----------|----------|------|
| **Active Directory** | LDAP Modify | UnicodePwd 属性，需要SSL |
| **支持 RFC 3062** | Password Modify Extended Op | 标准密码修改扩展操作 |
| **其他** | LDAP Modify | userPassword 属性直接替换 |

### 4.7 Referral 处理机制

- 自动跟随 LDAP Referral
- 递归搜索多个 LDAP 服务器
- 合并多服务器搜索结果
- 去重处理重复条目

---

## 五、认证策略层分析

### 5.1 策略接口定义

**文件位置**: `internal/handlers/handler_authz_types.go`

```go
type AuthnStrategy interface {
    // 获取认证信息
    Get(ctx *middlewares.AutheliaCtx, provider *session.Session, object *authorization.Object) (*Authn, error)
    
    // 是否能处理未授权情况
    CanHandleUnauthorized() bool
    
    // 是否为头部策略
    HeaderStrategy() bool
    
    // 处理未授权响应
    HandleUnauthorized(ctx *middlewares.AutheliaCtx, authn *Authn, redirectionURL *url.URL)
}
```

### 5.2 CookieSession 认证策略

**文件位置**: `internal/handlers/handler_authz_authn.go:86-158`

#### 核心流程

```
1. 从 Cookie 获取 Session
    ↓
2. 验证 Session 有效性
    ├─ 检查 Cookie Domain 匹配
    ├─ 检查会话是否过期
    ├─ 检查最后活动时间
    └─ 检查 Refresh TTL (定期刷新用户信息)
    ↓
3. 刷新用户信息（如需要）
    ↓ UserProvider.GetDetails()
    ├─ 比较 Email/Group/DisplayName 变更
    └─ 更新 Session 中的用户信息
    ↓
4. 返回 Authn 对象
    ├─ Level: OneFactor/TwoFactor/NotAuthenticated
    ├─ Details: UserDetails（用户名、组、邮箱等）
    └─ Username: 友好显示名
```

#### Session 刷新机制

**配置控制**: `authentication_backend.refresh_interval`

| 刷新模式 | 行为 |
|----------|------|
| `always` | 每次请求都刷新用户信息 |
| `disable` | 从不刷新 |
| `duration` | 按指定间隔刷新（如 1h） |

### 5.3 Header Authorization 认证策略

#### Basic Auth 处理流程

```go
func DefaultBasicAuthHandler(ctx, authorization) (valid bool, cached bool, err error)
```

```
1. 解析 Authorization 头部
    ↓ Base64 解码
2. 提取 username:password
    ↓
3. 监管检查 (Regulator)
    ├─ 检查用户是否被封禁
    ├─ 记录认证尝试
    └─ 失败次数计数
    ↓
4. UserProvider.CheckUserPassword()
    ├─ FileProvider: 本地哈希匹配
    └─ LDAPProvider: LDAP 绑定验证
    ↓
5. 成功 → 缓存结果（如启用）
    ↓
6. 返回认证级别: OneFactor
```

#### Bearer Token (OIDC) 处理流程

```
1. 解析 Bearer Token
    ↓
2. Token 内省 (Introspection)
    ↓ OpenIDConnect.IntrospectToken()
    ├─ 验证 Token 签名
    ├─ 检查 Token 是否过期
    ├─ 验证 Scope (authelia.bearer.authz)
    └─ 验证 Audience (目标URL)
    ↓
3. 提取 Session 信息
    ├─ Username
    ├─ Authentication Methods References
    └─ Client ID (客户端凭证模式)
    ↓
4. 确定认证级别
    ├─ Client Credentials → OneFactor
    ├─ AMR 包含 mfa → TwoFactor
    └─ 其他 → OneFactor
```

### 5.4 策略选择机制

```go
func (authz *Authz) authn(ctx, provider, object) (*Authn, AuthnStrategy, error)
```

**策略遍历顺序**:
1. 按注册顺序依次尝试每个策略
2. 第一个返回 `Level != NotAuthenticated` 的策略胜出
3. 如所有策略都失败，使用最后一个策略的错误处理

---

## 六、授权决策层分析

### 6.1 Authorizer 核心组件

**文件位置**: `internal/authorization/authorizer.go`

```go
type Authorizer struct {
    defaultPolicy Level          // 默认策略
    rules         []*AccessControlRule // 访问控制规则列表
    mfa           bool           // 是否启用MFA
}
```

### 6.2 访问控制规则匹配

```go
func (p *Authorizer) GetRequiredLevel(subject Subject, object Object) (hasSubjects bool, level Level)
```

#### Subject 结构

```go
type Subject struct {
    Username string   // 用户名
    Groups   []string // 用户组
    ClientID string   // OIDC客户端ID
    IP       net.IP   // 客户端IP
}
```

#### Object 结构

```go
type Object struct {
    URL    *url.URL // 目标URL
    Domain string   // 域名
    Method string   // HTTP方法
}
```

#### 规则匹配顺序

```
遍历规则列表（按配置顺序）:
    ├─ 匹配 Domain
    ├─ 匹配 Resources (路径正则)
    ├─ 匹配 Methods (HTTP方法)
    ├─ 匹配 Networks (IP/CIDR)
    └─ 匹配 Subjects (用户/组)
        ↓ 第一个匹配的规则生效
            ↓ 返回规则的 Policy 级别
```

### 6.3 认证级别比较

**文件位置**: `internal/handlers/handler_authz_util.go`

```go
func isAuthzResult(actual authentication.Level, required authorization.Level, hasSubjects bool) AuthzResult
```

#### 决策矩阵

| 实际级别 | 要求级别 | hasSubjects | 结果 |
|----------|----------|-------------|------|
| NotAuthenticated | Bypass | false | Authorized |
| NotAuthenticated | Bypass | true | Unauthorized |
| NotAuthenticated | * | * | Unauthorized |
| OneFactor | OneFactor | * | Authorized |
| OneFactor | TwoFactor | * | Unauthorized |
| TwoFactor | OneFactor | * | Authorized |
| TwoFactor | TwoFactor | * | Authorized |
| * | Deny | * | Forbidden |

---

## 七、完整认证决策链路

### 7.1 Handler 主流程

**文件位置**: `internal/handlers/handler_authz.go:15-110`

```
1. 获取授权目标对象
    ↓ handleGetObject()
    ├─ 从 X-Forwarded-* 头部提取
    ├─ 或从查询参数提取
    └─ 验证 URL Scheme (必须 https/wss)
    ↓
2. 获取 Session Provider
    ↓ ctx.GetSessionProviderByTargetURI()
    ↓
3. 获取 Authelia Portal URL
    ↓ getAutheliaURL()
    ↓
4. 执行认证策略链
    ↓ authz.authn()
    ├─ 遍历所有 AuthnStrategy
    └─ 获取 Authn 结果
    ↓
5. 计算所需授权级别
    ↓ Authorizer.GetRequiredLevel()
    ├─ 构造 Subject (用户/组/IP/ClientID)
    ├─ 匹配访问控制规则
    └─ 返回 required Level
    ↓
6. 认证决策比较
    ↓ isAuthzResult()
    ├─ AuthzResultAuthorized → 200 + 头部
    ├─ AuthzResultUnauthorized → 401 + 重定向/WWW-Authenticate
    └─ AuthzResultForbidden → 403
```

### 7.2 成功授权响应

```go
func handleAuthzAuthorizedStandard(ctx, authn)
```

**设置的响应头部**:
```http
Remote-User: john
Remote-Groups: admins,devs
Remote-Name: John Doe
Remote-Email: john@example.com
```

---

## 八、两种 Provider 对比总结

| 特性 | File Provider | LDAP Provider |
|------|---------------|---------------|
| **数据存储** | 本地 YAML 文件 | 远程 LDAP 目录服务 |
| **密码验证** | 本地哈希匹配 | LDAP BIND 操作 |
| **性能** | 极高（内存操作） | 网络IO依赖 |
| **扩展性** | 有限（静态配置） | 极高（企业级目录） |
| **动态更新** | 文件监听重载 | 实时查询 |
| **组管理** | 用户内联配置 | 独立组条目搜索 |
| **连接池** | 不适用 | 支持 |
| **密码修改** | 支持 | 支持（多种方式） |
| **Referral** | 不适用 | 支持 |
| **适用场景** | 小型部署、测试 | 企业部署、集中认证 |
| **高可用** | 文件复制 | LDAP 多服务器 |

---

## 九、关键代码索引

| 功能 | 文件位置 | 核心函数 |
|------|----------|----------|
| 用户提供者接口 | `internal/authentication/user_provider.go` | `UserProvider` interface |
| File Provider实现 | `internal/authentication/file_user_provider.go` | `FileUserProvider` |
| File数据库 | `internal/authentication/file_user_provider_database.go` | `FileUserDatabase.Load()` |
| LDAP Provider实现 | `internal/authentication/ldap_user_provider.go` | `LDAPUserProvider` |
| 认证策略接口 | `internal/handlers/handler_authz_types.go` | `AuthnStrategy` interface |
| Cookie策略 | `internal/handlers/handler_authz_authn.go` | `CookieSessionAuthnStrategy.Get()` |
| Header策略 | `internal/handlers/handler_authz_authn.go` | `HeaderAuthnStrategy.Get()` |
| 授权主处理器 | `internal/handlers/handler_authz.go` | `Authz.Handler()` |
| 授权决策器 | `internal/authorization/authorizer.go` | `Authorizer.GetRequiredLevel()` |
| 要求认证中间件 | `internal/middlewares/require_auth.go` | `Require1FA()`, `RequireElevated()` |

---

## 十、扩展点与优化建议

### 10.1 现有扩展机制

1. **额外属性系统**: File Provider 支持自定义额外属性及类型验证
2. **表达式引擎**: 支持基于用户属性的动态策略计算
3. **密码哈希算法**: 可配置多种哈希算法参数

### 10.2 潜在优化方向

1. **File Provider 增量加载**: 当前是全量重载，可考虑差异更新
2. **LDAP 属性缓存**: 减少重复的 LDAP 查询
3. **异步组解析**: 大型部署中组查询可能成为瓶颈
4. **预取策略**: 根据访问模式预测性加载用户数据

---

*报告生成时间: 2026-05-16*
*基于 Authelia 代码库分析*
