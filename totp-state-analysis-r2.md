# Authelia TOTP 注册与验证机制分析报告（修订版）

## 1. 核心入口与鉴权前置条件

### 1.1 注册入口（/api/secondfactor/totp/register）

| 方法 | 路径 | 鉴权中间件 | 前置条件 |
|------|------|-----------|---------|
| GET | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话**（近期重新验证过密码） |
| PUT | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话** |
| POST | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话** |
| DELETE | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话** |

**会话提升说明**：
- 用户需要在近期（可配置）重新验证密码
- 目的是防止会话劫持后被用于注册新的 2FA 设备

### 1.2 登录验证入口（/api/secondfactor/totp）

| 方法 | 路径 | 鉴权中间件 | 前置条件 |
|------|------|-----------|---------|
| GET | `/api/secondfactor/totp` | middleware1FA | 需要普通 1FA 会话（已通过密码验证） |
| POST | `/api/secondfactor/totp` | middlewareRateLimitTOTP | 1FA + TOTP 速率限制 |
| DELETE | `/api/secondfactor/totp` | middleware1FA | 需要普通 1FA 会话 |

---

## 2. 注册流程：密钥生成、临时存储、持久化绑定

### 2.1 第一步：获取注册选项（TOTPRegisterGET）

**核心逻辑**：
- 返回允许的 TOTP 算法列表、位数、周期配置
- 供前端展示用户可选的配置项

### 2.2 第二步：生成临时密钥（TOTPRegisterPUT）

**密钥生成流程**：

```
用户请求生成密钥
    ↓
[1] 验证会话已提升（Elevated 1FA）
    ↓
[2] 验证算法、周期、位数在策略允许范围内
    ↓
[3] 调用 TOTP Provider 生成随机密钥
    ↓
[4] 存入用户会话临时对象（10分钟有效期）
    ↓
[5] 返回 otpauth URL（用于扫码） + Base32 密钥（手动输入）
```

**临时会话对象结构** (`internal/session/types.go`)：
```go
type TOTP struct {
    Issuer    string    // 发行方
    Algorithm string    // 算法: SHA1/SHA256/SHA512
    Digits    uint32    // 位数: 6/8
    Period    uint      // 周期: 默认30秒
    Secret    string    // 明文密钥
    Expires   time.Time // 10分钟后过期
}
```

**关键安全设计**：
- 密钥只在会话 Cookie 中传输（会话本身加密）
- 10分钟有效期限制了暴露窗口

### 2.3 第三步：验证并绑定（TOTPRegisterPOST）

```
用户提交 TOTP 验证码
    ↓
[1] 检查会话中存在临时 TOTP 对象
    ↓
[2] 检查会话未过期（10分钟）
    ↓
[3] 使用会话中的密钥验证用户输入
    ↓
[4] 验证失败 → 返回 403 Forbidden（**不记录监管日志，不触发封禁**）
    ↓
[5] 验证成功 → 防重放检查（记录本次使用的时间步）
    ↓
[6] 配置持久化到数据库（TOTPConfiguration 表）
    ↓
[7] 清除会话中的临时 TOTP 对象
    ↓
[8] 记录审计日志（2FA 方法已添加）
    ↓
[9] 返回成功
```

**持久化数据结构** (`internal/model/totp_configuration.go`)：
```go
type TOTPConfiguration struct {
    ID         int
    CreatedAt  time.Time      // 创建时间
    LastUsedAt sql.NullTime   // 最后使用时间（初始为 NULL）
    Username   string         // 所属用户
    Issuer     string         // 发行方名称
    Algorithm  string         // 哈希算法
    Digits     uint32         // 位数
    Period     uint           // 周期(秒)
    Secret     []byte         // 共享密钥（加密存储）
}
```

---

## 3. 登录验证流程与状态流转

### 3.1 TimeBasedOneTimePasswordPOST 核心流程

```
用户提交 TOTP 验证码
    ↓
[1] 验证用户已通过 1FA（密码）认证
    ↓
[2] 格式校验：必须是 6 或 8 位数字
    ↓
[3] 从数据库加载用户 TOTP 配置
    ↓
[4] 使用配置中的密钥验证用户输入
    ↓
[5] 验证失败：
    ├─ 记录失败日志（AuthTypeTOTP）
    ├─ **不触发封禁检查**（只记录，不封禁）
    └─ 返回 403 Forbidden
    ↓
[6] 验证成功：
    ├─ 防重放检查（时间步是否已使用）
    │   ├─ 已使用且防重放启用 → 拒绝
    │   └─ 未使用 → 记录时间步到历史表
    ├─ 记录成功认证日志
    ├─ **会话再生**（防止会话固定攻击）
    ├─ 更新 LastUsedAt 时间戳
    ├─ 设置会话为二因素认证级别
    └─ 重定向到目标 URL
```

### 3.2 会话认证级别状态机

**初始状态**：
```
NotAuthenticated
      ↓ 密码验证成功（FirstFactorPasswordPOST）
OneFactor
  ├─ FirstFactorAuthnTimestamp = 现在
  └─ AuthenticationMethodRefs: {KnowledgeBasedAuthentication: true}
```

**TOTP 验证后状态转换**：
```go
// internal/session/user_session.go:74
func (s *UserSession) SetTwoFactorTOTP(now time.Time) {
    s.SecondFactorAuthnTimestamp = now.Unix()  // 设置2FA时间戳
    s.LastActivity = now.Unix()
    s.AuthenticationMethodRefs.TOTP = true     // 标记TOTP认证方式
}
```

**最终状态**：
```
TwoFactor
  ├─ FirstFactorAuthnTimestamp
  ├─ SecondFactorAuthnTimestamp = 现在
  └─ AuthenticationMethodRefs:
        {KnowledgeBasedAuthentication: true, TOTP: true}
```

---

## 4. 注册验证 vs 登录验证：关键差异对比

| 维度 | 注册验证（TOTPRegisterPOST） | 登录验证（TimeBasedOneTimePasswordPOST） |
|-----|-----------------------------|------------------------------------------|
| **鉴权前置** | 需要 Elevated 1FA（会话提升） | 需要普通 1FA |
| **密钥来源** | 从用户会话的临时 TOTP 对象读取 | 从数据库 TOTPConfiguration 表加载 |
| **状态前置** | 会话存在 `TOTP` 对象且未过期（10分钟） | 无临时对象，只需要已通过 1FA |
| **验证后动作** | 1. 配置持久化到数据库<br>2. 清除会话临时 TOTP 对象<br>3. **不更新认证级别** | 1. 更新 LastUsedAt<br>2. 会话再生（Session Regeneration）<br>3. 设置为 2FA 认证级别 |
| **失败记录** | **不调用 doMarkAuthenticationAttempt**<br>只记录普通错误日志 | 调用 doMarkAuthenticationAttempt，记录监管日志 |
| **防重放** | 记录使用的时间步 | 检查时间步历史 + 记录新时间步 |
| **触发封禁** | **不触发封禁** | **不触发封禁**（封禁仅针对 AuthType1FA） |
| **会话再生** | 不执行 | 执行（防止会话固定攻击） |

---

## 5. 非法尝试拦截与异常恢复路径

### 5.1 监管封禁机制的真实边界（关键修正）

**代码证据** (`internal/regulation/regulator.go:45-48`)：
```go
// We only need to perform the ban checks when; the attempt is unsuccessful, there is not an effective ban in place,
// regulation is enabled, and the authentication type is 1FA. Thus if this is not the case we can return here.
if successful || banned || (!r.ips && !r.users) || authType != AuthType1FA {
    return
}
```

**结论**：
- ✅ **封禁仅在 1FA（密码验证）失败时触发**
- ❌ **TOTP 验证失败** → 记录日志，但**不触发封禁检查**
- ❌ **注册验证失败** → 不记录监管日志，不触发封禁

### 5.2 封禁触发条件（仅适用于 1FA）

| 参数 | 说明 |
|------|------|
| MaxRetries | 在 FindTime 窗口内允许的最大失败次数 |
| FindTime | 计数回溯时间窗口（如 30 秒） |
| BanTime | 封禁持续时间（如 10 分钟） |
| Modes | 封禁维度：`ip`、`user` 或两者 |

**封禁判断逻辑**：
```go
func (r *Regulator) expires(since time.Time, records []model.RegulationRecord) *time.Time {
    // 收集连续失败记录，遇到成功记录则重置计数
    for _, record := range records {
        if record.Successful {
            break  // 遇到成功，终止计数
        }
        failures = append(failures, record)
    }
    
    // 超过 MaxRetries 则触发封禁
    if len(failures) >= r.config.MaxRetries {
        banexp := failures[0].Time.Add(r.config.BanTime)
        return &banexp  // 返回封禁到期时间
    }
    return nil  // 不封禁
}
```

### 5.3 各场景的异常恢复路径

#### 场景 1：TOTP 登录验证失败

```
验证失败
    ↓
[1] 调用 doMarkAuthenticationAttempt(false, BanTypeNone, AuthTypeTOTP)
    ↓
[2] 记录监管日志（但不触发封禁检查）
    ↓
[3] 返回 403 Forbidden
    ↓
[4] 用户可立即重试（受速率限制，但无封禁）
```

**可恢复条件**：
- 无需等待，可立即重试
- 但受速率限制中间件保护（middlewareRateLimitTOTP）
- 连续失败不会导致封禁

#### 场景 2：TOTP 码重放攻击

```
用户提交 TOTP 码
    ↓
[1] 计算时间步：step = now / Period
    ↓
[2] 查询 TOTP 历史表：该用户 + 该时间步
    ↓
[3] 记录已存在：
    ├─ DisableReuseSecurityPolicy = false（默认）→ 返回 403
    └─ DisableReuseSecurityPolicy = true → 记录警告但放行
    ↓
[4] 恢复：等待下一个时间步（默认 30 秒后）
```

#### 场景 3：注册会话过期

```
用户发起 POST 验证
    ↓
[1] 检查 userSession.TOTP 是否存在
    ↓
[2] 检查 Expires 是否已过期
    ↓
[3] 会话缺失或已过期 → 返回 403
    ↓
[4] 恢复：用户需要重新发起 PUT 请求生成新密钥
```

#### 场景 4：1FA 密码验证失败触发封禁

```
密码验证失败
    ↓
[1] 记录监管日志（AuthType1FA）
    ↓
[2] 检查 FindTime 窗口内失败次数
    ↓
[3] >= MaxRetries → 封禁 IP 或用户
    ├─ 写入 banned_ip 或 banned_user 表
    └─ 设置 BanTime 后的过期时间
    ↓
[4] 恢复：
    ├─ 自动恢复：等待 BanTime 时长后自动解禁
    └─ 手动恢复：管理员删除封禁记录
```

---

## 6. 安全防护机制总结

| 防护机制 | 注册流程 | 登录验证流程 |
|---------|---------|------------|
| 会话提升 (Elevated 1FA) | ✅ 必需 | ❌ 不需要 |
| 速率限制 | ❌ 无 | ✅ 有（middlewareRateLimitTOTP） |
| 防重放检查 | ✅ 记录时间步 | ✅ 检查+记录时间步 |
| 会话再生 | ❌ 不执行 | ✅ 验证成功后执行 |
| 监管封禁 | ❌ 不触发 | ❌ 不触发（仅1FA触发） |
| 临时密钥有效期 | ✅ 10分钟 | ❌ 不适用 |

---

## 7. 关键代码位置参考

| 模块 | 文件路径 | 关键行 |
|------|---------|--------|
| 注册处理器 | `internal/handlers/handler_register_totp.go` | 18-357 |
| 登录验证处理器 | `internal/handlers/handler_sign_totp.go` | 69-211 |
| 监管封禁逻辑 | `internal/regulation/regulator.go` | 45-55 |
| 会话类型定义 | `internal/session/types.go` | 51-58 |
| TOTP 配置模型 | `internal/model/totp_configuration.go` | 29-202 |
| 路由与中间件 | `internal/server/handlers.go` | 305-312 |
| 会话状态设置 | `internal/session/user_session.go` | 73-77 |

---

## 修订记录

**修订版本 R2**：
1. 修正各入口的准确路径与真实鉴权前置条件
2. 关键修正：明确 TOTP 失败**不触发封禁**，封禁仅针对 AuthType1FA
3. 厘清失败记录、封禁触发条件与可恢复路径的真实边界
4. 补充注册与登录验证在会话状态流转上的详细差异
5. 更正防重放、会话再生等机制的适用场景
