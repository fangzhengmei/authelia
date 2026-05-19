# Session Elevation 机制分析

## 概述

敏感操作触发的会话权限提升（Session Elevation）是 Authelia 中用于保护敏感操作的安全机制。它通过"前端请求拦截 → 二次验证挑战 → 短期权限窗口"的完整链路，确保用户在执行敏感操作（如修改密码、管理 2FA 凭证等）前重新验证身份。

---

## 一、Elevation 状态存储位置

### 1.1 会话内存储结构

Elevation 状态存储在用户会话（UserSession）中，具体位置如下：

**核心数据结构**（`internal/session/types.go`）：

```go
// UserSession 是用户会话的主结构
type UserSession struct {
    // ... 其他字段
    Elevations Elevations  // 第47行
}

// Elevations 描述各种会话提升
type Elevations struct {
    User *Elevation  // 用户级别的提升
}

// Elevation 是单个提升的结构
type Elevation struct {
    ID       int       // 关联的一次性代码ID
    RemoteIP net.IP    // 创建提升时的远程IP
    Expires  time.Time // 提升过期时间
}
```

### 1.2 会话存储与 Cookie 的关系（修正版）

**重要更正**：Elevation 状态**不直接存储在 Cookie 中**。Cookie 与服务端会话存储有明确的职责分离：

```
浏览器 Cookie
    ↓ (仅存储未加密的 Session ID)
服务端会话存储（Memory / Redis）
    ↓ (存储完整 UserSession，Redis 模式下加密)
UserSession.Elevations.User
```

**详细分层说明**：

1. **Cookie 层 - 会话标识（Session ID）**：
   - 存储位置：浏览器 Cookie（默认名称 `authelia_session`）
   - 生成方式（`internal/session/provider_config.go:25-35`）：
     ```go
     c.SessionIDGeneratorFunc = func() []byte {
         bytes := make([]byte, 32)
         _, _ = rand.Read(bytes)  // 32字节加密随机数
         for i, b := range bytes {
             // 映射到字符集: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_!#$%^*"
             bytes[i] = randomSessionChars[b%byte(len(randomSessionChars))]
         }
         return bytes
     }
     ```
   - **是否加密**：Session ID 本身不加密，直接存储在 Cookie 中
   - 安全性依赖：32 字节随机数的熵值（256 位）

2. **服务端会话存储层 - 会话数据**：
   - **Memory 模式**（默认）：会话数据以明文 JSON 存储在服务端内存中
   - **Redis 模式**：会话数据存储在 Redis 中，**加密存储**
     - 加密触发位置（`internal/session/provider_config.go:98-100`）：
       ```go
       case config.Redis != nil:
           serializer = NewEncryptingSerializer(config.Secret)
       ```
     - 加密实现（`internal/session/encrypting_serializer.go:18-27`）：
       ```go
       type EncryptingSerializer struct {
           key [32]byte  // AES-256 密钥
       }
       func NewEncryptingSerializer(secret string) *EncryptingSerializer {
           key := sha256.Sum256([]byte(secret))  // 从 session.secret 派生密钥
           return &EncryptingSerializer{key}
       }
       ```
     - 加密流程：MessagePack 序列化 → AES-GCM 256 位加密 → 存储到 Redis
     - 解密流程：从 Redis 读取 → AES-GCM 解密 → MessagePack 反序列化

3. **UserSession 序列化流程**（`internal/session/session.go:30-78`）：
   - `GetSession()`：从服务端存储取出 → 解密（Redis 模式）→ 反序列化为 Go 结构体
   - `SaveSession()`：序列化为 JSON → 加密（Redis 模式）→ 存入服务端存储
   - Elevation 状态作为 UserSession 的一部分被完整持久化

**存储说明**：
- Elevation 状态以 `*Elevation` 指针形式存储，`nil` 表示未提升
- 状态持久化在**服务端会话存储**中（内存或 Redis），而非直接在 Cookie 中
- 每次请求通过 `ctx.GetSession()` 从服务端存储恢复

### 1.3 一次性代码（One-Time Code）存储

在验证过程中，挑战代码存储在持久化存储后端：

**位置**：`internal/model/one_time_code.go`
- 表名：`one_time_codes`
- 关联 Intent：`OTCIntentUserSessionElevation`（值为 `"use"`）
- 字段包括：
  - `id`：自增主键
  - `public_id`：UUID，用于公开引用（撤销链接中使用）
  - `code`：加密存储的一次性代码
  - `issued` / `expires`：签发和过期时间
  - `consumed` / `revoked`：消费和撤销时间
  - `issued_ip` / `consumed_ip` / `revoked_ip`：各阶段 IP
  - `username`：关联的用户名
  - `intent`：使用意图

---

## 二、失效机制

Elevation 状态有多重失效保障机制，确保安全性：

### 2.1 时间过期

**配置项**（`internal/configuration/schema/identity_validation.go`）：

```go
type IdentityValidationElevatedSession struct {
    CodeLifespan      time.Duration  // OTC 有效期，默认 5 分钟
    ElevationLifespan time.Duration  // 提升后有效期，默认 10 分钟
    // ...
}
```

**失效检查点**：
1. **GET /api/user/session/elevation**（`internal/handlers/handler_session_elevation.go:81`）：
   - 检查 `Expires.Before(now)`，如果过期则清除 elevation 状态
   
2. **RequireElevated 中间件**（`internal/middlewares/require_auth.go:109`）：
   - 每次访问受保护端点时检查 `now.After(Expires)`
   - 过期则清除 elevation 并返回 403

### 2.2 IP 绑定验证

Elevation 与创建时的远程 IP 绑定，IP 变化即失效：

**检查点 1** - 查询状态时（`handler_session_elevation.go:88`）：
```go
if !userSession.Elevations.User.RemoteIP.Equal(ctx.RemoteIP()) {
    // IP 不匹配，销毁 elevation
    response.Expires, response.Elevated, deleted = 0, false, true
}
```

**检查点 2** - 访问受保护端点时（`require_auth.go:115`）：
```go
if !ctx.RemoteIP().Equal(userSession.Elevations.User.RemoteIP) {
    invalid = true  // IP 不匹配，标记为无效
}
```

### 2.3 主动撤销（DELETE 接口）

#### 2.3.1 访问约束

**路由注册**（`internal/server/handlers.go:296`）：
```go
r.DELETE("/api/user/session/elevation/{id}", middlewareAPI(handlers.UserSessionElevateDELETE))
```

**中间件**：`middlewareAPI` - **无认证要求**！
- 仅应用安全头（SecurityHeadersBase、SecurityHeadersNoStore、SecurityHeadersCSPNone）
- **不**需要 Require1FA 或任何身份验证
- 设计意图：允许用户通过邮件中的撤销链接无需登录即可撤销 OTC

#### 2.3.2 Public ID 绑定条件

**Public ID 生成**（`handler_session_elevation.go:158, 178`）：
```go
// POST /elevation 时生成
otp, _ := model.NewOneTimeCode(ctx, username, characters, duration)
// PublicID 是随机 UUID
deleteID := base64.RawURLEncoding.EncodeToString(otp.PublicID[:])
```

**Public ID 发送**：
- 通过邮件发送给用户，包含在撤销链接中
- 链接格式：`/revoke/one-time-code?id=<base64_public_id>`
- 邮件模板：`internal/templates/src/emails/IdentityVerificationOTC.tsx`

**绑定条件（DELETE 接口内部校验，`handler_session_elevation.go:365-442`）：
1. **ID 格式校验**（第375行）：必须是有效的 base64 Raw URL 编码的 UUID
2. **存在性校验**（第393行）：通过 `LoadOneTimeCodeByPublicID` 查询 OTC 必须存在
3. **未撤销校验**（第409行）：`code.RevokedAt.Valid` 必须为 false
4. **未消费校验**（第417行）：`code.ConsumedAt.Valid` 必须为 false
5. **Intent 匹配校验**（第425行）：`code.Intent == OTCIntentUserSessionElevation`

#### 2.3.3 撤销操作

**撤销操作仅标记 OTC，不影响已生效 Elevation**（`handler_session_elevation.go:433`）：
```go
// 调用存储层标记为 revoked
ctx.Providers.StorageProvider.RevokeOneTimeCode(ctx, id, model.NewIP(ctx.RemoteIP()))
```

#### 2.3.4 撤销入口

撤销有两个入口：

1. **前端对话框取消**（`IdentityVerificationDialog.tsx:71-77`）：
   - 用户关闭验证对话框时调用 `deleteUserSessionElevation(deleteID)`

2. **邮件撤销链接**（`RevokeOneTimeCodeView.tsx`）：
   - 用户点击邮件中的"Revoke"链接
   - 页面自动调用 `deleteUserSessionElevation(id)`
   - 无需登录即可撤销

#### 2.3.5 关键证据：DELETE 只作用于未消费 OTC

**证据 1：DELETE 接口显式拒绝已消费的 OTC**（`handler_session_elevation.go:417-423`）：
```go
if code.ConsumedAt.Valid {
    ctx.Logger.WithError(fmt.Errorf("the code challenge has already been consumed")).
        Errorf("Error occurred revoking user session elevation One-Time Code challenge")
    ctx.SetJSONError(messageOperationFailed)
    return  // 已消费 OTC 无法撤销
}
```

**证据 2：DELETE 接口不操作 UserSession.Elevations**：
- DELETE 接口代码中**完全没有**调用 `ctx.GetSession()` 或 `ctx.SaveSession()`
- DELETE 接口只操作 `one_time_codes` 表，不接触会话数据
- 没有任何代码路径会通过 DELETE 清除 `userSession.Elevations.User`

**证据 3：PUT 接口消费 OTC 后设置 Elevation**（`handler_session_elevation.go:335-359`）：
```go
code.Consume(ctx)  // 标记 OTC 为已消费
// ...
userSession.Elevations.User = &session.Elevation{
    ID:       code.ID,
    RemoteIP: ctx.RemoteIP(),
    Expires:  ctx.GetClock().Now().Add(ctx.Configuration.IdentityValidation.ElevatedSession.ElevationLifespan),
}
// 保存到会话存储
if err = ctx.SaveSession(userSession); err != nil { ... }
```

**结论**：
- OTC 被消费（PUT 成功）后，Elevation 状态独立存在于会话存储中
- DELETE 接口只能撤销**未消费**的 OTC
- 已生效的 Elevation 只能通过**时间过期**、**IP 变化**或**会话销毁**失效
- DELETE 撤销无法让已生效的 Elevation 立即失效

### 2.4 一次性代码自身失效

在验证阶段（PUT /elevation 时），OTC 本身也有多层防护：
- 过期检查：`code.ExpiresAt.Before(now)`（第290行）
- 已撤销检查：`code.RevokedAt.Valid`（第299行）
- 已消费检查：`code.ConsumedAt.Valid`（第308行）
- Intent 匹配检查：`code.Intent == OTCIntentUserSessionElevation`（第317行）
- 常量时间比较：`subtle.ConstantTimeCompare(code.Code, []byte(bodyJSON.OneTimeCode))`（第326行）

---

## 三、SkipSecondFactor 与 RequireSecondFactor 分支条件

这两个配置项通过后端设置标志位，前端根据标志位决定是否进入 elevation 流程。

### 3.1 后端标志位设置（GET /elevation）

**处理器**（`internal/handlers/handler_session_elevation.go:49-73`）：

```go
switch level := userSession.AuthenticationLevel(ctx.Configuration.WebAuthn.EnablePasskey2FA); {
case level >= authentication.TwoFactor:
    // 用户已通过 2FA 认证
    if ctx.Configuration.IdentityValidation.ElevatedSession.SkipSecondFactor {
        response.SkipSecondFactor = true  // 标志1: 可跳过 2FA
    }
case level == authentication.OneFactor:
    // 用户仅通过 1FA 认证
    response.FactorKnowledge = userSession.AuthenticationMethodRefs.FactorKnowledge()
    
    info, err = ctx.Providers.StorageProvider.LoadUserInfo(ctx, userSession.Username)
    has = info.HasTOTP || info.HasWebAuthn || info.HasDuo  // 用户是否配置了 2FA 方法
    
    if ctx.Configuration.IdentityValidation.ElevatedSession.RequireSecondFactor {
        if err != nil || has {
            response.RequireSecondFactor = true  // 标志2: 必须 2FA
        }
    } else if ctx.Configuration.IdentityValidation.ElevatedSession.SkipSecondFactor && has {
        response.CanSkipSecondFactor = true  // 标志3: 可选择跳过 2FA
    }
}
```

**返回的响应结构**（`internal/handlers/types.go:74-81`）：
```go
type bodyGETUserSessionElevate struct {
    RequireSecondFactor bool `json:"require_second_factor"`
    SkipSecondFactor    bool `json:"skip_second_factor"`
    CanSkipSecondFactor bool `json:"can_skip_second_factor"`
    FactorKnowledge     bool `json:"factor_knowledge"`
    Elevated            bool `json:"elevated"`
    Expires             int  `json:"expires"`
}
```

### 3.2 前端分支逻辑（SecondFactorDialog）

**核心判断逻辑**（`web/src/views/Settings/Common/SecondFactorDialog.tsx:140-159`）：

```tsx
useLayoutEffect(() => {
    if (closing || !opening || !elevation) return;

    // 关键判断：是否跳过 2FA 对话框
    const shouldSkip =
        (elevation.skip_second_factor || !elevation.require_second_factor) && 
        !elevation.can_skip_second_factor;
    
    if (shouldSkip) {
        resetState();
        handleClosed(true, false);  // 直接关闭，进入 OTC 验证
        return;
    }

    // 否则显示 2FA 对话框
    if (!open) {
        handleOpened();
        dispatch({ payload: true, type: "setOpen" });
    }
    // ...
}, [/* ... */]);
```

### 3.3 配置组合分支矩阵

| 配置组合 | 用户认证状态 | 标志位 | 前端行为 |
|---------|-------------|--------|----------|
| **SkipSecondFactor=true** | 已 2FA | `skip_second_factor=true` | 跳过 2FA，直接进入 OTC 验证 |
| **SkipSecondFactor=true** | 仅 1FA，有 2FA 方法 | `can_skip_second_factor=true` | 显示 2FA 选择界面，提供"Email One-Time Code"选项 |
| **RequireSecondFactor=true** | 仅 1FA，有 2FA 方法 | `require_second_factor=true` | 强制 2FA，必须完成 2FA 才能继续 |
| **两者都为 false**（默认） | 仅 1FA | 无特殊标志 | 跳过 2FA，直接进入 OTC 验证 |

### 3.4 完整流程分支图

```
用户点击敏感操作 → GET /elevation
       ↓
┌─────────────────────────────────────────────────────────────┐
│ 后端检查 authentication_level                                │
├─────────────────────────────────────────────────────────────┤
│ 已 2FA?                                                      │
│   ├─ Yes + SkipSecondFactor=true → skip_second_factor=true  │
│   │       ↓ (前端 shouldSkip=true)                           │
│   │   跳过 2FA 对话框 → 进入 OTC 验证                        │
│   └─ No (仅 1FA)                                             │
│          ├─ RequireSecondFactor=true + 有 2FA 方法           │
│          │       ↓ require_second_factor=true                │
│          │   强制 2FA → 必须完成 2FA 才能继续                │
│          ├─ SkipSecondFactor=true + 有 2FA 方法              │
│          │       ↓ can_skip_second_factor=true               │
│          │   显示选择界面: [Email OTC] 或 [2FA 方法]        │
│          └─ 其他情况 (默认配置)                               │
│                  ↓ (前端 shouldSkip=true)                     │
│              跳过 2FA 对话框 → 进入 OTC 验证                 │
└─────────────────────────────────────────────────────────────┘
```

### 3.5 SecurityView 调用链

**触发流程**（`web/src/views/Settings/Security/SecurityView.tsx:150-160`）：
```tsx
const handleElevation = () => {
    handleElevationRefresh().catch(console.error);  // GET /elevation
    setDialogSFOpening(true);  // 打开 SecondFactorDialog
};

const handleChangePassword = () => {
    setDialogPWChangeOpening(true);
    handleElevation();  // 修改密码触发 elevation
};
```

**SecondFactorDialog 关闭回调**（第74-114行）：
```tsx
const handleSFDialogClosed = (ok: boolean, changed: boolean) => {
    if (!ok) { handleResetState(); return; }
    
    if (changed) {
        // 2FA 成功，重新查询 elevation 状态
        handleElevationRefresh().then((refreshedElevation) => {
            const isElevatedFromRefresh =
                refreshedElevation.elevated || refreshedElevation.skip_second_factor;
            if (isElevatedFromRefresh) {
                // 已提升或可跳过，直接执行敏感操作
                handleOpenChangePWDialog();
            } else {
                setDialogIVOpening(true);  // 进入 OTC 验证
            }
        });
    } else {
        // 跳过 2FA 的情况
        const isElevated = elevation && (elevation.elevated || elevation.skip_second_factor);
        if (isElevated) {
            handleOpenChangePWDialog();
        } else {
            setDialogIVOpening(true);  // 进入 OTC 验证
        }
    }
};
```

---

## 四、失效机制协同

### 4.1 多层失效防护矩阵

| 失效机制 | 触发时机 | 检查位置 | 失效范围 | 能否让已生效 Elevation 失效 |
|-----------|----------|----------|----------|-----------------------------|
| **时间过期** | OTC 过期 | POST→PUT | OTC 失效 | 否 |
| **时间过期** | Elevation 过期 | GET / RequireElevated | Elevation 会话失效 | **是** |
| **IP 变化** | 访问受保护端点 | RequireElevated | Elevation 会话失效 | **是** |
| **主动撤销** | 用户取消/邮件链接 | DELETE /elevation | OTC 标记为 revoked | **否**（仅影响未消费 OTC） |
| **已消费** | OTC 使用后 | PUT /elevation | OTC 标记为 consumed | 否（OTC 使命完成） |
| **会话销毁** | 用户登出 | DestroySession | 整个 UserSession 销毁 | **是** |

### 4.2 失效协同流程

```
OTC 生命周期：
生成 OTC (存储在 one_time_codes 表）
   ↓
┌────────────────────────────────────────────────────────────┐
│ 失效检查层 1: 时间过期 (5 分钟)                            │
│  - OTC 过期后 PUT 直接拒绝                                  │
├────────────────────────────────────────────────────────────┤
│ 失效检查层 2: 主动撤销 (DELETE)                            │
│  - 用户取消对话框 → DELETE /elevation/{public_id}          │
│  - 用户点击邮件撤销链接 → DELETE                            │
│  - 检查: public_id 有效、未撤销、未消费、intent 匹配       │
│  - ⚠️ 仅能撤销未消费 OTC，不影响已生效 Elevation            │
├────────────────────────────────────────────────────────────┤
│ 失效检查层 3: OTC 验证时 (PUT)                              │
│  - 过期、已撤销、已消费、intent 不匹配                      │
│  - 验证通过 → 标记 consumed → 设置 Elevation                │
└────────────────────────────────────────────────────────────┘
   ↓ 验证通过
   ↓
Elevation 会话生效（存储在服务端会话存储）
   ↓
┌────────────────────────────────────────────────────────────┐
│ 失效检查层 4: 时间过期 (10 分钟)                           │
│  - GET /elevation 查询时检查                                │
│  - RequireElevated 中间件检查                               │
├────────────────────────────────────────────────────────────┤
│ 失效检查层 5: IP 绑定验证                                   │
│  - GET /elevation 查询时检查                                │
│  - RequireElevated 中间件检查                               │
│  - IP 变化立即清除 elevation                                │
├────────────────────────────────────────────────────────────┤
│ 失效检查层 6: 会话销毁                                      │
│  - 用户登出 → DestroySession                                │
│  - Cookie 过期 → 会话自动过期                               │
└────────────────────────────────────────────────────────────┘
   ↓
Elevation 失效
```

### 4.3 关键设计考量

1. **OTC 与 Elevation 是两个独立的生命周期**：
   - OTC：用于验证阶段（5 分钟）
   - Elevation：验证通过后的权限窗口（10 分钟）
   - 两者通过 `Elevation.ID` 关联，但失效机制独立

2. **Public ID 是 OTC 唯一的公开标识符**：
   - 仅用于撤销操作
   - 不用于验证（验证使用 code 字段）
   - 通过邮件链接公开但无法通过 public_id 反推出 code

3. **DELETE 接口无认证的设计权衡**：
   - 优点：用户无需登录即可撤销被盗用的 OTC
   - 安全保障：public_id 是随机 UUID（122 位熵），难以猜测
   - 额外防护：撤销仅能撤销，无法用于其他操作
   - 限制：只能撤销未消费 OTC，无法影响已生效的 Elevation

4. **SkipSecondFactor 与 RequireSecondFactor 的语义差异**：
   - `SkipSecondFactor=true`：信任 2FA，已 2FA 用户可跳过 elevation
   - `RequireSecondFactor=true`：强制 2FA，有 2FA 方法的用户必须使用
   - 两者可同时为 true，此时 `SkipSecondFactor` 优先级更高（已 2FA 直接跳过）

---

## 五、完整链路协同

### 5.1 链路总览

```
用户点击敏感操作
       ↓
[前端] 触发 elevation 检查
       ↓
[前端] GET /api/user/session/elevation
       ↓
[后端] 检查 session.Elevations.User
       ├─ 已提升 → 允许操作
       └─ 未提升 → 返回 elevation 状态 (含 skip/require 标志)
       ↓
[前端] SecondFactorDialog 根据标志决定分支
       ├─ skip_second_factor=true → 跳过 2FA → 进入 OTC 验证
       ├─ require_second_factor=true → 强制 2FA → 完成后进入 OTC 验证
       ├─ can_skip_second_factor=true → 用户选择 OTC 或 2FA
       └─ 默认 → 跳过 2FA → 进入 OTC 验证
       ↓
[前端] IdentityVerificationDialog
       ↓
[前端] POST /api/user/session/elevation
       ↓
[后端] 生成 OTC（带 public_id）→ 存储 → 发送邮件（含撤销链接）
       ↓
[前端] 用户输入 OTC
       ↓
[前端] PUT /api/user/session/elevation {otc: "xxxx"}
       ↓
[后端] 验证 OTC（过期/撤销/消费/intent 检查）→ 消费 → 设置 session.Elevations.User
       ↓
[前端] 执行敏感操作（如修改密码）
       ↓
[后端] RequireElevated 中间件验证（过期/IP 检查）
       └─ elevation 有效 → 允许操作
```

### 5.2 前端拦截与状态管理

**核心组件**：

1. **SecurityView**（`web/src/views/Settings/Security/SecurityView.tsx`）：
   - 点击"修改密码"时触发 `handleElevation()`
   - 调用 `getUserSessionElevation()` 获取当前状态
   - 根据状态决定弹出 SecondFactorDialog 还是 IdentityVerificationDialog

2. **SecondFactorDialog**（`web/src/views/Settings/Common/SecondFactorDialog.tsx`）：
   - 检查 `elevation.skip_second_factor`：已通过 2FA 则跳过
   - 检查 `elevation.require_second_factor`：需要 2FA 则要求验证
   - 支持 TOTP、WebAuthn、Mobile Push 等多种 2FA 方式

3. **IdentityVerificationDialog**（`web/src/views/Settings/Common/IdentityVerificationDialog.tsx`）：
   - 打开时自动调用 `generateUserSessionElevation()` 生成 OTC
   - 用户输入 OTC 后调用 `verifyUserSessionElevation(otc)` 验证
   - 取消时调用 `deleteUserSessionElevation(deleteID)` 撤销

4. **RevokeOneTimeCodeView**（`web/src/views/Revoke/RevokeOneTimeCodeView.tsx`）：
   - 处理邮件中的撤销链接
   - 自动调用 `deleteUserSessionElevation(id)`
   - 无需登录即可撤销

### 5.3 后端接口与中间件

**API 端点**（`internal/server/handlers.go:292-296`）：

| 方法 | 路径 | 中间件 | 处理器 |
|------|------|--------|--------|
| GET | `/api/user/session/elevation` | Require1FA | UserSessionElevationGET |
| POST | `/api/user/session/elevation` | RateLimit + Require1FA | UserSessionElevationPOST |
| PUT | `/api/user/session/elevation` | RateLimit + Require1FA + ArbitraryDelay | UserSessionElevationPUT |
| DELETE | `/api/user/session/elevation/{id}` | 仅安全头（无认证） | UserSessionElevateDELETE |

**Elevation 保护的端点**（使用 `middlewareElevated1FA`）：
- `POST /api/change-password` - 修改密码
- `GET/PUT/POST/DELETE /api/secondfactor/totp/register` - TOTP 管理
- `PUT/POST/DELETE /api/secondfactor/webauthn/credential/*` - WebAuthn 凭证管理

**RequireElevated 中间件**（`internal/middlewares/require_auth.go:24-136`）：

执行流程：
1. 检查用户是否已通过 1FA 认证
2. 检查配置：`SkipSecondFactor` 且用户已 2FA → 直接放行
3. 检查配置：`RequireSecondFactor` 且用户有 2FA 方法 → 要求 2FA
4. 检查 `session.Elevations.User` 是否存在
5. 验证 elevation 未过期且 IP 匹配
6. 验证失败则清除 elevation 并返回 403

### 5.4 状态流转

```
未提升 (nil)
   ↓ POST /elevation
生成 OTC (存储在 one_time_codes，生成 public_id)
   ├─ 用户取消 / 邮件链接 → DELETE /elevation/{public_id} → OTC 标记 revoked
   ├─ OTC 过期 → PUT /elevation 被拒绝
   └─ 用户输入 OTC → PUT /elevation
         ↓
验证成功 → 消费 OTC → 设置 session.Elevations.User
         ↓
已提升 (有 Elevation 对象)
   ├─ GET /elevation 检查 → 返回状态
   ├─ RequireElevated 检查 → 允许访问
   ├─ 时间过期 → 清除 → 未提升
   ├─ IP 变化 → 清除 → 未提升
   └─ 用户登出 → 会话销毁 → 未提升
```

---

## 六、配置参数与默认值

**配置结构**（`internal/configuration/schema/identity_validation.go`）：

```yaml
identity_validation:
  elevated_session:
    code_lifespan: 5m         # OTC 有效期
    elevation_lifespan: 10m   # 提升后有效期
    characters: 8             # OTC 字符数
    require_second_factor: false  # 是否强制要求 2FA
    skip_second_factor: false     # 有 2FA 是否跳过 OTC
```

**速率限制**（`internal/configuration/defaults.go`）：
- `session_elevation_start`：生成 OTC 速率限制（默认启用）
- `session_elevation_finish`：验证 OTC 速率限制（默认启用）

---

## 七、安全设计要点

1. **双重验证**：敏感操作需要额外的 OTC 验证，即使会话已认证
2. **时间窗口**：短期权限窗口（默认 10 分钟）减少暴露风险
3. **IP 绑定**：防止会话劫持后滥用 elevation
4. **速率限制**：防止暴力破解 OTC
5. **延迟防护**：PUT 接口有 `ArbitraryDelay(time.Second)` 防止时序攻击
6. **常量时间比较**：使用 `subtle.ConstantTimeCompare` 验证 OTC
7. **一次性使用**：OTC 验证后立即标记为 consumed，防止重放
8. **分离存储**：Elevation 状态存储在服务端，Cookie 仅存 Session ID
9. **加密存储**：Redis 模式下会话数据 AES-GCM 256 位加密
10. **无认证撤销**：Public ID 机制允许用户无需登录即可撤销 OTC
11. **UUID 熵值**：Public ID 是随机 UUID，122 位熵值难以猜测
12. **生命周期隔离**：OTC 与 Elevation 生命周期独立，撤销 OTC 不影响已生效 Elevation

---

## 八、关键代码位置汇总

| 模块 | 文件 | 关键行 |
|------|------|--------|
| 数据结构 | `internal/session/types.go` | 73-83 (Elevations, Elevation) |
| Session ID 生成 | `internal/session/provider_config.go` | 25-35 |
| 加密序列化 | `internal/session/encrypting_serializer.go` | 18-65 (EncryptingSerializer) |
| 会话存取 | `internal/session/session.go` | 29-78 (GetSession/SaveSession) |
| OTC 模型 | `internal/model/one_time_code.go` | 13-68 (OneTimeCode) |
| 配置定义 | `internal/configuration/schema/identity_validation.go` | 20-40 |
| GET 处理器 | `internal/handlers/handler_session_elevation.go` | 23-118 |
| POST 处理器 | `internal/handlers/handler_session_elevation.go` | 120-223 |
| PUT 处理器 | `internal/handlers/handler_session_elevation.go` | 225-362 |
| DELETE 处理器 | `internal/handlers/handler_session_elevation.go` | 364-442 |
| RequireElevated 中间件 | `internal/middlewares/require_auth.go` | 24-136 |
| 路由注册 | `internal/server/handlers.go` | 281-296 |
| 前端服务 | `web/src/services/UserSessionElevation.ts` | 1-74 |
| SecurityView | `web/src/views/Settings/Security/SecurityView.tsx` | 43-274 |
| SecondFactorDialog | `web/src/views/Settings/Common/SecondFactorDialog.tsx` | 85-274 |
| IdentityVerificationDialog | `web/src/views/Settings/Common/IdentityVerificationDialog.tsx` | 32-230 |
| RevokeOneTimeCodeView | `web/src/views/Revoke/RevokeOneTimeCodeView.tsx` | 12-54 |
