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

**存储说明**：
- Elevation 状态以 `*Elevation` 指针形式存储，`nil` 表示未提升
- 状态持久化在用户的浏览器 Cookie 中（由 fasthttp/session 管理）
- 每次请求通过 `ctx.GetSession()` 从 Cookie 中恢复

### 1.2 一次性代码（One-Time Code）存储

在验证过程中，挑战代码存储在持久化存储后端：

**位置**：`internal/model/one_time_code.go`
- 表名：`one_time_codes`
- 关联 Intent：`OTCIntentUserSessionElevation`
- 字段包括：`code`（加密存储）、`expires_at`、`revoked_at`、`consumed_at`

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

### 2.3 主动撤销

用户或系统可主动撤销 elevation：

1. **用户取消验证**（前端）：
   - 关闭 IdentityVerificationDialog 时调用 `deleteUserSessionElevation(deleteID)`
   - 发送 DELETE 请求到 `/api/user/session/elevation/{id}`

2. **后端撤销接口**（`handler_session_elevation.go:365-441`）：
   - `UserSessionElevateDELETE` 处理撤销请求
   - 标记 one_time_code 为 revoked

### 2.4 一次性代码失效

在验证阶段，OTC 本身也有多层防护：
- 过期检查：`code.ExpiresAt.Before(now)`（第290行）
- 已撤销检查：`code.RevokedAt.Valid`（第299行）
- 已消费检查：`code.ConsumedAt.Valid`（第308行）
- Intent 匹配检查：`code.Intent == OTCIntentUserSessionElevation`（第317行）

---

## 三、完整链路协同

### 3.1 链路总览

```
用户点击敏感操作
       ↓
[前端] 触发 elevation 检查
       ↓
[前端] GET /api/user/session/elevation
       ↓
[后端] 检查 session.Elevations.User
       ├─ 已提升 → 允许操作
       └─ 未提升 → 返回 elevation 状态
       ↓
[前端] 弹出 SecondFactorDialog
       ├─ 可跳过 2FA → 直接进入 OTC 验证
       └─ 需要 2FA → 先完成 2FA 验证
       ↓
[前端] 弹出 IdentityVerificationDialog
       ↓
[前端] POST /api/user/session/elevation
       ↓
[后端] 生成 OTC → 存储 → 发送邮件
       ↓
[前端] 用户输入 OTC
       ↓
[前端] PUT /api/user/session/elevation {otc: "xxxx"}
       ↓
[后端] 验证 OTC → 消费 → 设置 session.Elevations.User
       ↓
[前端] 执行敏感操作（如修改密码）
       ↓
[后端] RequireElevated 中间件验证
       └─ elevation 有效 → 允许操作
```

### 3.2 前端拦截与状态管理

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

### 3.3 后端接口与中间件

**API 端点**（`internal/server/handlers.go:292-296`）：

| 方法 | 路径 | 中间件 | 处理器 |
|------|------|--------|--------|
| GET | `/api/user/session/elevation` | Require1FA | UserSessionElevationGET |
| POST | `/api/user/session/elevation` | RateLimit + Require1FA | UserSessionElevationPOST |
| PUT | `/api/user/session/elevation` | RateLimit + Require1FA + ArbitraryDelay | UserSessionElevationPUT |
| DELETE | `/api/user/session/elevation/{id}` | - | UserSessionElevateDELETE |

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

### 3.4 状态流转

```
未提升 (nil)
   ↓ POST /elevation
生成 OTC (存储在 one_time_codes)
   ↓ 用户输入 OTC → PUT /elevation
验证成功 → 设置 session.Elevations.User
   ↓
已提升 (有 Elevation 对象)
   ├─ GET /elevation 检查 → 返回状态
   ├─ RequireElevated 检查 → 允许访问
   ├─ 时间过期 → 清除 → 未提升
   ├─ IP 变化 → 清除 → 未提升
   └─ 用户登出 → 会话销毁 → 未提升
```

---

## 四、配置参数与默认值

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

## 五、安全设计要点

1. **双重验证**：敏感操作需要额外的 OTC 验证，即使会话已认证
2. **时间窗口**：短期权限窗口（默认 10 分钟）减少暴露风险
3. **IP 绑定**：防止会话劫持后滥用 elevation
4. **速率限制**：防止暴力破解 OTC
5. **延迟防护**：PUT 接口有 `ArbitraryDelay(time.Second)` 防止时序攻击
6. **常量时间比较**：使用 `subtle.ConstantTimeCompare` 验证 OTC
7. **一次性使用**：OTC 验证后立即标记为 consumed，防止重放

---

## 六、关键代码位置汇总

| 模块 | 文件 | 关键行 |
|------|------|--------|
| 数据结构 | `internal/session/types.go` | 73-83 (Elevations, Elevation) |
| 配置定义 | `internal/configuration/schema/identity_validation.go` | 20-40 |
| GET 处理器 | `internal/handlers/handler_session_elevation.go` | 23-118 |
| POST 处理器 | `internal/handlers/handler_session_elevation.go` | 120-223 |
| PUT 处理器 | `internal/handlers/handler_session_elevation.go` | 225-362 |
| DELETE 处理器 | `internal/handlers/handler_session_elevation.go` | 364-442 |
| RequireElevated 中间件 | `internal/middlewares/require_auth.go` | 24-136 |
| 路由注册 | `internal/server/handlers.go` | 281-296 |
| 前端服务 | `web/src/services/UserSessionElevation.ts` | 1-74 |
| SecurityView | `web/src/views/Settings/Security/SecurityView.tsx` | 43-274 |
| IdentityVerificationDialog | `web/src/views/Settings/Common/IdentityVerificationDialog.tsx` | 32-230 |
| SecondFactorDialog | `web/src/views/Settings/Common/SecondFactorDialog.tsx` | 85-274 |
