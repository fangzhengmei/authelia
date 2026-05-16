# Authelia TOTP 注册与验证机制分析报告（修订版 R4）

---

## 1. TOTP 登录验证：三条失败路径最终结论

### 1.1 核心判定前提说明

**时间步基本概念**：
- TOTP 码基于时间步（默认 30 秒）生成
- 每个时间步窗口内生成的 TOTP 码相同
- 时间步切换后生成新的 TOTP 码

**Authelia 验证逻辑**（skew 机制）：
- 默认配置下，Authelia 允许 ±1 个时间步的偏差（skew = 1）
- 即：同时验证"上一个时间步"、"当前时间步"、"下一个时间步"的三个可能码
- 只要三个中的任意一个匹配即算验证通过

---

### 1.2 三条失败路径并列对比

| 对比项 | 路径 1：口令无效失败 | 路径 2：重放拒绝失败 | 路径 3：重放但策略放行 |
|-------|---------------------|---------------------|----------------------|
| **触发场景** | TOTP 码验证不通过<br>（与三个可能的码都不匹配） | TOTP 码验证通过<br>**但**该时间步已使用过<br>**且**防重放策略启用 | TOTP 码验证通过<br>**但**该时间步已使用过<br>**且**防重放策略禁用 |
| **代码位置** | handler_sign_totp.go:133-142 | handler_sign_totp.go:153-163 | handler_sign_totp.go:153-155 |
| | | | |
| **doMark 调用** | ✅ 是 | ❌ 否 | ✅ 是（但记录为成功） |
| **调用参数** | `doMark(ctx, false, BanTypeNone, AuthTypeTOTP, nil)` | - | `doMark(ctx, true, BanTypeNone, AuthTypeTOTP, nil)` |
| | | | |
| **监管记录写入** | ✅ 写入（失败记录） | ❌ 不写入 | ✅ 写入（成功记录） |
| **监管表** | authentication_log | - | authentication_log |
| **认证类型** | AuthTypeTOTP（失败） | - | AuthTypeTOTP（成功） |
| | | | |
| **返回码** | 403 Forbidden | 403 Forbidden | 302/200（成功） |
| **返回消息** | "MFA Validation Failed" | "MFA Validation Failed" | 重定向到目标 URL |
| | | | |
| **日志级别** | Error | Error | Warn（仅记录重放事件） |
| | | | |
| **封禁触发** | ❌ 不触发（BanTypeNone） | ❌ 不触发 | ❌ 不触发 |
| | | | |
| **用户可执行恢复动作** | 1. **立即重试**：重新输入正确的 TOTP 码<br>2. **等待下一时间步**：若因时间偏差导致失败，等 30 秒用新码重试 | 1. **必须等待时间步切换**：默认 30 秒后使用新的 TOTP 码<br>2. **不可重发相同码**：防重放策略会持续拒绝 | ✅ **无需等待**，已放行通过<br>⚠️ 但存在安全风险，攻击者截获的码在有效期内可重放 |
| | | | |
| **速率限制计数** | ✅ 增加（调用了 doMark） | ❌ 不增加（未调用 doMark） | ❌ 不增加（记录为成功） |

---

### 1.3 "口令无效失败"可恢复条件统一口径

**判定前提**：
1. TOTP 验证失败的原因是"输入的码与三个可能的时间步码都不匹配"
2. 失败原因可能是：输入错误、时间偏差过大、使用了过期码

**统一后的可恢复条件**：

| 场景 | 恢复动作 | 等待时间步切换 |
|------|---------|--------------|
| ✅ **纯输入错误**（输错数字） | 立即重新输入正确的码 | **不需要**等待 |
| ⚠️ **时间偏差**（客户端时间不准） | 等客户端时间同步后重试 | **可能需要**等待 |
| ⚠️ **使用了过期码**（上上个时间步或更旧） | 等待下一时间步生成新码后重试 | **需要**等待（约 0-30 秒） |

**结论总结**：
- ❌ **不是必须**等待下一时间步
- ✅ **可以立即重试**（如果知道正确的码）
- ⚠️ 但如果失败原因是时间偏差或码过期，则需要等待时间步切换才能成功

---

## 2. 核心入口与鉴权前置条件

### 2.1 注册入口（/api/secondfactor/totp/register）

| 方法 | 路径 | 鉴权中间件 | 前置条件 |
|------|------|-----------|---------|
| GET | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话**（近期重新验证过密码） |
| PUT | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话** |
| POST | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话** |
| DELETE | `/api/secondfactor/totp/register` | middlewareElevated1FA | 需要**提升的 1FA 会话** |

**会话提升说明**：
- 用户需要在近期（可配置）重新验证密码
- 目的是防止会话劫持后被用于注册新的 2FA 设备

### 2.2 登录验证入口（/api/secondfactor/totp）

| 方法 | 路径 | 鉴权中间件 | 前置条件 |
|------|------|-----------|---------|
| GET | `/api/secondfactor/totp` | middleware1FA | 需要普通 1FA 会话（已通过密码验证） |
| POST | `/api/secondfactor/totp` | middlewareRateLimitTOTP | 1FA + TOTP 速率限制 |
| DELETE | `/api/secondfactor/totp` | middleware1FA | 需要普通 1FA 会话 |

---

## 3. 登录验证：失败分流详细分析

### 3.1 doMarkAuthenticationAttempt 调用逻辑说明

**函数签名**：
```go
doMarkAuthenticationAttempt(ctx, successful bool, ban *regulation.Ban, authType string, err error)
```

**内部调用 Regulator.HandleAttempt**，参数含义：
- `successful`: 认证是否成功
- `ban`: 封禁类型（BanTypeNone/BanTypeIP/BanTypeUser）
- `authType`: 认证类型（AuthType1FA/AuthTypeTOTP/AuthTypeWebAuthn）

---

### 3.2 失败路径 1：口令无效失败（TOTP 码验证不通过）

**代码位置**：`handler_sign_totp.go:133-142`

```go
if !valid {
    ctx.GetLogger().WithError(fmt.Errorf("the user input wasn't valid")).Errorf("...")
    
    doMarkAuthenticationAttempt(ctx, false, 
        regulation.NewBan(regulation.BanTypeNone, userSession.Username, nil), 
        regulation.AuthTypeTOTP, nil)
    
    ctx.SetStatusCode(fasthttp.StatusForbidden)
    ctx.SetJSONError(messageMFAValidationFailed)
    return
}
```

**详细分析**：

| 项 | 值 | 说明 |
|----|----|------|
| **触发条件** | TOTP 码与三个可能的时间步码都不匹配 | - |
| **调用 doMark** | ✅ 是 | 第 136 行明确调用 |
| **监管记录类型** | AuthTypeTOTP（失败） | 标记为 TOTP 认证失败 |
| **BanType** | BanTypeNone | 不触发封禁检查 |
| **写入监管表** | ✅ 是 | 写入 authentication_log 表 |
| **日志级别** | Error | 记录错误级别日志 |
| **返回码** | 403 Forbidden | HTTP 状态码 |
| **返回消息** | messageMFAValidationFailed | "MFA Validation Failed" |

**可恢复条件（统一口径）**：
- ✅ **可以立即重试**，不是必须等待时间步切换
- ✅ 不触发封禁（BanTypeNone + AuthTypeTOTP）
- ⚠️ 受速率限制中间件保护（middlewareRateLimitTOTP）
- ⚠️ 连续失败不会导致账号/IP 封禁
- 🔹 **场景 A - 纯输入错误**：立即重新输入正确的码即可，无需等待
- 🔹 **场景 B - 时间偏差/码过期**：需要等待下一时间步（约 0-30 秒）后用新码重试

---

### 3.3 失败路径 2：重放拒绝失败（防重放策略启用）

**触发条件**：
- `DisableReuseSecurityPolicy = false`（**默认值**）
- 当前时间步在 totp_history 表中已存在
- ✅ TOTP 码本身验证是通过的

**代码位置**：`handler_sign_totp.go:153-163`

```go
if exists {
    if ctx.Configuration.TOTP.DisableReuseSecurityPolicy {
        // 策略禁用：记录警告并放行
        ctx.GetLogger().WithFields(map[string]any{"username": userSession.Username}).Warn("...")
    } else {
        // 策略启用：拒绝请求
        ctx.GetLogger().WithError(fmt.Errorf("the user has already used this code recently...")).Errorf("...")
        
        ctx.SetStatusCode(fasthttp.StatusForbidden)
        ctx.SetJSONError(messageMFAValidationFailed)
        
        return
    }
}
```

**详细分析**：

| 项 | 值 | 说明 |
|----|----|------|
| **触发条件** | 码验证通过 + 时间步已使用 + 防重放启用 | 注意：码本身是有效的！ |
| **调用 doMark** | ❌ 否 | **不调用** doMarkAuthenticationAttempt |
| **监管记录类型** | - | 不写入监管表 |
| **BanType** | - | 不涉及 |
| **写入监管表** | ❌ 否 | 只写普通错误日志 |
| **日志级别** | Error | 记录错误级别日志 |
| **返回码** | 403 Forbidden | HTTP 状态码 |
| **返回消息** | messageMFAValidationFailed | "MFA Validation Failed" |

**可恢复条件（DisableReuseSecurityPolicy = false）**：
- ❌ **必须等待时间步切换**（默认 30 秒后）
- ❌ **无法通过重发相同 TOTP 码通过**（防重放策略）
- ✅ 不触发封禁
- ✅ 速率限制计数器**不增加**（因为不调用 doMark）
- ⚠️ 需要用户等待令牌刷新后使用新的 TOTP 码

---

### 3.4 路径 3：重放但策略放行（防重放策略禁用）

**触发条件**：
- `DisableReuseSecurityPolicy = true`（需手动配置）
- 当前时间步在 totp_history 表中已存在
- ✅ TOTP 码本身验证是通过的

**代码位置**：`handler_sign_totp.go:153-155`

```go
if exists {
    if ctx.Configuration.TOTP.DisableReuseSecurityPolicy {
        // 策略禁用：仅记录警告，继续执行
        ctx.GetLogger().WithFields(map[string]any{"username": userSession.Username}).Warn("User has reused a Time-based One Time Password with the given step but the policy to disable reuse is disabled")
    } else {
        // ... 拒绝逻辑
    }
}
```

**后续执行路径**：
```
警告日志已记录
    ↓
继续执行后续逻辑（第 173 行）
    ↓
调用 doMarkAuthenticationAttempt(ctx, true, BanTypeNone, AuthTypeTOTP, nil)
    ↓
写入成功认证日志到监管表
    ↓
会话再生、更新 LastUsedAt、设置 2FA 状态
    ↓
最终放行通过
```

**详细分析**：

| 项 | 值 | 说明 |
|----|----|------|
| **触发条件** | 码验证通过 + 时间步已使用 + 防重放禁用 | 码本身是有效的 |
| **调用 doMark** | ✅ 是（但记录为成功） | 第 173 行调用，successful=true |
| **监管记录类型** | AuthTypeTOTP（成功） | 标记为 TOTP 认证成功 |
| **BanType** | BanTypeNone | - |
| **写入监管表** | ✅ 是 | 写入成功认证记录 |
| **日志级别** | Warn | 仅记录警告，提示重放事件 |
| **返回码** | 302/200 | 放行，重定向到目标 URL |
| **返回消息** | - | 成功，无错误消息 |

**可恢复条件（DisableReuseSecurityPolicy = true）**：
- ✅ **无需等待**，即使 TOTP 码已使用过仍可通过
- ✅ 不触发封禁
- ✅ 不影响用户体验
- ⚠️ 但存在安全风险：攻击者截获的 TOTP 码在有效期内可重放
- ⚠️ 仅记录警告日志供安全审计

---

## 4. DisableReuseSecurityPolicy 配置对比

| 维度 | DisableReuseSecurityPolicy = false（默认） | DisableReuseSecurityPolicy = true |
|-----|-------------------------------------------|----------------------------------|
| **安全级别** | 高，防止重放攻击 | 较低，允许令牌重用 |
| **重放检测** | ✅ 启用，检查并拒绝 | ❌ 仅记录警告，不拒绝 |
| **可恢复条件** | 必须等待下一个时间步（30秒）才能用新码通过 | 无需等待，立即重试即可通过 |
| **用户体验** | 较差，偶尔可能因网络延迟导致时间偏差失败 | 较好，容忍时间偏差和重试 |
| **失败后重试** | 必须用新的 TOTP 码才能通过 | 可使用相同 TOTP 码重试并通过 |
| **doMark 调用** | 重放拒绝时不调用 | 重放放行时调用（记录成功） |
| **监管记录** | 重放失败不写入监管表 | 重放放行写入成功记录 |
| **速率限制计数** | 不增加（不调用 doMark） | 不增加（记录为成功） |

---

## 5. 监管封禁机制的真实边界

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

---

## 6. 登录验证完整流程图（含失败分流）

```
                    用户提交 TOTP 码
                          │
                          ▼
          ┌───────────────────────────────┐
          │   格式校验（6/8位数字）       │
          └───────────────┬───────────────┘
                          │
                  ┌───────┴───────┐
                  │ 格式错误       │
                  ▼                ▼
              返回 403           通过
                                  │
                                  ▼
                      从 DB 加载 TOTP 配置
                                  │
                                  ▼
          ┌─────────────────────────────────────────────┐
          │  使用密钥验证 TOTP 码（skew 机制）           │
          │  同时验证：上一步、当前步、下一步 三个码       │
          └─────────────────────┬───────────────────────┘
                                │
                  ┌─────────────┴─────────────┐
                  │ 三个码都不匹配             │ 任意一个匹配
                  ▼                           ▼
      ┌─────────────────────────────┐     检查时间步是否已使用
      │ 路径 1：口令无效失败        │             │
      │ 调用 doMark(false, TOTP)    │     ┌───────┴───────┐
      │ 写入监管日志（不禁封禁）      │     │ 已使用         │ 未使用
      │ 返回 403 Forbidden          │     ▼                ▼
      │ 可立即重试（或等时间步）      │ ┌───────────┐    记录时间步到历史表
      └─────────────────────────────┘ │ 检查策略   │          │
                                      └─────┬─────┘          │
                            ┌───────────────┴───────────────┐
                            │ DisableReuseSecurityPolicy     │
                            │     = false?                   │
                            └─────┬─────────────────────┬───┘
                                  │ Yes                 │ No
                                  ▼                     ▼
                          ┌─────────────┐        ┌───────────────┐
                          │ 路径 2：     │        │ 路径 3：       │
                          │ 重放拒绝     │        │ 重放放行       │
                          │ 记录 Error  │        │ 记录 Warning  │
                          │ 返回 403    │        │ 继续执行       │
                          │ 不调用 doMark│        │               │
                          │ 必须等 30s  │        └───────┬───────┘
                          └─────────────┘                │
                                                          │
                                                          ▼
                                                调用 doMark(true, TOTP)
                                                          │
                                                          ▼
                                                会话再生（防固定攻击）
                                                          │
                                                          ▼
                                                更新 LastUsedAt
                                                          │
                                                          ▼
                                                设置 2FA 认证状态
                                                          │
                                                          ▼
                                                重定向到目标 URL
```

---

## 7. 关键代码位置参考

| 模块 | 文件路径 | 关键行 |
|------|---------|--------|
| 口令无效失败处理 | `internal/handlers/handler_sign_totp.go` | 133-142 |
| 重放检测与处理 | `internal/handlers/handler_sign_totp.go` | 144-171 |
| doMark 成功调用 | `internal/handlers/handler_sign_totp.go` | 173 |
| 监管封禁逻辑 | `internal/regulation/regulator.go` | 45-55 |
| 会话类型定义 | `internal/session/types.go` | 51-58 |
| TOTP 配置模型 | `internal/model/totp_configuration.go` | 29-202 |
| 路由与中间件 | `internal/server/handlers.go` | 305-312 |

---

## 修订记录

**修订版本 R4**（本次更新）：
1. 统一"口令无效失败"可恢复条件口径，明确判定前提：不是必须等待时间步，可立即重试
2. 新增 1.2 节：三条失败路径四项核心指标并列对比表
3. 新增 1.3 节："口令无效失败"可恢复条件分场景详细说明
4. 更新第 3 章各路径分析，统一恢复条件描述口径
5. 流程图中标注 skew 机制（验证三个时间步码）
6. 补充速率限制计数在三条路径中的差异

**修订版本 R3**：
1. 新增第 5 章：登录验证失败分流详细分析
2. 梳理三条失败路径：口令无效、重放拒绝、重放放行
3. 逐项说明每条路径的 doMark 调用情况、监管记录、返回码、恢复条件
4. 补充 DisableReuseSecurityPolicy=true/false 配置对比矩阵
5. 新增第 7 章：登录验证完整流程图（含失败分流可视化）

**修订版本 R2**：
1. 修正各入口的准确路径与真实鉴权前置条件
2. 关键修正：明确 TOTP 失败**不触发封禁**，封禁仅针对 AuthType1FA
3. 厘清失败记录、封禁触发条件与可恢复路径的真实边界
4. 补充注册与登录验证在会话状态流转上的详细差异
5. 更正防重放、会话再生等机制的适用场景
