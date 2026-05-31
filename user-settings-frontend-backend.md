# Authelia 用户设置页前端-后端交互脑图

## 一、整体架构概览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         前端 (React + TypeScript)                        │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐   │
│  │  SecurityView   │     │  TwoFactorAuth  │     │  SettingsRouter │   │
│  │  (修改密码)     │     │  (多因子管理)   │     │                 │   │
│  └────────┬────────┘     └────────┬────────┘     └─────────────────┘   │
│           │                       │                                      │
│           └───────────┬───────────┘                                      │
│                       │                                                  │
│              ┌────────▼─────────┐                                        │
│              │  会话提升层       │                                        │
│              │  - SecondFactor   │                                        │
│              │  - IdentityVerify │                                        │
│              └────────┬─────────┘                                        │
│                       │                                                  │
│              ┌────────▼─────────┐     ┌─────────────────┐                │
│              │  Hooks (状态)    │────►│  Services (API)  │                │
│              │  - useRemoteCall │     │  - Api.ts        │                │
│              │  - useUserInfo   │     │  - *Service.ts   │                │
│              └─────────────────┘     └────────┬────────┘                │
│                                               │                           │
└───────────────────────────────────────────────┼───────────────────────────┘
                                                │
┌───────────────────────────────────────────────▼───────────────────────────┐
│                         后端 (Go + fasthttp)                              │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐   │
│  │  Middleware     │────►│  Handlers       │────►│  Providers      │   │
│  │  - Require1FA   │     │  - 密码/2FA     │     │  - Storage      │   │
│  │  - RequireElev  │     │  - 会话提升     │     │  - UserProvider │   │
│  └─────────────────┘     └─────────────────┘     └────────┬────────┘   │
│                                                           │              │
│                                                  ┌────────▼────────┐     │
│                                                  │  Session存储    │     │
│                                                  │  - Cookie       │     │
│                                                  │  - Redis/DB     │     │
│                                                  └─────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 二、前端状态机详解

### 2.1 核心状态管理 Hook: useRemoteCall

**文件**: `web/src/hooks/RemoteCall.ts:5-28`

```typescript
// 返回四元组: [data, triggerCallback, inProgress, error]
function useRemoteCall<Ret>(fn: PromisifiedFunction<Ret>): [
  Ret | undefined,    // 数据
  () => void,         // 触发函数
  boolean,            // 加载中
  Error | undefined   // 错误
]
```

**状态流转**:
```
  初始状态: [undefined, trigger, false, undefined]
      │
      ▼ triggerCallback()
  [undefined, trigger, true, undefined]  ◄── inProgress = true
      │
      ├─ 成功 ► [data, trigger, false, undefined]  (setData)
      │
      └─ 失败 ► [undefined, trigger, false, Error]  (setError)
```

### 2.2 SecurityView 状态机 (修改密码入口)

**文件**: `web/src/views/Settings/Security/SecurityView.tsx:43-160`

**核心状态变量**:
- `elevation`: UserSessionElevation | undefined (会话提升状态)
- `dialogSFOpening`: boolean (第二因子对话框打开中)
- `dialogIVOpening`: boolean (身份验证对话框打开中)
- `dialogPWChangeOpen`: boolean (密码修改对话框打开)
- `dialogPWChangeOpening`: boolean (密码修改对话框打开中)

**状态流转图**:
```
┌──────────────────────────────────────────────────────────────────────┐
│                        初始状态                                        │
│  elevation=undefined, 所有dialog=false                                 │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼ 点击 "Change Password"
┌──────────────────────────────────────────────────────────────────────┐
│  handleChangePassword()                                               │
│  → setDialogPWChangeOpening(true)                                     │
│  → handleElevation()                                                  │
│    → getUserSessionElevation()  [API: GET /api/user/session/elevation]│
│    → setDialogSFOpening(true)                                         │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────────┐
│  SecondFactorDialog 打开 (activeStep=0)                               │
│  显示验证方法选择: TOTP / WebAuthn / Mobile Push / 邮箱OTC            │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
  ┌─────────────────────────┼─────────────────────────┐
  │ 选择第二因子            │ 选择邮箱OTC             │
  ▼                         ▼                         ▼
┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐
│ activeStep=1│    │ handleOneTimeCode│    │ IdentityVerification│
│ 验证组件     │    │ → 跳过2FA直接IV  │    │ Dialog (输入OTC)   │
└──────┬──────┘    └─────────┬────────┘    └─────────┬─────────┘
       │                     │                         │
       └─────────────────────┼─────────────────────────┘
                             ▼ 验证成功
┌──────────────────────────────────────────────────────────────────────┐
│  handleSFDialogClosed(ok=true, changed=true)                         │
│  → 刷新elevation状态                                                  │
│  → 检查: elevated OR skip_second_factor                               │
│    → YES: setDialogPWChangeOpen(true)  ✅ 进入密码修改                │
│    → NO:  setDialogIVOpening(true)     ⚠️  需要额外身份验证           │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.3 SecondFactorDialog 内部状态机 (useReducer)

**文件**: `web/src/views/Settings/Common/SecondFactorDialog.tsx:42-83`

```typescript
type State = {
  open: boolean;        // 对话框是否打开
  loading: boolean;     // 加载中
  closing: boolean;     // 关闭中
  activeStep: number;   // 当前步骤: 0=选择方法, 1=验证, 2=完成
  method: SecondFactorMethod | undefined;  // 选择的方法
};
```

**状态流转**:
```
  activeStep = 0: 选择方法
      │ 点击方法按钮 (TOTP/WebAuthn/Duo)
      ▼
  activeStep = 1: 执行验证
      │ 验证成功 onSecondFactorSuccess
      ▼
  activeStep = 2: 显示成功图标
      │ 1500ms 后自动关闭
      ▼
  handleClose(true, true) → 回调父组件
```

---

## 三、会话提升 (Session Elevation) 机制

### 3.1 核心概念

**会话提升**是 Authelia 的安全机制：即使用户已登录（1FA），执行敏感操作前仍需**临时提升权限**。

### 3.2 前端会话提升服务

**文件**: `web/src/services/UserSessionElevation.ts:13-74`

```typescript
interface UserSessionElevation {
  require_second_factor: boolean;    // 是否需要第二因子
  skip_second_factor: boolean;       // 是否可跳过第二因子
  can_skip_second_factor: boolean;   // 是否可选择跳过（用邮箱OTC）
  factor_knowledge: boolean;         // 是否已验证密码知识因子
  elevated: boolean;                 // 是否已提升
  expires: number;                   // 剩余有效时间（秒）
}
```

### 3.3 后端会话提升中间件

**文件**: `internal/middlewares/require_auth.go:24-136`

**RequireElevated 中间件检查流程**:
```
           ┌──────────────────────────────┐
           │  请求到达敏感接口              │
           │  (如 /api/change-password)    │
           └──────────────┬───────────────┘
                          │
                          ▼
           ┌──────────────────────────────┐
           │  检查是否已1FA认证?            │
           │  AuthenticationLevel >= 1?    │
           └───────┬──────────────────────┘
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
      是 ✅                否 ❌
         │             返回 403 Forbidden
         ▼
   ┌─────────────────────────────────────────────────┐
   │  配置 SkipSecondFactor 且用户已2FA认证?          │
   │  level >= TwoFactor && SkipSecondFactor = true?  │
   └───────┬─────────────────────────────────────────┘
           │
      ┌────┴────┐
      ▼         ▼
    是 ✅     否 ➡️ 继续检查
      │
  直接放行 ✅
      │
      ▼
   ┌─────────────────────────────────────────────┐
   │  配置 RequireSecondFactor 且用户有2FA设备?    │
   │  (HasTOTP || HasWebAuthn || HasDuo)          │
   └───────┬─────────────────────────────────────┘
           │
      ┌────┴────┐
      ▼         ▼
    是 ❌     否 ➡️ 继续检查
      │
  返回 403 (需要2FA)
      │
      ▼
   ┌─────────────────────────────────────────────┐
   │  检查 userSession.Elevations.User != nil?   │
   │  (是否有有效的提升会话)                       │
   └───────┬─────────────────────────────────────┘
           │
      ┌────┴────┐
      ▼         ▼
    是 ➡️ 验证   否 ❌
  有效性       返回 403 (需要提升)
      │
      ▼
   ┌─────────────────────────────────────────────┐
   │  验证提升会话有效性:                          │
   │  • 是否已过期?  (Now() > Expires)             │
   │  • IP是否匹配? (RemoteIP == Elevation.IP)     │
   └───────┬─────────────────────────────────────┘
           │
      ┌────┴────┐
      ▼         ▼
    有效 ✅    无效 ❌
      │       清除提升会话
  放行请求    返回 403
```

### 3.4 会话提升后端 Handler

**文件**: `internal/handlers/handler_session_elevation.go`

| 方法   | 路径 | 作用 |
|--------|------|------|
| **GET**    | `/api/user/session/elevation` | 获取当前提升状态 |
| **POST**   | `/api/user/session/elevation` | 生成OTC（发送邮件） |
| **PUT**    | `/api/user/session/elevation` | 验证OTC，执行提升 |
| **DELETE** | `/api/user/session/elevation/{id}` | 撤销OTC |

**提升会话存储结构**:
```go
// internal/session/user_session.go
type Elevation struct {
  ID       int         // OTC记录ID
  RemoteIP net.IP      // 创建提升会话的IP
  Expires  time.Time   // 过期时间
}
```

---

## 四、修改密码完整流程

### 4.1 完整时序图

```
前端 (SecurityView)            后端 (Handlers)
     │                              │
     │ 1. 点击修改密码              │
     │───── handleChangePassword ──►│
     │                              │
     │ 2. 获取提升状态              │
     │───── GET /elevation ────────►│
     │◄──── 返回状态 (未提升) ◄─────│
     │                              │
     │ 3. 打开SecondFactorDialog    │
     │                              │
     │ 4. 用户选择2FA方法并验证      │
     │───── POST /secondfactor/* ──►│
     │◄──── 验证成功 ◄──────────────│
     │                              │
     │ 5. 刷新提升状态              │
     │───── GET /elevation ────────►│
     │◄──── 已提升? ◄───────────────│
     │     (可能仍需OTC验证)         │
     │                              │
     │ 6. 打开IdentityVerifyDialog  │
     │                              │
     │ 7. 生成并发送OTC             │
     │───── POST /elevation ───────►│
     │                              │ 生成OneTimeCode
     │                              │ 发送邮件给用户
     │◄──── 返回delete_id ◄─────────│
     │                              │
     │ 8. 用户输入OTC               │
     │───── PUT /elevation ────────►│
     │                              │ 验证OTC
     │                              │ 创建Elevation会话
     │◄──── OK ◄───────────────────│
     │                              │
     │ 9. 打开ChangePasswordDialog  │
     │                              │
     │ 10. 用户输入新旧密码         │
     │───── POST /change-password ─►│
     │                              │
     │                              │ ┌──────────────────────┐
     │                              │ │ RequireElevated检查  │
     │                              │ │ 1. 已1FA? ✅         │
     │                              │ │ 2. 已提升? ✅        │
     │                              │ │ 3. IP匹配? ✅        │
     │                              │ └──────────────────────┘
     │                              │
     │                              │ 验证旧密码
     │                              │ 检查密码策略
     │                              │ 更新密码
     │                              │ 发送通知邮件
     │◄──── OK ◄───────────────────│
     │                              │
     │ 11. 成功提示 + 关闭对话框     │
     └──────────────────────────────┘
```

### 4.2 后端修改密码 Handler 详细流程

**文件**: `internal/handlers/handler_change_password.go:13-152`

```
1. 获取会话提供商 (session.Provider)
   └─► 失败 → 500 Internal Server Error

2. 获取用户会话 (userSession)
   └─► 失败 → 500 Internal Server Error

3. 解析请求体
   └─► 失败 → 400 Bad Request

4. 检查新密码强度 (PasswordPolicy)
   └─► 不通过 → 400 Bad Request ("Password weak")

5. 调用UserProvider.ChangePassword()
   ├─► 旧密码错误 → 401 Unauthorized ("Incorrect password")
   ├─► 新密码弱 → 400 Bad Request
   ├─► 认证失败 → 401 Unauthorized
   └─► 其他错误 → 500 Internal Server Error

6. 保存会话 (虽然密码修改不直接修改会话)
   └─► 失败 → 500 (但密码已改! ⚠️)

7. 获取用户详情 (用于发送邮件)
   └─► 失败 → 直接返回OK (不影响主流程)

8. 发送密码修改通知邮件
   └─► 失败 → 直接返回OK (不影响主流程)
```

**⚠️ 注意**: 步骤6-8失败时，密码**已经修改**，属于"部分成功"场景。

---

## 五、多因子设备 (MFA) 管理流程

### 5.1 TOTP 设备绑定

**文件**: `internal/handlers/handler_register_totp.go`

**三步注册流程**:
```
1. GET  /api/secondfactor/totp/register
   └─► 返回可用选项 (算法、周期、长度)
   [RequireElevated]

2. PUT  /api/secondfactor/totp/register
   ├─► 验证选项合规性
   ├─► 生成TOTP配置 (密钥等)
   ├─► 存入Session: userSession.TOTP (10分钟有效期)
   └─► 返回 otpauth:// URL 和 Base32密钥
   [RequireElevated]

3. POST /api/secondfactor/totp/register
   ├─► 检查Session中是否有待确认的TOTP
   ├─► 检查是否过期 (10分钟)
   ├─► 验证用户输入的Token
   ├─► 保存TOTP配置到Storage
   ├─► 清除Session中的TOTP
   └─► 发送通知邮件
   [RequireElevated]
```

**TOTP 删除流程** (`TOTPConfigurationDELETE`):
```
1. 验证会话和身份
2. 从Storage加载配置 (确保存在)
3. 从Storage删除配置
4. 记录日志事件 + 发送邮件
```

### 5.2 WebAuthn 凭证管理

**文件**: `internal/handlers/handler_webauthn_credentials.go`

**主要接口**:
| 方法   | 路径 | 权限 | 作用 |
|--------|------|------|------|
| GET    | `/api/secondfactor/webauthn/credentials` | 1FA | 获取用户所有凭证 |
| PUT    | `/api/secondfactor/webauthn/credential/register` | Elevated | 开始注册 (返回attestation options) |
| POST   | `/api/secondfactor/webauthn/credential/register` | Elevated | 完成注册 (验证attestation) |
| DELETE | `/api/secondfactor/webauthn/credential/register` | Elevated | 取消待完成的注册 |
| PUT    | `/api/secondfactor/webauthn/credential/{id}` | Elevated | 修改凭证描述 |
| DELETE | `/api/secondfactor/webauthn/credential/{id}` | Elevated | 删除凭证 |

**WebAuthn 删除/修改 安全检查**:
```
接收到删除/修改请求
    │
    ▼
从Storage加载凭证 (credentialID)
    │
    ├─► 不存在 → 403 Forbidden
    │
    ▼
检查凭证所有权 (credential.Username == session.Username)
    │
    ├─► 不匹配 → 403 Forbidden (记录警告日志!)
    │
    ▼
执行删除/修改操作
```

---

## 六、错误回滚与状态一致性

### 6.1 前端错误处理策略

**useRemoteCall 错误处理**:
```typescript
// web/src/hooks/RemoteCall.ts:14-26
try {
  setInProgress(true);
  const res = await fnCallback();
  setInProgress(false);
  setData(res);
} catch (err) {
  console.error(err);
  setError(err as Error);
  // ⚠️ 注意: 没有 setInProgress(false)
  // 但 inProgress 保持 true? 实际会被下次调用重置
}
```

**ChangePasswordDialog 错误处理** (`web/src/views/Settings/Security/ChangePasswordDialog.tsx:106-162`):
```
try {
  await postPasswordChange(...)
  ✅ 成功:
    - 成功通知
    - 关闭对话框
    - 重置所有状态
} catch (err) {
  ❌ 失败:
    - resetPasswordErrors() → 清除错误标记
    - setLoading(false) → 停止加载
    - 根据HTTP状态码精细化处理:
      • 400 (弱密码): setNewPasswordError(true) + 错误通知
      • 401 (旧密码错): setOldPasswordError(true) + 错误通知
      • 500 (其他): 通用错误通知
    - return (不关闭对话框，允许重试)
}
```

### 6.2 后端原子性与回滚

**密码修改的部分成功问题** (`handler_change_password.go`):
```
时序关键节点:

   t0 开始请求
   t1 密码验证通过
   t2 UserProvider.ChangePassword() 成功  ✅ 密码已改!
   t3 SaveSession() 失败                ❌
   t4 返回 500 错误

   结果: 前端显示"失败"，但后端密码实际已修改
```

**TOTP 注册的原子性**:
```
  临时状态存储在 Session 中 (内存/Redis)
        │
        ▼  POST 验证成功
  写入持久化 Storage
        │
        ▼
  清除 Session 中的临时状态
        │
        ▼
  返回成功

⚠️ 若 Storage 写入失败:
  - Session 临时状态保留
  - 用户可重试 POST (只要未过期)
  - 不会产生脏数据
```

### 6.3 会话同步策略

**前端会话状态刷新点**:
1. **SecondFactorDialog 关闭后** → `handleElevationRefresh()`
2. **IdentityVerificationDialog 关闭后** → 隐式刷新（后端已更新）
3. **TwoFactorAuthenticationView 操作后** → `handleRefreshState()` → 重新 fetchUserInfo

**后端会话更新时机**:
- 提升验证成功 → `ctx.SaveSession(userSession)` (写入Elevation)
- TOTP注册完成 → `ctx.SaveSession(userSession)` (清除临时TOTP)
- OTC撤销 → 不修改session（只修改Storage中的OTC记录）

---

## 七、敏感接口权限矩阵

| 接口路径 | 方法 | 所需权限 | 中间件 |
|---------|------|---------|--------|
| `/api/change-password` | POST | **Elevated 1FA** | `middlewareElevated1FA` |
| `/api/secondfactor/totp/register` | GET/PUT/POST/DELETE | **Elevated 1FA** | `middlewareElevated1FA` |
| `/api/secondfactor/totp` | DELETE | 1FA | `middleware1FA` |
| `/api/secondfactor/webauthn/credential/register` | PUT/POST/DELETE | **Elevated 1FA** | `middlewareElevated1FA` |
| `/api/secondfactor/webauthn/credential/{id}` | PUT/DELETE | **Elevated 1FA** | `middlewareElevated1FA` |
| `/api/secondfactor/webauthn/credentials` | GET | 1FA | `middleware1FA` |
| `/api/user/info` | GET/POST | 1FA | `middleware1FA` |
| `/api/user/session/elevation` | GET | 1FA | `middleware1FA` |
| `/api/user/session/elevation` | POST | 1FA + RateLimit | `middlewareElevatePOST` |
| `/api/user/session/elevation` | PUT | 1FA + RateLimit + Delay | `middlewareElevatePUT` |
| `/api/user/session/elevation/{id}` | DELETE | 公开 | `middlewareAPI` |

---

## 八、关键代码位置速查表

### 前端
| 功能 | 文件路径 |
|------|---------|
| 安全设置主页面 | `web/src/views/Settings/Security/SecurityView.tsx` |
| 双因子认证主页面 | `web/src/views/Settings/TwoFactorAuthentication/TwoFactorAuthenticationView.tsx` |
| 修改密码对话框 | `web/src/views/Settings/Security/ChangePasswordDialog.tsx` |
| 第二因子验证对话框 | `web/src/views/Settings/Common/SecondFactorDialog.tsx` |
| 身份验证(OTC)对话框 | `web/src/views/Settings/Common/IdentityVerificationDialog.tsx` |
| 远程调用Hook | `web/src/hooks/RemoteCall.ts` |
| 会话提升服务 | `web/src/services/UserSessionElevation.ts` |
| API路径定义 | `web/src/services/Api.ts` |

### 后端
| 功能 | 文件路径 |
|------|---------|
| 修改密码Handler | `internal/handlers/handler_change_password.go` |
| 会话提升Handler | `internal/handlers/handler_session_elevation.go` |
| TOTP注册Handler | `internal/handlers/handler_register_totp.go` |
| WebAuthn凭证Handler | `internal/handlers/handler_webauthn_credentials.go` |
| 权限中间件 | `internal/middlewares/require_auth.go` |
| 路由注册 | `internal/server/handlers.go` |
