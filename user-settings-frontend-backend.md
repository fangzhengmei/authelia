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

### 5.3 登录历史（认证日志）记录机制

**认证日志数据模型** (`internal/model/regulation.go:9-19`):
```go
type AuthenticationAttempt struct {
    ID            int       `db:"id"`
    Time          time.Time `db:"time"`           // 认证时间
    Successful    bool      `db:"successful"`     // 是否成功
    Banned        bool      `db:"banned"`         // 是否被封禁
    Username      string    `db:"username"`       // 用户名
    Type          string    `db:"auth_type"`      // 认证类型: 1FA/2FA/TOTP/WebAuthn等
    RemoteIP      NullIP    `db:"remote_ip"`      // 远程IP
    RequestURI    string    `db:"request_uri"`    // 请求URI
    RequestMethod string    `db:"request_method"` // 请求方法
}
```

**登录历史记录触发点** (`internal/regulation/regulator.go:26-55`):
```
每次认证尝试（成功或失败）都调用 Regulator.HandleAttempt()
    │
    ▼
1. 调用 ctx.RecordAuthn() → 记录到Prometheus指标
    │
    ▼
2. 构造 AuthenticationAttempt 对象
    │
    ▼
3. 调用 AppendAuthenticationLog() → 写入 authentication_logs 表
    │
    ├─► 失败 → 记录错误日志，但不影响主流程
    │
    ▼
4. 若为失败的1FA认证 → 执行封禁检查
    ├─► 按IP检查 → LoadRegulationRecordsByIP()
    └─► 按用户检查 → LoadRegulationRecordsByUser()
```

---

## 六、登录历史查看与敏感信息二次确认

### 6.0 代码勘误：登录历史API缺失证据

> **⚠️ 重要勘误**：Authelia设置模块中**没有独立的登录历史页面或API**。

**路由缺失证据** (`internal/server/handlers.go`):
- 全文搜索 `/api/.*login.*history` 或 `/api/.*authentication.*log` 无匹配
- 无 `/api/user/login-history` 或类似独立API端点
- 无 `handler_login_history.go` 或类似处理器文件

**页面缺失证据** (`web/src/views/Settings/`):
- 无 `LoginHistoryPanel.tsx` 或类似页面组件
- 设置页仅包含 `SecurityView`（修改密码）和 `TwoFactorAuthenticationView`（2FA管理）

**替代分析边界**：
本文档中的"登录历史查看"分析**仅限**于以下间接功能：
1. TOTP配置信息中的 `last_used_at` 字段（通过 `/api/secondfactor/totp` GET获取）
2. WebAuthn凭证信息中的 `last_used_at` 字段（通过 `/api/secondfactor/webauthn/credentials` GET获取）
3. 内部 `authentication_logs` 表仅用于监管（封禁检测），**不对外暴露API**

---

### 6.1 TOTP与WebAuthn查看最近使用信息的二次确认差异

**TOTP 查看流程** (`web/src/views/Settings/TwoFactorAuthentication/OneTimePasswordPanel.tsx:158-160`):
```typescript
const handleInformation = () => {
    setDialogInformationOpen(true);  // 直接打开，无二次确认
};
```

**WebAuthn 查看流程** (`web/src/views/Settings/TwoFactorAuthentication/WebAuthnCredentialsPanel.tsx:188-195`):
```typescript
const handleInformation = (index: number) => {
    if (!props.credentials) return;
    if (props.credentials.length + 1 < index) return;
    
    setIndexInformation(index);
    setDialogInformationOpen(true);  // 直接打开，无二次确认
};
```

**共同点**：
- 两者的"查看"操作**都不需要二次确认**
- 只有"编辑"和"删除"操作才需要会话提升（二次确认）

**差异对比表**：

| 特性 | TOTP | WebAuthn |
|------|------|----------|
| 查看操作二次确认 | ❌ 不需要 | ❌ 不需要 |
| 编辑操作 | N/A（无编辑功能） | ✅ 需要二次确认 |
| 删除操作 | ✅ 需要二次确认 | ✅ 需要二次确认 |
| 最近使用信息 | `last_used_at`（单个时间点） | `last_used_at` + `sign_count`（使用次数） |
| 信息详细程度 | 算法、位数、周期、发行者、添加时间、最后使用 | 描述、RPID、AAGUID、 attestation类型、附件、可发现、用户验证、备份状态、传输方式、克隆警告、使用次数、添加时间、最后使用 |

**TOTP信息对话框内容** (`web/src/views/Settings/TwoFactorAuthentication/OneTimePasswordInformationDialog.tsx:70-80`):
```typescript
<PropertyText name={translate("Last Used")} value={
    props.config.last_used_at
        ? translate("{{when, datetime}}", { when: new Date(props.config.last_used_at) })
        : translate("Never")
} />
```

---

### 6.2 WebAuthn 凭证详情查看流程

**前端触发点** (`web/src/views/Settings/TwoFactorAuthentication/WebAuthnCredentialsPanel.tsx:188-195`):
```typescript
const handleInformation = (index: number) => {
    if (!props.credentials) return;
    if (props.credentials.length + 1 < index) return;
    
    setIndexInformation(index);
    setDialogInformationOpen(true);  // ⚠️ 注意: 直接打开，无二次确认!
};
```

**⚠️ 关键发现**: WebAuthn凭证详情查看（包含登录历史中的 `last_used_at`、`sign_count` 等敏感信息）**不需要**会话提升（二次确认），而编辑、删除操作才需要。

### 6.3 凭证详情展示内容

**展示数据** (`web/src/views/Settings/TwoFactorAuthentication/WebAuthnCredentialInformationDialog.tsx:1-189`):
```
基础信息:
  ├─ Description      (描述)
  ├─ Relying Party ID (RPID)
  ├─ Authenticator GUID (AAGUID)
  ├─ Attestation Type/Format
  ├─ Attachment       (平台/跨平台)
  └─ Transports       (传输方式: usb/nfc/ble等)

安全属性:
  ├─ Discoverable     (是否可发现)
  ├─ User Verified    (是否用户验证)
  ├─ Backup State     (备份状态)
  ├─ Clone Warning    (克隆警告)
  └─ Usage Count      (签名次数)

登录历史相关:
  ├─ Added            (添加时间)
  └─ Last Used        (最后使用时间 ⚠️ 敏感信息)
```

**后端API** (`internal/handlers/handler_webauthn_credentials.go:35-80`):
- **接口**: `GET /api/secondfactor/webauthn/credentials`
- **权限**: `middleware1FA` (仅需1FA认证，**无需**会话提升)
- **返回**: 完整的 `[]model.WebAuthnCredential` 数组，包含 `last_used_at`

### 6.4 登录历史（认证日志）的二次确认场景

虽然查看WebAuthn凭证详情不需要二次确认，但以下场景**需要**会话提升：

| 操作 | 前端触发 | 权限要求 |
|------|---------|---------|
| **编辑**凭证描述 | `handleEdit()` → `handleElevation()` | Elevated 1FA |
| **删除**凭证 | `handleDelete()` → `handleElevation()` | Elevated 1FA |
| **注册**新凭证 | `handleRegister()` → `handleElevation()` | Elevated 1FA |
| **查看**凭证详情 | `handleInformation()` → 直接打开 | 1FA Only |

### 6.5 二次确认完整流程（以编辑凭证为例）

```
前端 (WebAuthnCredentialsPanel)
     │
     ▼ 1. 点击 "Edit" 按钮
     │
     ├─► setDialogEditOpening(true)
     ├─► setIndexEdit(index)
     └─► handleElevation()
           │
           ├─► handleElevationRefresh()
           │     └─► GET /api/user/session/elevation
           │
           └─► setDialogSFOpening(true)
                 │
                 ▼ 2. 打开 SecondFactorDialog
                 │
                 ▼ 3. 用户完成2FA验证
                 │    (TOTP/WebAuthn/Duo)
                 │
                 ▼ 4. handleSFDialogClosed(ok=true, changed=true)
                 │
                 ├─► handleElevationRefresh()
                 │     └─► GET /api/user/session/elevation
                 │
                 ▼ 5. 检查提升状态
                       ├─► elevated OR skip_second_factor = true
                       │     └─► 打开 EditDialog ✅
                       │
                       └─► 否则
                             └─► setDialogIVOpening(true)
                                   │
                                   ▼ 6. 打开 IdentityVerificationDialog
                                   │
                                   ▼ 7. 生成并发送OTC邮件
                                   │    POST /api/user/session/elevation
                                   │
                                   ▼ 8. 用户输入OTC
                                   │    PUT /api/user/session/elevation
                                   │
                                   ▼ 9. 验证成功，创建Elevation会话
                                   │    userSession.Elevations.User = &Elevation{...}
                                   │    ctx.SaveSession(userSession)
                                   │
                                   ▼ 10. 打开 EditDialog ✅
```

---

## 七、本地缓存与Session刷新机制

### 7.1 前端本地缓存

**持久化存储Hook** (`web/src/hooks/PersistentStorage.ts:1-60`):
```typescript
// 封装localStorage，支持JSON序列化
class LocalStorage implements PersistentStorage {
    getItem(key: string) {
        const item = localStorage.getItem(key);
        // 特殊值处理: "null" → null, "undefined" → undefined
        // JSON.parse失败时返回原始字符串
    }
    setItem(key: string, value: any) {
        // value === undefined → removeItem
        // 否则 → JSON.stringify后存储
    }
}

// Hook: 状态与localStorage双向绑定
export function usePersistentStorageValue<T>(key: string, initialValue?: T) {
    const [value, setValue] = useState<T>(() => {
        // 初始化: 从localStorage读取，与initialValue合并（对象时）
        const valueFromStorage = persistentStorage.getItem(key);
        if (typeof initialValue === "object" && ...) {
            return { ...initialValue, ...valueFromStorage };  // ⚠️ 合并策略
        }
        return valueFromStorage || initialValue;
    });

    // 自动同步: value变化时写入localStorage
    useEffect(() => {
        persistentStorage.setItem(key, value);
    }, [key, value]);

    return [value, setValue] as const;
}
```

**缓存使用场景**：
- 隐私政策接受状态 (`PrivacyPolicyDrawer.tsx`)
- 主题设置 (`ThemeContext.tsx`)
- 语言设置 (`LanguageContext.tsx`)
- ⚠️ **注意**: 会话状态（elevation、user info）**不**缓存到localStorage，每次从后端获取

### 7.2 后端Session刷新机制

**RefreshTTL 字段** (`internal/session/types.go:45`):
```go
type UserSession struct {
    // ...
    RefreshTTL time.Time  // 用户信息刷新到期时间
    // ...
}
```

**刷新触发逻辑** (`internal/handlers/handler_authz_authn.go:498-555`):
```
handleSessionValidateRefresh()
     │
     ▼ 1. 检查是否需要刷新
     ├─► refresh.Never() 或 用户匿名 → 跳过
     ├─► refresh.Always() → 始终刷新
     └─► userSession.RefreshTTL.After(now) → 未到期，跳过
           │
           ▼ 已到期，执行刷新
           │
           ▼ 2. 从UserProvider获取最新用户详情
           │    GetDetails(username)
           │    ├─► 用户不存在 → 返回 invalid=true（强制登出）
           │    └─► 其他错误 → 跳过刷新，保留旧状态
           │
           ▼ 3. 比较差异 (diffEmails, diffGroups, diffDisplayName)
           │
           ▼ 4. 更新RefreshTTL（如果不是Always模式）
           │    userSession.RefreshTTL = now.Add(refresh.Value())
           │
           ▼ 5. 若有差异，更新Session
           │    userSession.Emails = details.Emails
           │    userSession.Groups = details.Groups
           │    userSession.DisplayName = details.DisplayName
           │
           ▼ 6. 返回 (modified, invalid)
```

**RefreshTTL 设置时机**：
1. **1FA认证成功**: `handler_firstfactor_password.go:143` → `RefreshTTL = now + RefreshInterval`
2. **2FA认证成功**: 不修改RefreshTTL
3. **会话刷新执行时**: `handler_authz_authn.go:537` → 更新为 `now + RefreshInterval`

### 7.3 本地缓存与Session刷新的互相影响

```
┌─────────────────────────────────────────────────────────────────────┐
│                        前端状态来源                                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  usePersistentStorageValue                                           │
│    (localStorage)                                                    │
│         │                                                            │
│         ├─► 主题、语言、隐私政策等静态配置                            │
│         └─► 页面刷新时恢复状态                                        │
│                                                                      │
│  useRemoteCall                                                       │
│    (API请求)                                                         │
│         │                                                            │
│         ├─► getState()         → 认证级别、用户名                    │
│         ├─► getUserInfo()     → 用户详情、2FA方法                   │
│         ├─► getElevation()    → 会话提升状态                        │
│         └─► getCredentials()  → WebAuthn/TOTP凭证列表               │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
                             │
                             ▼ 每次API请求都经过
┌─────────────────────────────────────────────────────────────────────┐
│                      后端会话验证 (Authz中间件)                      │
├─────────────────────────────────────────────────────────────────────┤
│  1. 验证Cookie有效性                                                │
│  2. 检查是否超时 (LastActivity + Inactivity)                         │
│  3. 检查是否需要刷新用户信息 (RefreshTTL)                            │
│  4. 如有需要，从UserProvider拉取最新信息并更新Session                │
│  5. 非"记住我"用户，更新LastActivity时间戳                           │
│  6. Session有修改 → 调用 ctx.SaveSession() 回写                      │
└─────────────────────────────────────────────────────────────────────┘
```

**状态一致性保证**：
- 前端敏感状态（elevation、user info）**每次操作前重新获取**，不依赖缓存
- 后端Session是**唯一真相来源**，每次请求都可能被更新
- 本地缓存仅存储非敏感的UI偏好设置

---

## 八、旧状态回写机制

### 8.1 回写触发条件

旧状态回写（通过 `ctx.SaveSession()`）发生在以下场景：

| 触发场景 | 代码位置 | 修改内容 |
|---------|---------|---------|
| **会话提升过期/IP不匹配** | `handler_session_elevation.go:75-107` | 清除 `Elevations.User` |
| **WebAuthn验证后清理** | `handler_sign_webauthn.go:215-221` | 清除 `userSession.WebAuthn = nil` |
| **用户信息刷新** | `handler_authz_authn.go:534-554` | 更新 `Emails/Groups/DisplayName/RefreshTTL` |
| **会话活动更新** | `handler_authz_authn.go:477-481` | 更新 `LastActivity`（非记住我用户） |
| **TOTP注册完成** | `handler_register_totp.go` | 清除 `userSession.TOTP = nil` |
| **2FA认证成功** | `handler_sign_*.go` | 设置 `SecondFactorAuthnTimestamp` |
| **会话提升成功** | `handler_session_elevation.go:346-359` | 设置 `Elevations.User` |

### 8.2 旧状态回写关键实现

**场景1: 会话提升过期自动清理** (`handler_session_elevation.go:75-107`):
```go
if userSession.Elevations.User != nil {
    var deleted bool
    
    // 检查是否过期
    if userSession.Elevations.User.Expires.Before(ctx.GetClock().Now()) {
        response.Elevated, deleted = false, true
        ctx.Logger.Info("The user session elevation has already expired...")
    }
    
    // 检查IP是否匹配
    if !userSession.Elevations.User.RemoteIP.Equal(ctx.RemoteIP()) {
        response.Expires, response.Elevated, deleted = 0, false, true
        ctx.Logger.Warn("The user session elevation was created from a different remote IP...")
    }
    
    // 旧状态回写: 清除过期的提升会话
    if deleted {
        userSession.Elevations.User = nil
        if err = ctx.SaveSession(userSession); err != nil {
            // 回写失败 → 返回500
            ctx.SetJSONError(messageOperationFailed)
            ctx.SetStatusCode(fasthttp.StatusForbidden)
            return
        }
    }
}
```

**场景2: WebAuthn验证后defer清理** (`handler_sign_webauthn.go:215-221`):
```go
defer func() {
    userSession.WebAuthn = nil  // 清除临时会话数据
    
    if err = ctx.SaveSession(userSession); err != nil {
        // ⚠️ 注意: 此处仅记录日志，不返回错误
        // 即使回写失败，验证仍然被视为成功
        ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn...")
    }
}()
```

**场景3: 用户信息刷新回写** (`handler_authz_authn.go:498-555`):
```go
// 返回值 modified 表示是否需要回写
func handleSessionValidateRefresh(...) (modified, invalid bool) {
    // ... 检查RefreshTTL ...
    
    if !refresh.Always() {
        modified = true  // 需要更新TTL
        userSession.RefreshTTL = ctx.GetClock().Now().Add(refresh.Value())
    }
    
    // ... 比较用户信息差异 ...
    
    if diffEmails || diffGroups || diffDisplayName {
        modified = true  // 需要更新用户信息
        userSession.Emails, userSession.Groups, userSession.DisplayName = ...
    }
    
    return modified, false
}

// 调用方根据modified决定是否回写
if modified {
    if err = ctx.SaveSession(userSession); err != nil {
        // 回写失败处理
    }
}
```

### 8.3 回写失败策略（代码勘误版）

> **⚠️ 重要勘误**：之前的分析有误。实际代码中回写失败**没有返回500的场景**，全部是返回403/401/400或仅记录日志。

**实际返回行为分类**：

#### 🔴 返回 403 Forbidden 的场景（共4处）

| 场景 | 代码位置 | 操作是否已执行 |
|-----|---------|--------------|
| **会话提升GET - 过期/IP不匹配清理后** | `handler_session_elevation.go:98-105` | ❌ 未执行（只是清除） |
| **会话提升PUT - 验证成功后** | `handler_session_elevation.go:352-359` | ✅ OTC已消费 |
| **WebAuthn断言GET - 生成挑战后** | `handler_sign_webauthn.go:107-114` | ❌ 未开始验证 |
| **TOTP验证POST - 验证成功后** | `handler_sign_totp.go:197-204` | ✅ 验证已通过 |

**代码示例** (`handler_session_elevation.go:98-105`):
```go
if err = ctx.SaveSession(userSession); err != nil {
    ctx.Logger.WithError(err).Error("Error occurred retrieving the user session elevation state...")
    ctx.SetJSONError(messageOperationFailed)
    ctx.SetStatusCode(fasthttp.StatusForbidden)  // 403，不是500
    return
}
```

#### 🟠 返回 401 Unauthorized 的场景（共1处）

| 场景 | 代码位置 | 操作是否已执行 |
|-----|---------|--------------|
| **密码验证POST - 验证成功后** | `handler_sign_password.go:87-93` | ✅ 验证已通过 |

**代码示例** (`handler_sign_password.go:87-93`):
```go
if err = ctx.SaveSession(userSession); err != nil {
    ctx.Logger.WithError(err).Errorf("Error occurred saving session...")
    respondUnauthorized(ctx, messageAuthenticationFailed)  // 401
    return
}
```

#### 🟡 返回 400 Bad Request 的场景（共2处）

| 场景 | 代码位置 | 操作是否已执行 |
|-----|---------|--------------|
| **会话提升PUT - 请求体解析失败** | `handler_session_elevation.go:252-259` | ❌ 未开始验证 |
| **会话提升PUT - OTC长度>20** | `handler_session_elevation.go:263-270` | ❌ 未开始验证 |

**代码示例** (`handler_session_elevation.go:252-259`):
```go
if err = ctx.ParseBody(&bodyJSON); err != nil {
    ctx.Logger.WithError(err).Errorf("Error occurred parsing body...")
    ctx.SetStatusCode(fasthttp.StatusBadRequest)  // 400
    ctx.SetJSONError(messageOperationFailed)
    return
}
```

#### 🟢 仅记录日志不返回错误的场景（共2处）

| 场景 | 代码位置 | 操作是否已执行 |
|-----|---------|--------------|
| **WebAuthn断言POST - defer清理临时数据** | `handler_sign_webauthn.go:215-221` | ✅ 验证已通过 |
| **重置密码DELETE - 清除密码重置标记** | `handler_reset_password.go:283-285` | ✅ 已清除标记 |

**代码示例** (`handler_sign_webauthn.go:215-221`):
```go
defer func() {
    userSession.WebAuthn = nil
    if err = ctx.SaveSession(userSession); err != nil {
        // ⚠️ 仅记录日志，不返回错误
        // 即使回写失败，验证仍然被视为成功
        ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn...")
    }
}()
```

---

**修正后的回写失败影响矩阵**：

| 回写场景 | 回写失败时操作是否已执行 | 实际返回状态码 | 状态一致性风险 |
|---------|------------------------|--------------|--------------|
| 会话提升过期清理 | ❌ 未执行（只是清除） | 403 | 低 - 下次请求重新清理 |
| 会话提升成功 | ✅ OTC已消费 | 403 | 中 - 需重新生成OTC |
| WebAuthn挑战生成 | ❌ 验证未开始 | 403 | 低 - 重新获取挑战 |
| WebAuthn验证清理（defer） | ✅ 验证已通过 | 200（仅日志） | 低 - 下次请求清理 |
| TOTP验证成功 | ✅ 验证已通过 | 403 | **高** - 实际已认证但返回失败 |
| 密码验证成功 | ✅ 验证已通过 | 401 | **高** - 实际已认证但返回失败 |
| 用户信息刷新 | ✅ Session内存已更新 | 200（中间件处理） | 高 - Cookie与内存不一致 |
| TOTP注册清理 | ✅ 已写入Storage | 403 | 中 - 可能重复注册 |
| LastActivity更新 | ❌ 仅更新时间戳 | 静默失败 | 低 - 可能提前超时 |
| 2FA认证成功 | ✅ 认证已通过 | 403 | **高** - 实际已认证但返回失败 |

---

## 九、错误回滚与状态一致性

### 9.1 前端错误处理策略

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

### 9.2 后端原子性与回滚

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

### 9.3 会话同步策略

**前端会话状态刷新点**:
1. **SecondFactorDialog 关闭后** → `handleElevationRefresh()`
2. **IdentityVerificationDialog 关闭后** → 隐式刷新（后端已更新）
3. **TwoFactorAuthenticationView 操作后** → `handleRefreshState()` → 重新 fetchUserInfo

**后端会话更新时机**:
- 提升验证成功 → `ctx.SaveSession(userSession)` (写入Elevation)
- TOTP注册完成 → `ctx.SaveSession(userSession)` (清除临时TOTP)
- OTC撤销 → 不修改session（只修改Storage中的OTC记录）

---

## 十、敏感接口权限矩阵

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

## 十一、关键代码位置速查表

### 前端
| 功能 | 文件路径 |
|------|---------|
| 安全设置主页面 | `web/src/views/Settings/Security/SecurityView.tsx` |
| 双因子认证主页面 | `web/src/views/Settings/TwoFactorAuthentication/TwoFactorAuthenticationView.tsx` |
| 修改密码对话框 | `web/src/views/Settings/Security/ChangePasswordDialog.tsx` |
| 第二因子验证对话框 | `web/src/views/Settings/Common/SecondFactorDialog.tsx` |
| 身份验证(OTC)对话框 | `web/src/views/Settings/Common/IdentityVerificationDialog.tsx` |
| WebAuthn凭证面板 | `web/src/views/Settings/TwoFactorAuthentication/WebAuthnCredentialsPanel.tsx` |
| WebAuthn凭证详情对话框 | `web/src/views/Settings/TwoFactorAuthentication/WebAuthnCredentialInformationDialog.tsx` |
| 远程调用Hook | `web/src/hooks/RemoteCall.ts` |
| 持久化存储Hook | `web/src/hooks/PersistentStorage.ts` |
| 会话提升服务 | `web/src/services/UserSessionElevation.ts` |
| 本地存储服务 | `web/src/services/LocalStorage.ts` |
| API路径定义 | `web/src/services/Api.ts` |

### 后端
| 功能 | 文件路径 |
|------|---------|
| 修改密码Handler | `internal/handlers/handler_change_password.go` |
| 会话提升Handler | `internal/handlers/handler_session_elevation.go` |
| TOTP注册Handler | `internal/handlers/handler_register_totp.go` |
| WebAuthn凭证Handler | `internal/handlers/handler_webauthn_credentials.go` |
| WebAuthn签名Handler | `internal/handlers/handler_sign_webauthn.go` |
| Authz认证Handler | `internal/handlers/handler_authz_authn.go` |
| 权限中间件 | `internal/middlewares/require_auth.go` |
| Authelia上下文 | `internal/middlewares/authelia_context.go` |
| 会话类型定义 | `internal/session/types.go` |
| 会话Provider | `internal/session/session.go` |
| 认证日志模型 | `internal/model/regulation.go` |
| 监管器（日志记录） | `internal/regulation/regulator.go` |
| 路由注册 | `internal/server/handlers.go` |

---

## 十二、关键分支与失败回退策略

### 12.1 会话提升关键分支

**UserSessionElevationGET 关键分支** (`handler_session_elevation.go:23-118`):
```
用户已2FA认证
    │
    ├─► SkipSecondFactor = true → 可跳过第二因子
    │
    └─► 否则 → 继续检查

用户仅1FA认证
    │
    ├─► RequireSecondFactor = true 且 有2FA设备
    │     └─► RequireSecondFactor = true
    │
    └─► SkipSecondFactor = true 且 有2FA设备
          └─► CanSkipSecondFactor = true

已有提升会话
    │
    ├─► 已过期 → 清除 + 回写Session
    │
    ├─► IP不匹配 → 清除 + 回写Session
    │
    └─► 正常 → 返回 Elevated = true
```

**失败回退策略**（代码勘误版）:
- 会话获取失败 → 返回 403 Forbidden
- 提升会话过期/IP不匹配 → 清除后尝试回写Session
  - 回写成功 → 返回正常响应（elevated=false）
  - 回写失败 → 返回 **403 Forbidden**（不是500）

### 12.2 会话提升PUT（OTC验证）关键分支

**UserSessionElevationPUT 关键分支** (`handler_session_elevation.go:226-362`):
```
接收OTC验证请求
    │
    ▼
Session获取失败 → 403
用户匿名 → 403
请求体解析失败 → 400
OTC长度>20 → 400
    │
    ▼
从Storage加载OTC
    ├─► 加载失败 → 403
    ├─► OTC为nil → 403
    ├─► 已过期 → 403
    ├─► 已撤销 → 403
    ├─► 已使用 → 403
    ├─► Intent不匹配 → 403
    └─► 验证码不匹配 → 403
    │
    ▼
标记OTC为已消费 → ConsumeOneTimeCode()
    └─► 失败 → 403
    │
    ▼
创建Elevation会话 → userSession.Elevations.User = &Elevation{...}
    │
    ▼
SaveSession(userSession)
    └─► 失败 → 403
    │
    ▼
返回成功 ✅
```

**失败回退策略**:
- 每一步验证失败都立即返回，不进行后续操作
- OTC验证失败不标记为已消费，可重试（但有速率限制）
- OTC已消费但SaveSession失败 → OTC已用，需重新生成

### 12.3 WebAuthn验证关键分支

**WebAuthnAssertionPOST 关键分支** (`handler_sign_webauthn.go:129-283`):
```
接收WebAuthn验证请求
    │
    ▼
Session获取失败 → 403
用户匿名 → 403
请求体解析失败 → 400
Challenge数据不存在 → 403
WebAuthn Provider初始化失败 → 403
WebAuthn用户加载失败 → 403
    │
    ▼
ValidateLogin() 验证签名
    └─► 失败 → 记录日志 + 返回403
    │
    ▼
defer 注册: 清除 Session.WebAuthn + SaveSession
    │
    ▼
查找匹配的凭证并更新登录信息
    ├─► 未找到 → 403
    └─► UpdateWebAuthnCredentialSignIn() 失败 → 403
    │
    ▼
CloneWarning检查 → 克隆检测 → 403
    │
    ▼
RegenerateSession() → 会话固定保护
    └─► 失败 → 403
    │
    ▼
记录成功认证日志
    │
    ▼
SetTwoFactorWebAuthn() → 更新Session
    │
    ▼
Handle2FAResponse() → 返回成功
```

**失败回退策略**:
- defer函数即使在返回错误时也会执行，确保临时数据被清理
- ValidateLogin失败 → 记录失败日志（AppendAuthenticationLog）+ 封禁检查
- 关键操作（RegenerateSession、UpdateWebAuthnCredentialSignIn）失败 → 返回错误，阻止验证成功
- defer中的SaveSession失败 → 仅记录日志，不影响验证结果（已通过验证）

### 12.4 用户信息刷新关键分支

**handleSessionValidateRefresh 关键分支** (`handler_authz_authn.go:498-555`):
```
检查是否需要刷新
    ├─► refresh.Never() → 跳过
    ├─► 用户匿名 → 跳过
    └─► RefreshTTL未到期 → 跳过
    │
    ▼
GetDetails() 从UserProvider获取最新信息
    ├─► ErrUserNotFound → 返回 invalid=true（强制登出）
    └─► 其他错误 → 跳过刷新，保留旧状态
    │
    ▼
比较差异（Emails/Groups/DisplayName）
    │
    ▼
非Always模式 → 更新RefreshTTL → modified=true
    │
    ▼
有差异 → 更新Session → modified=true
    │
    ▼
返回 (modified, invalid)
```

**失败回退策略**:
- UserProvider返回ErrUserNotFound → 标记为invalid，调用方将清除会话
- 其他错误 → 返回modified=false, invalid=false，保留现有Session状态
- 差异比较失败 → 静默跳过，不更新Session

### 12.5 前端状态重置关键分支

**WebAuthnCredentialsPanel 状态重置** (`WebAuthnCredentialsPanel.tsx:46-64`):
```typescript
// 重置所有"打开中"状态
const handleResetStateOpening = () => {
    setDialogSFOpening(false);
    setDialogIVOpening(false);
    setDialogRegisterOpening(false);
    setDialogEditOpening(false);
    setDialogDeleteOpening(false);
};

// 完整重置所有状态
const handleResetState = useCallback(() => {
    handleResetStateOpening();
    setElevation(undefined);
    setDialogRegisterOpen(false);
    setDialogEditOpen(false);
    setIndexEdit(-1);
    setDialogDeleteOpen(false);
    setIndexDelete(-1);
}, []);
```

**触发时机**:
- SecondFactorDialog关闭且操作失败（ok=false）→ `handleResetState()`
- IdentityVerificationDialog关闭且操作失败（ok=false）→ `handleResetState()`
- 操作完成后关闭对话框 → `handleResetState()`

**失败回退策略**:
- 任何对话框操作取消或失败 → 完整重置所有状态，避免状态不一致
- elevation状态设为undefined → 下次操作重新从后端获取
- 索引设为-1 → 避免引用无效凭证

---

## 十三、登录历史与缓存刷新关键分支速查

### 13.1 登录历史记录分支

```
Regulator.HandleAttempt(successful, banned, ...)
    │
    ├─► 成功 → 只记录日志，不检查封禁
    │
    ├─► 失败但已banned → 只记录日志
    │
    ├─► 非1FA认证 → 只记录日志
    │
    └─► 失败的1FA认证 → 检查封禁
          ├─► 按IP检查 → LoadRegulationRecordsByIP()
          │     └─► 超过MaxRetries → SaveBannedIP()
          │
          └─► 按用户检查 → LoadRegulationRecordsByUser()
                └─► 超过MaxRetries → SaveBannedUser()
```

### 13.2 缓存与Session交互分支

```
前端状态来源
    ├─► localStorage (usePersistentStorageValue)
    │     └─► 主题、语言、隐私政策 → 页面刷新时恢复
    │
    └─► API (useRemoteCall)
          ├─► getState() → 每次进入页面调用
          ├─► getUserInfo() → 每次进入页面调用
          ├─► getElevation() → 敏感操作前调用
          └─► getCredentials() → 每次进入页面调用

后端每次请求处理
    ├─► Cookie验证
    ├─► 超时检查 (LastActivity)
    ├─► RefreshTTL检查 → 可能触发用户信息刷新
    ├─► 非记住我用户 → 更新LastActivity
    └─► Session有修改 → SaveSession() 回写
```

### 13.3 回写失败影响矩阵（代码勘误版）

> **⚠️ 重要勘误**：此矩阵已根据实际代码行为修正，之前版本中"返回500"的描述均为错误。

| 回写场景 | 回写失败时操作是否已执行 | 实际返回状态码 | 状态一致性风险 |
|---------|------------------------|--------------|--------------|
| 会话提升过期清理 | ❌ 未执行（只是清除） | 403 | 低 - 下次请求重新清理 |
| 会话提升成功 | ✅ OTC已消费 | 403 | 中 - 需重新生成OTC |
| WebAuthn挑战生成 | ❌ 验证未开始 | 403 | 低 - 重新获取挑战 |
| WebAuthn验证清理（defer） | ✅ 验证已通过 | 200（仅日志） | 低 - 下次请求清理 |
| TOTP验证成功 | ✅ 验证已通过 | 403 | **高** - 实际已认证但返回失败 |
| 密码验证成功 | ✅ 验证已通过 | 401 | **高** - 实际已认证但返回失败 |
| 用户信息刷新 | ✅ Session内存已更新 | 200（中间件处理） | 高 - Cookie与内存不一致 |
| TOTP注册清理 | ✅ 已写入Storage | 403 | 中 - 可能重复注册 |
| LastActivity更新 | ❌ 仅更新时间戳 | 静默失败 | 低 - 可能提前超时 |
| 2FA认证成功 | ✅ 认证已通过 | 403 | **高** - 实际已认证但返回失败 |

---

### 13.4 回写失败处理策略总结

**核心原则**：回写失败的处理策略取决于**操作是否已产生不可逆影响**：

1. **操作未执行**（如会话提升过期清理、WebAuthn挑战生成）→ 返回403，让用户重试
2. **操作已执行但可重试**（如会话提升成功、OTC已消费）→ 返回403，提示用户重新验证
3. **操作已执行且不可重试**（如WebAuthn验证通过、密码验证通过）→ 仅记录日志，返回成功，避免用户困惑
4. **非关键操作**（如LastActivity更新）→ 静默失败，不影响主流程

**高风险场景警示**：
- TOTP/密码/2FA验证成功但SaveSession失败时，用户实际已认证但收到失败响应，可能导致重复验证
- 建议在前端增加重试逻辑，或在后端优化SaveSession失败时的状态一致性保障

---

## 十四、会话回写失败与认证状态的精准判定

### 14.0 核心概念澄清

> **⚠️ 关键理解**：认证状态是**内存中**的 `UserSession` 对象属性，而 `SaveSession` 只是**将会话持久化到 Cookie/Storage**。两者是分离的！

**认证状态生效点**：
- 调用 `SetTwoFactorTOTP()` / `SetTwoFactorWebAuthn()` / `SetTwoFactorPassword()` 时
- 这些方法修改 `AuthenticationMethodRefs` 字段，**立即生效于内存**
- `AuthenticationLevel()` 方法根据 `AuthenticationMethodRefs` 实时计算认证级别

**SaveSession 的作用**：
- 仅负责将内存中的 `UserSession` 序列化为 Cookie 或存储到 Redis
- 不改变内存中的任何状态
- 失败不影响内存中已设置的认证状态

---

### 14.1 各认证路径 SaveSession 失败时的认证状态判定

#### 🔴 场景1：TOTP 验证流程

**代码时序** (`handler_sign_totp.go:173-204`)：
```go
// 1. 记录成功认证日志（已写入Storage）
doMarkAuthenticationAttempt(ctx, true, ...)

// 2. 重新生成Session ID（会话固定保护）
if err = ctx.RegenerateSession(); err != nil { /* 返回403 */ }

// 3. 更新Storage中的TOTP配置最后使用时间
if err = ctx.Providers.StorageProvider.UpdateTOTPConfigurationSignIn(...); err != nil { /* 返回403 */ }

// 4. ⚠️ 内存中设置认证状态（已生效！）
userSession.SetTwoFactorTOTP(ctx.GetClock().Now())

// 5. 尝试持久化到Cookie
if err = ctx.SaveSession(userSession); err != nil {
    // ⚠️ 即使这里失败，内存中的认证状态已经是TwoFactor了！
    ctx.SetStatusCode(fasthttp.StatusForbidden)  // 返回403
    return
}

// 6. 返回成功响应
Handle2FAResponse(ctx, bodyJSON.TargetURL)
```

**判定结果**：
| 判定项 | 结果 | 判断依据 |
|-------|------|---------|
| **认证已生效？** | ✅ **是** | `SetTwoFactorTOTP()` 在 SaveSession 之前调用，内存中 AuthenticationMethodRefs.TOTP = true |
| **认证未落盘？** | ❌ **否** | 认证已在内存生效，只是Cookie没更新 |
| **实际认证级别** | TwoFactor | `AuthenticationLevel()` 返回 authentication.TwoFactor |
| **HTTP响应码** | 403 Forbidden | SaveSession 失败时的硬编码 |
| **前端感知** | 认证失败 | 前端根据403判断失败，对话框不关闭 |

---

#### 🔴 场景2：密码验证（第二因子）流程

**代码时序** (`handler_sign_password.go:75-93`)：
```go
// 1. 记录成功认证日志
doMarkAuthenticationAttempt(ctx, true, ...)

// 2. ⚠️ 内存中设置认证状态（已生效！）
userSession.SetTwoFactorPassword(ctx.GetClock().Now())

// 3. 重新生成Session ID
if err = ctx.RegenerateSession(); err != nil { /* 返回401 */ }

// 4. 尝试持久化到Cookie
if err = ctx.SaveSession(userSession); err != nil {
    // ⚠️ 即使这里失败，内存中的认证状态已经是TwoFactor了！
    respondUnauthorized(ctx, messageAuthenticationFailed)  // 返回401
    return
}

// 5. 返回成功响应
Handle2FAResponse(ctx, bodyJSON.TargetURL)
```

**判定结果**：
| 判定项 | 结果 | 判断依据 |
|-------|------|---------|
| **认证已生效？** | ✅ **是** | `SetTwoFactorPassword()` 在 SaveSession 之前调用 |
| **认证未落盘？** | ❌ **否** | 认证已在内存生效 |
| **实际认证级别** | TwoFactor | `AuthenticationLevel()` 返回 authentication.TwoFactor |
| **HTTP响应码** | 401 Unauthorized | SaveSession 失败时的硬编码 |
| **前端感知** | 认证失败 | 前端根据401判断失败 |

---

#### 🔴 场景3：WebAuthn 验证流程

**代码时序** (`handler_sign_webauthn.go:271-282`)：
```go
// 1. 重新生成Session ID
if err = ctx.RegenerateSession(); err != nil { /* 返回403 */ }

// 2. 记录成功认证日志
doMarkAuthenticationAttempt(ctx, true, ...)

// 3. ⚠️ 内存中设置认证状态（已生效！）
userSession.SetTwoFactorWebAuthn(...)

// 4. defer 注册：清理临时数据 + SaveSession
//    注意：defer 在 return 时执行，即使返回成功也会执行
//    defer 中的 SaveSession 失败只记录日志，不改变响应！

// 5. 返回成功响应（无论defer中的SaveSession是否成功！）
Handle2FAResponse(ctx, bodyJSON.TargetURL)
```

**defer 中的处理** (`handler_sign_webauthn.go:215-221`)：
```go
defer func() {
    userSession.WebAuthn = nil
    
    if err = ctx.SaveSession(userSession); err != nil {
        // ⚠️ 仅记录日志，不返回错误！
        ctx.Logger.WithError(err).Errorf("Error occurred validating a WebAuthn...")
    }
}()
```

**判定结果**：
| 判定项 | 结果 | 判断依据 |
|-------|------|---------|
| **认证已生效？** | ✅ **是** | `SetTwoFactorWebAuthn()` 在 Handle2FAResponse 之前调用 |
| **认证未落盘？** | 取决于 defer | defer 中的 SaveSession 可能失败 |
| **实际认证级别** | TwoFactor | `AuthenticationLevel()` 返回 authentication.TwoFactor |
| **HTTP响应码** | 200 OK | Handle2FAResponse 返回重定向，不受 defer 影响 |
| **前端感知** | 认证成功 | 前端收到重定向，跳转到目标URL |

---

#### 🔴 场景4：会话提升（OTC验证）流程

**代码时序** (`handler_session_elevation.go:335-361`)：
```go
// 1. ⚠️ 标记OTC为已消费（已写入Storage，不可逆！）
code.Consume(ctx)
if err = ctx.Providers.StorageProvider.ConsumeOneTimeCode(ctx, code); err != nil { /* 返回403 */ }

// 2. ⚠️ 内存中设置提升状态（已生效！）
userSession.Elevations.User = &session.Elevation{
    ID:       code.ID,
    RemoteIP: ctx.RemoteIP(),
    Expires:  ctx.GetClock().Now().Add(...),
}

// 3. 尝试持久化到Cookie
if err = ctx.SaveSession(userSession); err != nil {
    // ⚠️ 即使这里失败：
    // - OTC已消费，无法重用
    // - 内存中的Elevation已设置
    ctx.SetStatusCode(fasthttp.StatusForbidden)  // 返回403
    return
}

// 4. 返回成功响应
ctx.ReplyOK()
```

**判定结果**：
| 判定项 | 结果 | 判断依据 |
|-------|------|---------|
| **提升已生效？** | ✅ **是** | `Elevations.User` 在 SaveSession 之前设置 |
| **OTC已消费？** | ✅ **是** | `ConsumeOneTimeCode` 在 SaveSession 之前调用 |
| **实际提升状态** | 已提升 | 内存中 Elevations.User != nil |
| **HTTP响应码** | 403 Forbidden | SaveSession 失败时的硬编码 |
| **前端感知** | 提升失败 | 前端根据403判断失败，需重新生成OTC |

---

#### 🔵 场景5：修改密码流程

**代码时序** (`handler_change_password.go:61-103`)：
```go
// 1. ⚠️ 修改密码（已写入UserProvider，不可逆！）
if err = ctx.Providers.UserProvider.ChangePassword(username, old, new); err != nil {
    // 密码修改失败，返回对应错误
    return
}

// 2. 尝试持久化Session（注意：userSession 本身没有修改！）
if err = provider.SaveSession(ctx.RequestCtx, userSession); err != nil {
    // ⚠️ 即使这里失败，密码已经改了！
    ctx.SetJSONError(messageOperationFailed)
    // ⚠️ 注意：没有 SetStatusCode！默认是200？
    return
}

// 3. 发送通知邮件，返回OK
ctx.ReplyOK()
```

**关键发现**：修改密码流程中，`userSession` 本身**没有任何修改**，SaveSession 实际上是多余的调用！

**判定结果**：
| 判定项 | 结果 | 判断依据 |
|-------|------|---------|
| **密码已修改？** | ✅ **是** | `ChangePassword()` 在 SaveSession 之前调用，已写入 UserProvider |
| **Session有修改？** | ❌ **否** | 代码中没有修改 userSession 的任何字段 |
| **HTTP响应码** | 200 OK | 没有 SetStatusCode，默认返回200 |
| **响应体** | `{"status":"KO","message":"Operation failed"}` | SetJSONError 设置了错误消息 |
| **前端感知** | 密码修改失败 | 前端检测到 status="KO"，显示错误通知 |
| **实际状态** | 密码已改但前端显示失败 | 最严重的不一致场景！ |

---

### 14.2 修改密码流程回写失败的前端观察结果

**前端错误处理** (`ChangePasswordDialog.tsx:129-161`)：
```typescript
try {
    await postPasswordChange(props.username, oldPassword, newPassword);
    createSuccessNotification("Password changed successfully");
    handleClose();  // ✅ 成功：关闭对话框
} catch (err) {
    resetPasswordErrors();
    setLoading(false);
    
    if (axios.isAxiosError(err) && err.response) {
        switch (err.response.status) {
            case 400:  // 弱密码
                setNewPasswordError(true);
                createErrorNotification("Password does not meet policy");
                break;
            case 401:  // 旧密码错误
                setOldPasswordError(true);
                createErrorNotification("Incorrect password");
                break;
            case 500:  // 服务器错误
            default:
                createErrorNotification("There was an issue changing the password");
                break;
        }
    }
    // ❌ 失败：对话框保持打开，允许重试
    return;
}
```

**⚠️ 但是**：修改密码的 SaveSession 失败时，后端返回的是 **200 OK + status="KO"**，这不会触发 axios 的 catch 分支！

**实际前端行为**：
1. `postPasswordChange` 调用返回成功（HTTP 200）
2. `PostWithOptionalResponse` 检测到 `status="KO"`，**抛出异常**
3. catch 分支被触发
4. 显示通用错误通知："There was an issue changing the password"
5. 对话框**保持打开**，允许用户重试
6. **但密码实际上已经修改了！**

**用户体验问题**：
- 用户看到"密码修改失败"的错误提示
- 但旧密码已经失效，新密码已生效
- 用户再次尝试时，旧密码验证失败（401），更加困惑
- 这是最严重的状态不一致场景

---

### 14.3 认证状态与响应码决策表（可复用）

| 操作场景 | 认证/操作生效点 | SaveSession 调用时机 | 内存状态 | SaveSession失败HTTP响应 | 前端感知 | 实际状态 | 不一致风险 |
|---------|---------------|-------------------|---------|----------------------|---------|---------|-----------|
| **TOTP验证** | `SetTwoFactorTOTP()` 第195行 | 第197行，生效之后 | TwoFactor | 403 Forbidden | 认证失败 | 已认证 | ⚠️ 高 |
| **密码验证(2FA)** | `SetTwoFactorPassword()` 第77行 | 第87行，生效之后 | TwoFactor | 401 Unauthorized | 认证失败 | 已认证 | ⚠️ 高 |
| **WebAuthn验证** | `SetTwoFactorWebAuthn()` 第273行 | defer 中，返回之后 | TwoFactor | 200 OK | 认证成功 | 已认证 | ✅ 低 |
| **会话提升PUT** | `Elevations.User = &Elevation{}` 第346行 | 第352行，生效之后 | 已提升 | 403 Forbidden | 提升失败 | 已提升 | ⚠️ 中 |
| **会话提升GET清理** | `Elevations.User = nil` 第96行 | 第98行，生效之后 | 未提升 | 403 Forbidden | 获取失败 | 已清除 | ✅ 低 |
| **WebAuthn挑战生成** | `userSession.WebAuthn = &data` 第105行 | 第107行，生效之后 | 有挑战 | 403 Forbidden | 获取失败 | 已设置 | ✅ 低 |
| **修改密码** | `ChangePassword()` 第61行 | 第96行，生效之后 | 无变化 | 200 OK (status=KO) | 修改失败 | 已修改 | 🔴 极高 |
| **重置密码清理** | `PasswordResetUsername = &username` 第281行 | 第283行，生效之后 | 已标记 | 静默（仅日志） | 无感 | 已标记 | ✅ 低 |
| **LastActivity更新** | `LastActivity = now` 中间件中 | SaveSessionIfRequired | 已更新 | 静默失败 | 无感 | 已更新 | ✅ 低 |
| **用户信息刷新** | `Emails/Groups/DisplayName` 更新 | SaveSession 中间件中 | 已更新 | 200 OK | 无感 | 已更新 | ⚠️ 中 |

---

### 14.4 避免混淆的判断规则

**规则1：先找 Set* 方法调用**
- 搜索 `SetTwoFactor` / `SetOneFactor` / `Elevations.User =`
- 这些是认证状态**真正生效**的位置
- 只要这些方法调用成功，内存中认证状态就已改变

**规则2：再看 SaveSession 的位置**
- SaveSession 在 Set* 之后 → 认证已生效，回写失败不影响内存状态
- SaveSession 在 Set* 之前 → 理论上不存在这种模式
- SaveSession 在 defer 中 → 返回响应后才执行，不影响HTTP状态码

**规则3：区分"操作成功"与"响应成功"**
- ✅ **操作成功** = 核心业务逻辑执行（密码修改、验证通过）
- ✅ **响应成功** = HTTP 200 + status="OK"
- ❌ 两者可能不一致！（如修改密码场景）

**规则4：前端判断依据**
- 优先看 HTTP 状态码（401/403/500 = 失败）
- 其次看响应体 `status` 字段（"KO" = 失败）
- 但这些都**不能保证**后端实际状态

**规则5：状态一致性修复建议**
- 高风险场景（修改密码）：SaveSession 失败不应返回错误，密码已经改了
- 认证场景：SaveSession 失败后，前端应自动重试1次刷新状态
- 最佳实践：关键操作后调用 GET /api/state 重新拉取真实状态
