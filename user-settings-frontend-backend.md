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

### 6.1 WebAuthn 凭证详情查看流程

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

### 6.2 凭证详情展示内容

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

### 6.3 登录历史（认证日志）的二次确认场景

虽然查看WebAuthn凭证详情不需要二次确认，但以下场景**需要**会话提升：

| 操作 | 前端触发 | 权限要求 |
|------|---------|---------|
| **编辑**凭证描述 | `handleEdit()` → `handleElevation()` | Elevated 1FA |
| **删除**凭证 | `handleDelete()` → `handleElevation()` | Elevated 1FA |
| **注册**新凭证 | `handleRegister()` → `handleElevation()` | Elevated 1FA |
| **查看**凭证详情 | `handleInformation()` → 直接打开 | 1FA Only |

### 6.4 二次确认完整流程（以编辑凭证为例）

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

### 8.3 回写失败策略

不同场景对回写失败的处理策略不同：

| 场景 | 回写失败处理 | 影响 |
|-----|-------------|------|
| **会话提升过期清理** | 返回500错误 | 用户无法获取提升状态，需重新验证 |
| **会话提升成功** | 返回500错误 | 验证成功但会话未保存，需重试 |
| **用户信息刷新** | 返回500错误 | 请求失败，但Session实际已更新 |
| **WebAuthn验证后清理** | 仅记录日志，继续返回成功 | 临时数据可能残留，下次请求被清理 |
| **TOTP注册完成** | 返回500错误 | 注册成功但会话未清理，可能导致重复注册 |
| **LastActivity更新** | 静默失败 | 活动时间未更新，可能导致提前超时 |

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

**失败回退策略**:
- 会话获取失败 → 返回 403 Forbidden
- 提升会话过期/IP不匹配 → 清除后尝试回写Session
  - 回写成功 → 返回正常响应（elevated=false）
  - 回写失败 → 返回 500 错误

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

### 13.3 回写失败影响矩阵

| 回写场景 | 回写失败时操作是否已执行 | 状态一致性风险 |
|---------|------------------------|--------------|
| 会话提升过期清理 | ❌ 未执行（只是清除） | 低 - 下次请求重新清理 |
| 会话提升成功 | ✅ OTC已消费 | 中 - 需重新生成OTC |
| 用户信息刷新 | ✅ Session内存已更新 | 高 - Cookie与内存不一致 |
| WebAuthn验证清理 | ✅ 验证已通过 | 低 - defer重试清理 |
| TOTP注册清理 | ✅ 已写入Storage | 中 - 可能重复注册 |
| LastActivity更新 | ❌ 仅更新时间戳 | 低 - 可能提前超时 |
| 2FA认证成功 | ✅ 认证已通过 | 中 - 需重新认证 |
