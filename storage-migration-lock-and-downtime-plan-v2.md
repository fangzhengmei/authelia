# Authelia 存储迁移锁定与并发边界深度分析（v2）

## 1. 核心函数签名与行号核对

### 1.1 关键函数签名确认

| 函数 | 签名 | 代码位置 |
|------|------|----------|
| `StartupCheck` | `func (p *SQLProvider) StartupCheck() (err error)` | `internal/storage/sql_provider.go:399` |
| `SchemaMigrate` | `func (p *SQLProvider) SchemaMigrate(ctx context.Context, up bool, version int) (err error)` | `internal/storage/sql_provider_schema.go:186` |
| `loadMigrations` | `func loadMigrations(providerName string, prior, target int) (migrations []model.SchemaMigration, err error)` | `internal/storage/migrations.go:53` |
| `schemaMigrate` (内部) | `func (p *SQLProvider) schemaMigrate(ctx context.Context, conn SQLXConnection, prior, target int) (err error)` | `internal/storage/sql_provider_schema.go:242` |
| `schemaMigrateLock` | `func (p *SQLProvider) schemaMigrateLock(ctx context.Context, conn SQLXConnection) (err error)` | `internal/storage/sql_provider_schema.go:271` |
| `StartupCheck` (接口) | `type StartupCheck interface { StartupCheck() (err error) }` | `internal/model/types.go:168` |

**重要修正**：`StartupCheck()` 方法**没有 `context.Context` 参数**，它在内部创建 `context.Background()`。之前文档中的签名描述有误。

### 1.2 StartupCheck 调用链

```
Providers.StartupChecks()
  [internal/middlewares/startup.go:14]
  └─> StorageProvider.StartupCheck()
      [internal/storage/sql_provider.go:399]
      ├─> 数据库连接 Ping（最多重试 19 次，每次 500ms）
      ├─> SchemaEncryptionCheckKey(ctx, false)
      ├─> SchemaMigrate(ctx, true, SchemaLatest)
      │   [internal/storage/sql_provider_schema.go:186]
      ├─> getHMACOneTimeCode()
      └─> getHMACOneTimePassword()
```

---

## 2. SchemaMigrate 执行顺序与并发边界

### 2.1 SchemaMigrate 实际执行流程

**代码位置**：`internal/storage/sql_provider_schema.go:186-240`

```go
func (p *SQLProvider) SchemaMigrate(ctx context.Context, up bool, version int) (err error) {
    var (
        tx   SQLXTx
        conn SQLXConnection
    )

    // 步骤 1: 开启事务（PostgreSQL/SQLite）或直接使用 db（MySQL）
    if p.name != providerMySQL {
        if tx, err = p.db.BeginTxx(ctx, nil); err != nil {  // 行 193
            return fmt.Errorf("failed to begin transaction: %w", err)
        }
        conn = tx
    } else {
        conn = p.db  // MySQL 不使用事务
    }

    // 步骤 2: 读取当前版本（不加锁！）
    currentVersion, err := p.SchemaVersion(ctx)  // 行 202
    if err != nil {
        return err
    }

    // 步骤 3: 如果非空数据库，获取锁
    if currentVersion != 0 {  // 行 207
        if err = p.schemaMigrateLock(ctx, conn); err != nil {  // 行 208
            return err
        }
    }

    // 步骤 4: 迁移校验
    if err = schemaMigrateChecks(p.name, up, version, currentVersion); err != nil {  // 行 213
        if tx != nil {
            _ = tx.Rollback()
        }
        return err
    }

    // 步骤 5: 执行实际迁移
    if err = p.schemaMigrate(ctx, conn, currentVersion, version); err != nil {  // 行 221
        if tx != nil && err == ErrNoMigrationsFound {
            _ = tx.Rollback()
        }
        return err
    }

    // 步骤 6: 提交事务
    if tx != nil {
        if err = tx.Commit(); err != nil {  // 行 230
            if rerr := tx.Rollback(); rerr != nil {
                return fmt.Errorf("failed to commit the transaction with: commit error: %w, rollback error: %+v", err, rerr)
            }
            return fmt.Errorf("failed to commit the transaction but it has been rolled back: commit error: %w", err)
        }
    }

    return nil
}
```

**关键发现**：
- **版本读取在锁获取之前**！`SchemaVersion()` 在第 202 行调用，而 `schemaMigrateLock()` 在第 208 行。
- 这意味着两个实例可能读取到相同的 `currentVersion`，然后其中一个在获取锁时阻塞。

### 2.2 schemaMigrate 内部执行流程

**代码位置**：`internal/storage/sql_provider_schema.go:242-269`

```go
func (p *SQLProvider) schemaMigrate(ctx context.Context, conn SQLXConnection, prior, target int) (err error) {
    // 步骤 A: 加载迁移列表（基于读取到的 prior 版本）
    migrations, err := loadMigrations(p.name, prior, target)  // 行 243
    if err != nil {
        return err
    }

    if len(migrations) == 0 {
        return ErrNoMigrationsFound
    }

    // 步骤 B: 逐个执行迁移
    for i, migration := range migrations {
        // 特殊处理：从 V0 升级时，V1 执行完后才加锁
        if migration.Up && prior == 0 && i == 1 {  // 行 255
            if err = p.schemaMigrateLock(ctx, conn); err != nil {
                return err
            }
        }

        // 应用迁移（SQL + 特殊迁移 + 写入 migrations 表）
        if err = p.schemaMigrateApply(ctx, conn, migration); err != nil {  // 行 261
            return p.schemaMigrateRollback(ctx, conn, prior, migration.After(), err)
        }
    }

    return nil
}
```

### 2.3 schemaMigrateLock 实现

**代码位置**：`internal/storage/sql_provider_schema.go:271-281`

```go
func (p *SQLProvider) schemaMigrateLock(ctx context.Context, conn SQLXConnection) (err error) {
    if p.name != providerPostgres {  // 仅 PostgreSQL 加锁！
        return nil
    }

    // LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE
    if _, err = conn.ExecContext(ctx, fmt.Sprintf(queryFmtPostgreSQLLockTable, tableMigrations, "ACCESS EXCLUSIVE")); err != nil {
        return fmt.Errorf("failed to lock tables: %w", err)
    }

    return nil
}
```

---

## 3. 多实例并发迁移时序分析（修正版）

### 3.1 PostgreSQL 多实例并发场景

假设两个 Authelia 实例（Pod A 和 Pod B）同时启动，当前 schema 版本为 22，目标版本为 24。

```
时间轴:
t0: Pod A 启动
t1: Pod B 启动
t2: Pod A: BeginTxx() → 开启事务 TA
t3: Pod B: BeginTxx() → 开启事务 TB
t4: Pod A: SchemaVersion() → 读取 currentVersion = 22  (不加锁)
t5: Pod B: SchemaVersion() → 读取 currentVersion = 22  (不加锁)
t6: Pod A: currentVersion != 0 → 执行 LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE
    └─> 获取锁成功，继续执行
t7: Pod B: currentVersion != 0 → 执行 LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE
    └─> 阻塞！等待 Pod A 释放锁
t8: Pod A: schemaMigrateChecks() → 校验通过
t9: Pod A: loadMigrations("postgres", 22, 24) → 得到 [V23, V24]
t10: Pod A: 执行 V23 迁移 → 写入 migrations 表 version_after=23
t11: Pod A: 执行 V24 迁移 → 写入 migrations 表 version_after=24
t12: Pod A: Commit TA → 锁释放，schema 版本变为 24
t13: Pod B: LOCK TABLE 获取成功，继续执行
t14: Pod B: schemaMigrateChecks() → 校验 currentVersion=22（注意：用的是 t5 读取的旧值！）
t15: Pod B: loadMigrations("postgres", 22, 24) → 得到 [V23, V24]
t16: Pod B: 执行 V23 迁移
     ├─ SQL: ALTER TABLE ... (假设 V23 是 ADD COLUMN)
     └─> 失败！列已存在（Pod A 已添加）
t17: Pod B: schemaMigrateRollback() → Rollback TB
     └─> 因为是事务，所有变更回滚，schema 仍为 24
t18: Pod B: SchemaMigrate 返回错误
t19: Pod B: StartupCheck 失败 → Pod B 启动失败，进入 CrashLoopBackOff
```

**修正后的结论**：
- 第二个实例**不会自动检测到** schema 已经被更新，因为版本号在锁获取之前就读取了
- 第二个实例会尝试重复执行迁移，失败后事务回滚
- **最终结果**：Pod A 成功迁移并启动，Pod B 启动失败（CrashLoopBackOff）
- 这不是数据损坏问题，但会导致多余的 Pod 无法启动
- Kubernetes 会自动重启失败的 Pod，第二次重启时：
  - SchemaVersion() 读取到 24
  - schemaMigrateChecks() 发现已是最新版本，返回 `ErrSchemaAlreadyUpToDate`
  - StartupCheck 成功，服务正常启动

### 3.2 MySQL 多实例并发场景（无锁保护）

```
t0: Pod A 和 Pod B 同时启动
t1: Pod A: SchemaVersion() → 22
t2: Pod B: SchemaVersion() → 22
t3: Pod A: 执行 V23 SQL: ALTER TABLE webauthn_credentials ADD COLUMN ...
t4: Pod B: 执行 V23 SQL: ALTER TABLE webauthn_credentials ADD COLUMN ...
    └─> 结果取决于 SQL 类型：
        - CREATE TABLE IF NOT EXISTS → 成功（幂等）
        - ALTER TABLE ADD COLUMN → 失败（列已存在）
        - CREATE INDEX → 失败（索引已存在）
t5: 如果 Pod B 失败：
    ├─ MySQL 无事务包裹，无法回滚
    ├─ schema 处于不确定状态（V23 部分执行）
    ├─ Pod B 启动失败
    └─ Pod A 可能成功也可能失败，取决于时序
```

**风险**：MySQL 多实例并发迁移可能导致 schema 处于不一致的中间状态，需要手动修复。

### 3.3 SQLite 多实例并发场景

```
t0: Pod A: BeginTxx() → 获取 SHARED 锁
t1: Pod B: BeginTxx() → 获取 SHARED 锁（SQLite 支持共享读锁）
t2: Pod A: 执行第一个 DDL → 升级到 EXCLUSIVE 锁
    └─> Pod B 的后续操作会阻塞或返回 SQLITE_BUSY
t3: Pod A: 完成所有迁移，Commit → 释放锁
t4: Pod B: 继续执行
    ├─ 可能由于锁等待超时失败
    └─ 或成功（但会重复执行迁移，同 PostgreSQL 场景）
```

---

## 4. 认证写路径详细分析

### 4.1 登录流程与会话续期（第一因子认证）

**入口 Handler**：`FirstFactorPasswordPOST()`
**代码位置**：`internal/handlers/handler_firstfactor_password.go:16-162`

#### 完整调用链

```
POST /api/firstfactor
  │
  ├─> ctx.ParseBody(&bodyJSON)  # 解析用户名密码
  │
  ├─> ctx.Providers.UserProvider.GetDetails(username)  # LDAP/文件后端查询
  │
  ├─> ctx.Providers.Regulator.BanCheck(ctx, username)  # 检查是否被封禁
  │   └─> LoadBannedIP() / LoadBannedUser()  # 读 banned_ip / banned_user 表
  │
  ├─> ctx.Providers.UserProvider.CheckUserPassword()  # 密码验证
  │
  ├─> doMarkAuthenticationAttempt()  # 行 87
  │   └─> Regulator.HandleAttempt()  [internal/regulation/regulator.go:26]
  │       ├─> AppendAuthenticationLog()  # 写 authentication_logs 表
  │       │   [internal/storage/sql_provider.go:1579]
  │       │   SQL: INSERT INTO authentication_logs ...
  │       │
  │       └─> 失败时：LoadRegulationRecordsByIP() / LoadRegulationRecordsByUser()
  │           └─> SaveBannedIP() / SaveBannedUser()  # 写 banned_ip / banned_user 表
  │
  ├─> provider.DestroySession(ctx.RequestCtx)  # 行 99 - 销毁旧会话
  │   [internal/session/session.go:86]
  │   └─> sessionHolder.Destroy(ctx)
  │       └─> Redis: DEL session_id 或 内存: delete(map)
  │
  ├─> userSession := provider.NewDefaultUserSession()  # 行 104
  │
  ├─> provider.SaveSession(ctx.RequestCtx, userSession)  # 行 107
  │   [internal/session/session.go:57]
  │   ├─> json.Marshal(userSession)
  │   ├─> store.Set(userSessionStorerKey, data)
  │   └─> sessionHolder.Save(ctx, store)
  │       └─> Redis: SET session_id data EX expiration 或 内存: store
  │
  ├─> provider.RegenerateSession(ctx.RequestCtx)  # 行 115 - 防止会话固定
  │   [internal/session/session.go:81]
  │   └─> sessionHolder.Regenerate(ctx)
  │       └─> 生成新 session_id，旧 session_id 失效
  │
  ├─> keepMeLoggedIn = ...  # 行 124 - 记住我逻辑
  │
  ├─> if keepMeLoggedIn: provider.UpdateExpiration()  # 行 128
  │   [internal/session/session.go:91]
  │   └─> store.SetExpiration(rememberMeDuration)
  │
  ├─> userSession.SetOneFactorPassword(now, details, keepMeLoggedIn)  # 行 140
  │   [internal/session/user_session.go:40]
  │   ├─> setOneFactor()  # 设置 FirstFactorAuthnTimestamp, LastActivity, Username 等
  │   └─> AuthenticationMethodRefs.KnowledgeBasedAuthentication = true
  │
  ├─> userSession.RefreshTTL = ...  # 行 143 - 配置刷新间隔
  │
  └─> provider.SaveSession(ctx.RequestCtx, userSession)  # 行 146 - 保存最终会话
      └─> Redis: SETEX 或 内存存储
```

**涉及的数据库/存储操作**：

| 操作 | 表/存储 | SQL/命令 | 阻塞风险 |
|------|---------|----------|----------|
| 认证日志 | `authentication_logs` | `INSERT` | 无（仅 DDL 时短暂阻塞） |
| 封禁查询 | `banned_ip`, `banned_user` | `SELECT` | 无 |
| 封禁写入 | `banned_ip`, `banned_user` | `INSERT` | 无 |
| 会话存储 | Redis / 内存 | `SET`, `DEL`, `SETEX` | 无（完全独立于关系型存储） |

**关键发现**：Authelia 的会话存储**完全独立**于关系型数据库！使用 `github.com/fasthttp/session/v2` 库，支持：
- **内存**（默认，单实例部署）
- **Redis**（高可用部署，多实例共享）

因此，**会话刷新路径不受数据库迁移锁的影响**！

---

### 4.2 会话校验与活动更新（每次请求）

**入口 Middleware**：`handleAuthnCookieValidate()`
**代码位置**：`internal/handlers/handler_authz_authn.go:430-484`

#### 完整调用链（每次受保护请求都会执行）

```
每次请求 → handleAuthnCookieValidate()
  │
  ├─> manager.GetSessionProvider() → *session.Session
  │
  ├─> provider.GetSession(ctx)  # 从 Cookie 解析 session_id，加载会话
  │   [internal/session/session.go:30]
  │   ├─> sessionHolder.Get(ctx) → *session.Store
  │   │   └─> Redis: GET session_id 或 内存: map[session_id]
  │   └─> json.Unmarshal(data, &userSession)
  │
  ├─> handleAuthnCookieValidateInactivity()  # 行 461
  │   [internal/handlers/handler_authz_authn.go:486]
  │   └─> 检查 userSession.LastActivity 是否超过 Inactivity 阈值
  │       └─> KeepMeLoggedIn 的会话跳过此检查
  │
  ├─> handleSessionValidateRefresh()  # 行 467
  │   [internal/handlers/handler_authz_authn.go:498]
  │   ├─> if refresh.Never() || isAnonymous: return
  │   ├─> if userSession.RefreshTTL.After(now): return  # 未到刷新时间
  │   │
  │   ├─> UserProvider.GetDetails(username)  # 行 515 - 从 LDAP/文件刷新用户信息
  │   │
  │   ├─> 比较 Emails, Groups, DisplayName 是否变化
  │   │
  │   ├─> modified = true
  │   └─> userSession.RefreshTTL = now.Add(refreshInterval)  # 行 537
  │
  ├─> if !userSession.KeepMeLoggedIn:  # 行 477
  │   ├─> modified = true
  │   └─> userSession.LastActivity = now.Unix()  # 行 480 - 更新活动时间
  │
  └─> if modified:
      └─> provider.SaveSession(ctx, userSession)
          └─> Redis: SETEX session_id 或 内存更新
```

**会话校验路径的数据库操作**：

| 操作 | 存储 | 说明 | 阻塞风险 |
|------|------|------|----------|
| 会话加载 | Redis/内存 | 每次请求 | 无 |
| 用户信息刷新 | LDAP/文件后端 | 按 RefreshInterval 周期 | 无（不访问关系型 DB） |
| 会话保存 | Redis/内存 | modified=true 时 | 无 |

**关键发现**：会话校验过程**完全不访问关系型数据库**！所有用户信息来自认证后端（LDAP/文件），会话数据来自 Redis 或内存。因此，**会话刷新和校验在数据库迁移期间完全不受影响**。

---

### 4.3 一次性验证码（OTC）消费流程

**入口 Handler**：`UserSessionElevatePOST()` 中的 OTC 验证逻辑
**代码位置**：`internal/handlers/handler_session_elevation.go:320-362`

#### 完整调用链（会话提升 OTC 验证）

```
POST /api/session/elevate/one-time-code
  │
  ├─> ctx.GetSession()  # 加载用户会话
  │
  ├─> code, err = ctx.Providers.StorageProvider.LoadOneTimeCodeByPublicID(ctx, id)
  │   [internal/storage/sql_provider.go:1102]
  │   SQL: SELECT * FROM one_time_code WHERE public_id = ?
  │
  ├─> 检查 code 是否已消费或已撤销
  │   ├─> code.ConsumedAt.Valid → 错误：已消费
  │   └─> code.RevokedAt.Valid → 错误：已撤销
  │
  ├─> 验证 OTP 值：subtle.ConstantTimeCompare(code.Code, bodyJSON.OneTimeCode)
  │
  ├─> code.Consume(ctx)  # 行 335 - 设置 ConsumedAt, ConsumedIP
  │   [internal/model/one_time_code.go]
  │
  ├─> ctx.Providers.StorageProvider.ConsumeOneTimeCode(ctx, code)  # 行 337
  │   [internal/storage/sql_provider.go:1035]
  │   SQL: UPDATE one_time_code
  │        SET consumed = ?, consumed_ip = ?
  │        WHERE signature = ?
  │   └─> 检查 RowsAffected() == 1
  │
  ├─> userSession.Elevations.User = &session.Elevation{...}  # 行 346
  │
  └─> ctx.SaveSession(userSession)  # 行 352 - 保存会话（Redis/内存）
```

#### OTC 生成流程（发送验证码时）

```
发送重置密码/会话提升邮件时：
  ├─> 生成随机 code
  ├─> ctx.Providers.StorageProvider.SaveOneTimeCode(ctx, code)
  │   [internal/storage/sql_provider.go:1018]
  │   ├─> code.Signature = otcHMACSignature(...)
  │   ├─> code.Code = encrypt(code.Code)  # AES 加密
  │   └─> SQL: INSERT INTO one_time_code ...
  └─> 发送邮件（包含 code）
```

**OTC 路径涉及的数据库操作**：

| 操作 | 表 | SQL | 阻塞风险 |
|------|----|-----|----------|
| OTC 生成 | `one_time_code` | `INSERT` | 仅 DDL 时短暂阻塞 |
| OTC 查询 | `one_time_code` | `SELECT` | 仅 DDL 时短暂阻塞 |
| OTC 消费 | `one_time_code` | `UPDATE` | 仅 DDL 时短暂阻塞 |

**迁移期间的阻塞行为**：
- 如果迁移不涉及 `one_time_code` 表的 DDL → **完全不阻塞**
- 如果迁移包含 `one_time_code` 表的 DDL → **DDL 执行期间阻塞**（通常毫秒级）
- 由于 OTC 消费是幂等的（UPDATE WHERE signature = ?），阻塞超时失败后用户可重试

---

### 4.4 登录日志写入详细分析

**入口函数**：`AppendAuthenticationLog()`
**代码位置**：`internal/storage/sql_provider.go:1579-1587`

```go
func (p *SQLProvider) AppendAuthenticationLog(ctx context.Context, attempt model.AuthenticationAttempt) (err error) {
    if _, err = p.db.ExecContext(ctx, p.sqlInsertAuthenticationAttempt,
        attempt.Time, attempt.Successful, attempt.Banned, attempt.Username,
        attempt.Type, attempt.RemoteIP, attempt.RequestURI, attempt.RequestMethod); err != nil {
        return fmt.Errorf("error inserting authentication attempt for user '%s': %w", attempt.Username, err)
    }
    return nil
}
```

**SQL 定义**（PostgreSQL 版本）：
```sql
INSERT INTO authentication_logs (time, successful, banned, username, type, remote_ip, request_uri, request_method)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);
```

**迁移期间的阻塞行为**：
- 只有当迁移脚本执行 `ALTER TABLE authentication_logs` 时才会阻塞
- 查看历史迁移，只有 V20（Regulation）创建了 `banned_user` 和 `banned_ip` 表，没有修改 `authentication_logs` 表结构
- 因此，**登录日志写入在所有已知迁移中都不会阻塞**

---

### 4.5 会话刷新 vs 数据库迁移：影响总结

| 路径 | 关系型 DB 操作 | 会话存储 | 迁移期间是否阻塞 | 备注 |
|------|---------------|----------|------------------|------|
| 登录（1FA） | `INSERT authentication_logs` | Redis/内存（独立） | 几乎不阻塞 | 会话管理完全走 Redis |
| TOTP/WebAuthn 登录 | `UPDATE totp_configurations` / `INSERT authentication_logs` | Redis/内存 | 几乎不阻塞 | |
| 会话校验（每次请求） | 无 | Redis/内存 | **完全不阻塞** | 不访问关系型 DB |
| 会话刷新（RefreshInterval） | 无 | Redis/内存 | **完全不阻塞** | 从 LDAP 刷新，不访问 DB |
| OTC 生成 | `INSERT one_time_code` | - | 仅 DDL 时短暂 | |
| OTC 消费 | `UPDATE one_time_code` | - | 仅 DDL 时短暂 | |
| OAuth2 Token 生成 | `INSERT oauth2_*_session` | - | 仅 DDL 时短暂 | |
| OAuth2 Token 刷新 | `UPDATE oauth2_*_session` | - | 仅 DDL 时短暂 | |

**最重要的结论**：Authelia 的**会话管理完全独立于关系型数据库**。只要 Redis（或内存）正常，即使关系型数据库迁移期间，用户的已登录会话仍可正常访问受保护资源。

---

## 5. 三种后端锁定行为对比（完整版）

### 5.1 PostgreSQL 锁定机制详解

**锁定策略**：
1. **事务级别**：迁移全程在事务内执行
2. **显式锁**：`LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE`
   - 仅作用于 `migrations` 表
   - 阻止其他迁移执行，但不影响业务表
3. **隐式锁**：DDL 执行时自动获取业务表的 ACCESS EXCLUSIVE 锁
   - 仅在 DDL 语句执行期间持有
   - 语句完成即释放（毫秒级）

**锁时序**：
```
BEGIN TRANSACTION
  ├─ SchemaVersion() → 无锁
  ├─ LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE  ← 只锁 migrations 表
  ├─ schemaMigrateChecks()
  ├─ 执行迁移：
  │   ├─ V23: ALTER TABLE webauthn_credentials ...
  │   │   └─ 获取 webauthn_credentials 表的 ACCESS EXCLUSIVE 锁（短暂）
  │   ├─ V24: ALTER TABLE ...
  │   │   └─ 获取对应表的 ACCESS EXCLUSIVE 锁（短暂）
  │   └─ 每次迁移后 INSERT INTO migrations ...
  │       └─ 需要 migrations 表的写锁（已持有）
  └─ COMMIT  ← 释放所有锁
```

**业务影响**：
- 无业务表 DDL 的迁移 → **业务零影响**
- 有业务表 DDL 的迁移 → **仅 DDL 执行瞬间阻塞**（通常 < 50ms）
- V24 特殊迁移的数据处理阶段（SELECT + UPDATE 凭证）→ **不阻塞**（行级锁）

---

### 5.2 MySQL 锁定机制详解

**锁定策略**：
1. **无事务包裹**：每个 DDL 语句独立执行并隐式提交
2. **无显式锁**：不执行 `LOCK TABLE`
3. **MDL 锁**：DDL 执行时获取元数据锁（Metadata Lock）
   - 锁类型：MDL 写锁
   - 持续时间：DDL 执行全程
   - 影响：阻塞所有对该表的读写操作

**风险点**：
- `ALTER TABLE` 大表可能需要几分钟到几小时
- 期间该表完全不可用
- 失败后无法自动回滚，schema 处于中间状态

---

### 5.3 SQLite 锁定机制详解

**锁定策略**：
1. **事务级别**：迁移全程在事务内执行
2. **文件级锁**：
   - `BEGIN TRANSACTION` → 获取 SHARED 锁（可并发读）
   - 第一个 DDL 执行 → 升级到 EXCLUSIVE 锁（独占整个数据库文件）
   - 持续到 `COMMIT` 或 `ROLLBACK`

**业务影响**：
- 迁移期间**整个数据库不可写**
- 读操作可能成功（取决于 WAL 模式和锁等待超时）
- 停机时间 = 整个迁移执行时间

---

### 5.4 三种后端对比矩阵（完整版）

| 维度 | PostgreSQL | MySQL | SQLite |
|------|------------|-------|--------|
| **显式迁移锁** | ACCESS EXCLUSIVE on `migrations` 表 | 无 | 无（事务隐式升级） |
| **事务包裹** | 是 | 否 | 是 |
| **DDL 原子性** | 事务内原子，可回滚 | 每条 DDL 隐式提交，不可回滚 | 事务内原子，可回滚 |
| **业务表锁定** | 仅 DDL 执行瞬间（毫秒级） | DDL 执行全程（可能很长） | 迁移全程（整个文件锁） |
| **登录写入** | 不阻塞（无 DDL 时） | 不阻塞（无 DDL 时） | 迁移全程阻塞 |
| **会话校验** | 完全不阻塞（独立存储） | 完全不阻塞（独立存储） | 完全不阻塞（独立存储） |
| **会话刷新** | 完全不阻塞（独立存储） | 完全不阻塞（独立存储） | 完全不阻塞（独立存储） |
| **OTC 写入** | 仅 DDL 时短暂阻塞 | 仅 DDL 时短暂阻塞 | 迁移全程阻塞 |
| **并发迁移防护** | 强（migrations 表锁） | 无 | 弱（文件锁竞争） |
| **失败回滚能力** | 完全 | 尽力而为（可能残留） | 完全 |
| **最小停机时间** | < 1s（各 DDL 时间之和） | 不确定（大表可能小时级） | 几秒到几十秒 |
| **推荐部署规模** | 生产级、多实例 | 中小规模、单实例 | 测试、单实例 |

---

## 6. 自动迁移 vs CLI 迁移对比（修正版）

### 6.1 自动迁移（StartupCheck）

**触发时机**：每次 Authelia 服务启动时，在 `StartupCheck()` 中自动调用 `SchemaMigrate(ctx, true, SchemaLatest)`。

**执行时序**：
```
authelia serve 启动
  └─> Providers.StartupChecks()  [internal/middlewares/startup.go:14]
      └─> StorageProvider.StartupCheck()  [internal/storage/sql_provider.go:399]
          ├─> Ping 数据库（重试 19 次）
          ├─> SchemaEncryptionCheckKey()
          ├─> SchemaMigrate(ctx, true, SchemaLatest)  ← 自动迁移
          └─> 初始化 HMAC 密钥
```

**多实例风险（PostgreSQL）**：
- 场景：Kubernetes 滚动更新，`maxSurge = 2`，同时启动两个新版本 Pod
- 结果：一个成功，一个启动失败（CrashLoopBackOff），第二次重启成功
- 影响：短暂的 Pod 启动失败，不影响已运行的旧版本 Pod

**多实例风险（MySQL）**：
- 场景：同时启动两个新版本 Pod
- 结果：可能导致 schema 损坏，需要手动修复
- 影响：可能需要从备份恢复

### 6.2 CLI 预迁移

**执行方式**：`authelia storage migrate up --target N --config /path/to/config.yml`

**执行时序**：
```
# 独立进程执行，与业务服务解耦
authelia storage migrate up --target 24
  └─> SchemaMigrate(ctx, true, 24)
      └─> 单进程执行，无并发风险
```

**优势**：
1. 迁移与应用部署解耦
2. 可在业务低峰期执行
3. 失败不影响运行中的服务
4. 可逐版本验证（`--target` 逐步升级）
5. 无多实例并发风险

### 6.3 详细对比矩阵

| 维度 | 自动迁移 (StartupCheck) | CLI 预迁移 |
|------|-------------------------|------------|
| **触发时机** | 服务启动时 | 手动/脚本调用 |
| **执行进程** | 业务服务进程内 | 独立 CLI 进程 |
| **并发风险** | PostgreSQL: 低（失败重启即可）<br/>MySQL: 高（可能损坏） | **无**（单进程执行） |
| **停机窗口** | 与服务启动绑定 | 可独立调度，与部署解耦 |
| **停机时间** | PostgreSQL: 秒级<br/>MySQL: 不确定<br/>SQLite: 迁移全程 | 与自动迁移相同，但可在低峰期 |
| **可控性** | 自动执行，不可干预 | 完全可控，可先验证再部署 |
| **回滚灵活性** | 失败自动回滚，成功后需手动 down | 支持显式 up/down，可逐版本验证 |
| **调试能力** | 只有启动日志 | 可逐版本执行，详细输出 |
| **失败影响** | 服务启动失败（CrashLoopBackOff） | 不影响运行中的服务 |
| **大表迁移** | 可能阻塞滚动更新 | 可在低峰期单独执行 |
| **运维复杂度** | 低（全自动） | 中（需额外步骤） |
| **推荐场景** | 单实例、SQLite、小数据量 | 多实例、PostgreSQL/MySQL、生产环境 |

---

## 7. 最小停机升级可执行步骤（修正版）

### 7.1 升级前检查清单

#### 步骤 0：环境与版本确认

```bash
# 1. 确认当前 Authelia 版本
authelia --version

# 2. 确认当前数据库 schema 版本
authelia storage schema-info

# 3. 确认新版本支持的最大 schema 版本
./new-authelia storage schema-info

# 4. 确认会话存储配置
# 检查配置文件: session.redis != null → 使用 Redis（推荐多实例）
# session.redis == null → 使用内存（仅单实例）

# 5. 备份数据库（CRITICAL!）
# PostgreSQL:
pg_dump -U authelia -W authelia > authelia_backup_$(date +%Y%m%d).sql

# MySQL:
mysqldump -u authelia -p authelia > authelia_backup_$(date +%Y%m%d).sql

# SQLite:
cp /path/to/db.sqlite /path/to/db.sqlite.backup.$(date +%Y%m%d)

# 6. 备份 Redis（如使用）
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb /path/to/redis_backup_$(date +%Y%m%d).rdb
```

#### 步骤 0.5：分析迁移影响

查看待执行的迁移脚本，识别高风险操作：

```bash
# 列出两个版本之间的迁移
# 例如：从版本 22 升级到 24
# 检查:
#   - V23: migrations/{provider}/V0023.*.up.sql
#   - V24: migrations/{provider}/V0024.*.up.sql

# 高风险标志:
# - ALTER TABLE 大表 (authentication_logs, oauth2_*_session)
# - 需要全表扫描的特殊迁移 (如 V24)
# - CREATE INDEX CONCURRENTLY (PostgreSQL 专用，不锁表但慢)
# - 有 migrationsSpecialUp 注册的版本（当前只有 V24）
```

### 7.2 PostgreSQL 后端最小停机升级流程

**推荐方式**：CLI 预迁移 + 滚动更新

#### 阶段 1：预迁移（业务低峰期，如凌晨 2:00-4:00）

```bash
# 1. 使用新版本二进制执行迁移
# 注意: 使用新版本的 authelia 可执行文件！
./new-authelia storage migrate up --target 24 --config /path/to/config.yml

# 预期输出:
# INFO: Storage schema migration from version 22 to 24 is complete.

# 2. 验证迁移结果
./new-authelia storage schema-info
# 应输出: Schema version: 24 (Latest: 24)

# 3. 查看迁移历史
./new-authelia storage migrate history | head -10

# 4. 验证关键业务流程
# - 测试登录（1FA + 2FA）
# - 测试密码重置（OTC 流程）
# - 测试 OAuth2 登录
# - 测试已登录会话访问（应完全正常）
```

**预期影响**：
- 各 DDL 执行期间短暂阻塞对应表（毫秒级）
- V24 特殊迁移的数据处理阶段不阻塞写入
- 已登录用户的会话访问**完全不受影响**（Redis 独立）
- 总体业务几乎无感知

#### 阶段 2：滚动更新应用

```bash
# Kubernetes 示例:
# 确保 maxSurge 和 maxUnavailable 配置合理
kubectl patch deployment authelia \
  -p '{"spec":{"strategy":{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0}}}}'

# 执行滚动更新
kubectl set image deployment/authelia authelia=new-version:tag

# 或者使用 Helm:
helm upgrade authelia authelia/authelia --version x.y.z \
  --set strategy.rollingUpdate.maxSurge=1 \
  --set strategy.rollingUpdate.maxUnavailable=0

# 监控滚动更新状态
kubectl rollout status deployment/authelia
kubectl get pods -w
```

**关键**：新版本 Pod 启动时，`StartupCheck()` 会发现 schema 已是最新版本（24），直接启动服务，**不会重复执行迁移**。

#### 阶段 3：验证与监控

```bash
# 1. 检查日志中无迁移错误
kubectl logs -l app=authelia | grep -i "migration\|schema"
# 应看到: "Storage schema is already up to date"

# 2. 验证认证流程正常
# - 测试用户名密码登录
# - 测试 TOTP
# - 测试 WebAuthn
# - 测试 OAuth2/OpenID Connect
# - 测试密码重置

# 3. 监控数据库连接和锁
# PostgreSQL:
psql -c "SELECT * FROM pg_locks WHERE mode = 'AccessExclusiveLock';"
psql -c "SELECT pid, query, state FROM pg_stat_activity WHERE state = 'active';"

# 4. 监控 Redis
redis-cli INFO stats | grep connected_clients
redis-cli INFO memory | grep used_memory_human
```

#### 回滚流程（如发现问题）

```bash
# 1. 先回滚应用到旧版本
kubectl rollout undo deployment/authelia

# 2. 等待旧版本正常运行
kubectl rollout status deployment/authelia

# 3. 确认旧版本兼容性
# 注意: 旧版本的 StartupCheck 会检查 schema 版本
# 如果新版本的 schema 有不兼容变更，旧版本可能启动失败
# 此时需要执行 schema 回滚

# 4. 如需回滚 schema（谨慎操作!）:
# 先确认业务影响
./new-authelia storage migrate down --target 22 --config /path/to/config.yml
# 需要输入 "DESTROY" 确认
```

### 7.3 MySQL 后端最小停机升级流程

**特殊注意**：MySQL 无事务包裹，大表 ALTER TABLE 可能造成长时间停机。

#### 阶段 1：预迁移准备

```bash
# 1. 特别检查是否有大表变更
# 查看 migrations/mysql/V*.up.sql 中的 ALTER TABLE

# 2. 估算 ALTER TABLE 时间（可选，在备库测试）
# 在测试环境执行:
mysql -e "SET profiling = 1;"
mysql -e "ALTER TABLE big_table ADD COLUMN ...;"
mysql -e "SHOW PROFILES;"

# 3. 如果预期停机 > 30 秒:
# - 公告维护窗口
# - 或考虑使用 pt-online-schema-change 等外部工具先执行变更
# - 或设置 Authelia 为维护模式
```

#### 阶段 2：低峰期 CLI 迁移

```bash
# 1. 执行迁移
./new-authelia storage migrate up --target 24 --config /path/to/config.yml

# 2. 持续监控
# MySQL:
mysql -e "SHOW PROCESSLIST;"
mysql -e "SHOW OPEN TABLES WHERE In_use > 0;"
mysql -e "SELECT * FROM information_schema.INNODB_TRX\G"
```

**如果遇到长时间锁等待**：
- 评估是继续等待还是中断
- 中断后可能需要手动清理部分执行的迁移
- 可执行 `SHOW ENGINE INNODB STATUS;` 查看死锁信息

#### 阶段 3 & 4：同 PostgreSQL

### 7.4 SQLite 后端最小停机升级流程

**特性**：SQLite 迁移期间整个数据库锁定，停机时间 = 迁移执行时间。

#### 方案 A：维护窗口停机升级（推荐）

```bash
# 1. 停止 Authelia 服务
systemctl stop authelia
# 或
kubectl scale deployment authelia --replicas=0

# 2. 备份数据库
cp /path/to/db.sqlite /path/to/db.sqlite.backup.pre_upgrade

# 3. 执行迁移
./new-authelia storage migrate up --target 24 --config /path/to/config.yml

# 4. 验证迁移
./new-authelia storage schema-info

# 5. 更新应用二进制/镜像
# ...

# 6. 启动服务
systemctl start authelia
# 或
kubectl scale deployment authelia --replicas=N
```

**总停机时间**：迁移执行时间 + 应用重启时间（通常几秒到几十秒）

#### 方案 B：最小化停机（不推荐，SQLite 不适合）

```bash
# 1. 准备新版本代码和配置
# 2. 执行迁移（会有短暂写入阻塞）
./new-authelia storage migrate up --target 24 --config /path/to/config.yml
# 3. 立即热重启/快速切换到新版本
```

### 7.5 多实例部署特殊注意事项

#### PostgreSQL 多实例并发防护

虽然 PostgreSQL 的 `LOCK TABLE` 能保证数据一致性，但仍建议：

```bash
# Kubernetes 安全升级配置:
# 1. 设置 maxSurge = 1，maxUnavailable = 0
# 2. 配置 readinessProbe 确保服务就绪后再接收流量
# 3. 可选: 使用 initContainer 执行迁移
initContainers:
- name: migrate
  image: new-authelia:tag
  command: ["authelia", "storage", "migrate", "up"]
  args: ["--target", "24", "--config", "/config/config.yml"]
  volumeMounts:
  - name: config
    mountPath: /config
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    allowPrivilegeEscalation: false
    readOnlyRootFilesystem: true
    capabilities:
      drop: ["ALL"]
```

**initContainer 方式的优势**：
- 确保迁移在应用启动前完成
- 只有一个 initContainer 执行迁移（Pod 顺序启动）
- 迁移失败则 Pod 启动失败，不会影响运行中的 Pod

#### MySQL 多实例必须确保单实例迁移

```bash
# MySQL 安全的多实例升级步骤:
# 1. 将所有实例设置为 maintenance 模式（如果支持）
# 2. 缩减到单实例运行
kubectl scale deployment authelia --replicas=1

# 3. 等待其他实例终止
kubectl wait --for=delete pod -l app=authelia --timeout=60s

# 4. 使用 CLI 执行迁移
./new-authelia storage migrate up --target 24 --config /path/to/config.yml

# 5. 滚动更新到新版本
kubectl set image deployment/authelia authelia=new-version:tag

# 6. 扩展回多实例
kubectl scale deployment authelia --replicas=N
```

### 7.6 升级后验证脚本

```bash
#!/bin/bash
# upgrade-validation.sh

set -e

echo "=== Authelia Upgrade Validation ==="
echo ""

echo "--- Schema Version Check ---"
authelia storage schema-info
echo ""

echo "--- Migration History (last 10) ---"
authelia storage migrate history | head -10
echo ""

echo "--- Basic Authentication Test ---"
# 建议使用 API 自动化测试
# curl -X POST http://authelia/api/firstfactor \
#   -H "Content-Type: application/json" \
#   -d '{"username":"test","password":"test"}'
echo "[MANUAL] Please test 1FA and 2FA login"
echo ""

echo "--- OTC Flow Test ---"
echo "[MANUAL] Please test password reset flow"
echo ""

echo "--- OAuth2 Flow Test ---"
echo "[MANUAL] Please test OAuth2/OIDC login"
echo ""

echo "--- Session Persistence Test ---"
echo "[MANUAL] Please verify existing sessions remain valid"
echo ""

echo "--- Database Health Check ---"
# PostgreSQL:
# psql -c "SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC LIMIT 10;"

# MySQL:
# mysql -e "SHOW TABLE STATUS WHERE Name LIKE 'auth%' OR Name LIKE 'oauth2%' OR Name LIKE 'one_time%' OR Name LIKE 'webauthn%' OR Name LIKE 'totp%';"

# SQLite:
# sqlite3 /path/to/db.sqlite ".tables"
echo ""

echo "--- Redis Health Check (if applicable) ---"
# redis-cli ping
# redis-cli INFO stats | grep -E "connected_clients|total_commands_processed"
echo ""

echo "--- Error Log Check (last 10 minutes) ---"
# journalctl -u authelia --since "10 minutes ago" | grep -i "error\|warn" | head -20
# kubectl logs -l app=authelia --tail=100 | grep -i "error\|warn" | head -20
echo ""

echo "=== Upgrade Validation Complete ==="
echo "If all checks passed, the upgrade was successful."
```

---

## 8. 关键代码路径索引（v2 修正版）

| 功能 | 文件 | 行号 |
|------|------|------|
| StartupCheck (存储) | `internal/storage/sql_provider.go` | 399 |
| StartupCheck (接口定义) | `internal/model/types.go` | 168 |
| StartupChecks (统一入口) | `internal/middlewares/startup.go` | 14 |
| SchemaMigrate (公开) | `internal/storage/sql_provider_schema.go` | 186 |
| schemaMigrate (内部) | `internal/storage/sql_provider_schema.go` | 242 |
| schemaMigrateLock | `internal/storage/sql_provider_schema.go` | 271 |
| loadMigrations | `internal/storage/migrations.go` | 53 |
| FirstFactorPasswordPOST | `internal/handlers/handler_firstfactor_password.go` | 16 |
| AppendAuthenticationLog | `internal/storage/sql_provider.go` | 1579 |
| handleAuthnCookieValidate | `internal/handlers/handler_authz_authn.go` | 430 |
| handleSessionValidateRefresh | `internal/handlers/handler_authz_authn.go` | 498 |
| handleAuthnCookieValidateInactivity | `internal/handlers/handler_authz_authn.go` | 486 |
| UserSessionElevatePOST (OTC) | `internal/handlers/handler_session_elevation.go` | 276 |
| SaveOneTimeCode | `internal/storage/sql_provider.go` | 1018 |
| ConsumeOneTimeCode | `internal/storage/sql_provider.go` | 1035 |
| SaveSession (会话存储) | `internal/session/session.go` | 57 |
| GetSession (会话加载) | `internal/session/session.go` | 30 |
| Regulator.HandleAttempt | `internal/regulation/regulator.go` | 26 |
| 锁查询 SQL | `internal/storage/sql_provider_queries_special.go` | 12 |
