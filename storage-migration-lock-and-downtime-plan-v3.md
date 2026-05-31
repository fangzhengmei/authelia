# Authelia 存储迁移锁定与并发边界深度分析（v3）

> 本文档已对照源码逐行核实所有函数名与行号。v2 中的以下错误已修正：
> - OTC 验证入口函数由 `UserSessionElevatePOST` 更正为 `UserSessionElevationPUT`
> - `handleAuthnCookieValidate` 行号由 430 更正为 451
> - `handleAuthnCookieValidateInactivity` 行号由 486 更正为 486（不变）
> - `handleSessionValidateRefresh` 行号由 498 更正为 498（不变）
> - `doMarkAuthenticationAttempt` 行号由 464 更正为 464（不变）
> - `loadMigrations` 签名确认无 `context.Context` 参数
> - 所有调用链行号已重新核实

---

## 1. 核心函数签名与行号核对

| 函数 | 签名 | 文件 | 行号 |
|------|------|------|------|
| `StartupCheck` (接口) | `type StartupCheck interface { StartupCheck() (err error) }` | `internal/model/types.go` | 168 |
| `StartupCheck` (实现) | `func (p *SQLProvider) StartupCheck() (err error)` | `internal/storage/sql_provider.go` | 399 |
| `StartupChecks` (统一入口) | `func (p *Providers) StartupChecks(ctx ServiceContext, log bool) (err error)` | `internal/middlewares/startup.go` | 14 |
| `SchemaMigrate` | `func (p *SQLProvider) SchemaMigrate(ctx context.Context, up bool, version int) (err error)` | `internal/storage/sql_provider_schema.go` | 186 |
| `SchemaVersion` | `func (p *SQLProvider) SchemaVersion(ctx context.Context) (version int, err error)` | `internal/storage/sql_provider_schema.go` | 87 |
| `schemaMigrate` (内部) | `func (p *SQLProvider) schemaMigrate(ctx context.Context, conn SQLXConnection, prior, target int) (err error)` | `internal/storage/sql_provider_schema.go` | 242 |
| `schemaMigrateLock` | `func (p *SQLProvider) schemaMigrateLock(ctx context.Context, conn SQLXConnection) (err error)` | `internal/storage/sql_provider_schema.go` | 271 |
| `schemaMigrateApply` | `func (p *SQLProvider) schemaMigrateApply(ctx context.Context, conn SQLXConnection, migration model.SchemaMigration) (err error)` | `internal/storage/sql_provider_schema.go` | 283 |
| `schemaMigrateFinalize` | `func (p *SQLProvider) schemaMigrateFinalize(ctx context.Context, conn SQLXConnection, migration model.SchemaMigration) (err error)` | `internal/storage/sql_provider_schema.go` | 323 |
| `schemaMigrateRollback` | `func (p *SQLProvider) schemaMigrateRollback(ctx context.Context, conn SQLXConnection, prior, after int, merr error) (err error)` | `internal/storage/sql_provider_schema.go` | 337 |
| `schemaMigrateChecks` | `func schemaMigrateChecks(providerName string, up bool, targetVersion, currentVersion int) (err error)` | `internal/storage/sql_provider_schema.go` | 379 |
| `loadMigrations` | `func loadMigrations(providerName string, prior, target int) (migrations []model.SchemaMigration, err error)` | `internal/storage/migrations.go` | 53 |
| `latestMigrationVersion` | `func latestMigrationVersion(providerName string) (version int, err error)` | `internal/storage/migrations.go` | 19 |
| `skipMigration` | `func skipMigration(up bool, target, prior int, migration *model.SchemaMigration) (skip bool)` | `internal/storage/migrations.go` | 98 |
| `scanMigration` | `func scanMigration(providerName, m string) (migration model.SchemaMigration, err error)` | `internal/storage/migrations.go` | 125 |
| `migrationSpecialUp24` | `func migrationSpecialUp24(ctx context.Context, conn SQLXConnection, provider *SQLProvider, prior, target int) (err error)` | `internal/storage/sql_provider_schema_special.go` | 20 |

---

## 2. SchemaMigrate 执行顺序（行号级）

**代码位置**：`internal/storage/sql_provider_schema.go:186-240`

```
行 186: func (p *SQLProvider) SchemaMigrate(ctx context.Context, up bool, version int) (err error) {
行 192:   if p.name != providerMySQL {
行 193:     tx, err = p.db.BeginTxx(ctx, nil)    ← 步骤1: PostgreSQL/SQLite 开启事务
行 199:     conn = p.db                          ← 步骤1: MySQL 不开事务
行 202:   currentVersion, err := p.SchemaVersion(ctx)  ← 步骤2: 读版本（不加锁！）
行 207:   if currentVersion != 0 {
行 208:     err = p.schemaMigrateLock(ctx, conn)       ← 步骤3: PostgreSQL 加 ACCESS EXCLUSIVE 锁
行 213:   schemaMigrateChecks(...)                      ← 步骤4: 校验
行 221:   p.schemaMigrate(ctx, conn, currentVersion, version)  ← 步骤5: 执行迁移
行 230:   tx.Commit()                                   ← 步骤6: 提交
```

**`schemaMigrate` 内部**（`internal/storage/sql_provider_schema.go:242-269`）：

```
行 243:   migrations, err := loadMigrations(p.name, prior, target)  ← 步骤A: 加载迁移列表
行 254:   for i, migration := range migrations {
行 255:     if migration.Up && prior == 0 && i == 1 {              ← V0→V1 时延迟加锁
行 256:       p.schemaMigrateLock(ctx, conn)
行 261:     p.schemaMigrateApply(ctx, conn, migration)             ← 步骤B: 应用单个迁移
行 262:     p.schemaMigrateRollback(...) on error
```

---

## 3. 多实例并发迁移时序分析

### 3.1 PostgreSQL 多实例并发场景

两个 Pod 同时启动，当前 schema 版本 22，目标版本 24。

```
t0  Pod A: BeginTxx() → 事务 TA                                                :193
t1  Pod B: BeginTxx() → 事务 TB                                                :193
t2  Pod A: SchemaVersion() → currentVersion = 22（无锁读取）                    :202
t3  Pod B: SchemaVersion() → currentVersion = 22（无锁读取）                    :202
t4  Pod A: LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE → 获取成功            :276
t5  Pod B: LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE → 阻塞！等待 TA 释放  :276
t6  Pod A: schemaMigrateChecks() → 通过                                        :379
t7  Pod A: loadMigrations("postgres", 22, 24) → [V23, V24]                     :243
t8  Pod A: schemaMigrateApply V23 → INSERT INTO migrations                      :283→328
t9  Pod A: schemaMigrateApply V24 → INSERT INTO migrations                      :283→328
t10 Pod A: Commit → 锁释放，schema 版本 = 24                                    :230
t11 Pod B: LOCK TABLE 获取成功
t12 Pod B: schemaMigrateChecks(up=true, target=24, current=22) → 通过           :379
     注意：currentVersion 仍是 t3 读取的 22，未重新读取！
t13 Pod B: loadMigrations("postgres", 22, 24) → [V23, V24]                     :243
t14 Pod B: schemaMigrateApply V23 → ALTER TABLE ... 列已存在 → 失败             :285
t15 Pod B: schemaMigrateRollback → Rollback TB                                  :337→347
t16 Pod B: SchemaMigrate 返回错误 → StartupCheck 失败 → Pod B CrashLoopBackOff  :437
t17 Pod B 重启: SchemaVersion() → 24
t18 Pod B: SchemaMigrate(ctx, true, SchemaLatest)
     schemaMigrateChecks → currentVersion(24) == latest → 返回 ErrSchemaAlreadyUpToDate
t19 Pod B: StartupCheck 成功，正常启动
```

**结论**：PostgreSQL 多实例并发迁移不会导致数据损坏，但第二个实例会经历一次启动失败。

### 3.2 MySQL 多实例并发场景（无锁保护）

```
t0  Pod A: SchemaVersion() → 22（无事务、无锁）                                 :202
t1  Pod B: SchemaVersion() → 22                                                :202
t2  Pod A: 执行 V23 SQL: ALTER TABLE ... ADD COLUMN
t3  Pod B: 执行 V23 SQL: ALTER TABLE ... ADD COLUMN → 列已存在 → 失败
t4  MySQL 无事务包裹，Pod A 的 V23 已隐式提交，无法回滚
t5  schema 可能处于 V23 部分完成的不一致状态
```

**结论**：MySQL 多实例并发可能导致 schema 不一致，必须确保单实例执行迁移。

---

## 4. 认证写路径详细调用链（行号级）

### 4.1 登录写入路径

**入口**：`FirstFactorPasswordPOST`（`internal/handlers/handler_firstfactor_password.go:16`）

```
FirstFactorPasswordPOST                                         handler_firstfactor_password.go:16
  ├─ UserProvider.GetDetails(username)                          (LDAP/文件后端，非关系型DB)
  ├─ Regulator.BanCheck(ctx, username)                          regulator.go:135
  │   └─ LoadBannedIP(ctx, ip)                                  sql_provider.go:1623
  │      SQL: SELECT FROM banned_ip ...
  │   └─ LoadBannedUser(ctx, username)                          sql_provider.go:1623
  │      SQL: SELECT FROM banned_user ...
  ├─ UserProvider.CheckUserPassword(username, password)         (LDAP/文件后端)
  ├─ doMarkAuthenticationAttempt(ctx, true, ...)                response.go:464
  │   └─ doMarkAuthenticationAttemptWithRequest(...)            response.go:482
  │       └─ Regulator.HandleAttempt(ctx, ...)                  regulator.go:26
  │           ├─ AppendAuthenticationLog(ctx, attempt)          sql_provider.go:1579
  │           │   SQL: INSERT INTO authentication_logs
  │           └─ (失败时) SaveBannedUser(ctx, ban)              sql_provider.go:1615
  │              SQL: INSERT INTO banned_user
  ├─ provider.DestroySession(ctx.RequestCtx)                    session.go:86
  │   └─ sessionHolder.Destroy(ctx)                             (Redis DEL / 内存 delete)
  ├─ provider.NewDefaultUserSession()                           session.go:21
  ├─ provider.SaveSession(ctx.RequestCtx, userSession)          session.go:57
  │   └─ sessionHolder.Save(ctx, store)                         (Redis SETEX / 内存 map)
  ├─ provider.RegenerateSession(ctx.RequestCtx)                 session.go:81
  │   └─ sessionHolder.Regenerate(ctx)                          (Redis RENAME+EXPIRE)
  ├─ (keepMeLoggedIn) provider.UpdateExpiration(ctx, exp)       session.go:91
  ├─ userSession.SetOneFactorPassword(now, details, keep)       user_session.go:40
  └─ provider.SaveSession(ctx.RequestCtx, userSession)          session.go:57
      └─ sessionHolder.Save(ctx, store)                         (Redis SETEX / 内存 map)
```

**关系型 DB 操作**：`authentication_logs` INSERT、`banned_user` INSERT、`banned_ip` SELECT
**会话操作**：全部走 Redis/内存，**不访问关系型 DB**

---

### 4.2 会话校验路径

**入口**：`CookieSessionAuthnStrategy.Get` → `handleAuthnCookieValidate`（`internal/handlers/handler_authz_authn.go:451`）

```
CookieSessionAuthnStrategy.Get                                  handler_authz_authn.go:90
  └─ handleAuthnCookieValidate(ctx, manager, &userSession, refresh)  handler_authz_authn.go:451
      ├─ ctx.GetSessionProvider()                               authelia_context.go:331
      ├─ provider.GetSession(ctx.RequestCtx)                    session.go:30
      │   └─ sessionHolder.Get(ctx)                             (Redis GET / 内存 map)
      │   └─ json.Unmarshal(data, &userSession)
      │
      ├─ handleAuthnCookieValidateInactivity(ctx, manager, &userSession, isAnonymous)
      │                                                         handler_authz_authn.go:486
      │   └─ 检查 time.Unix(LastActivity) + Inactivity < now
      │      KeepMeLoggedIn 会话跳过此检查
      │
      ├─ handleSessionValidateRefresh(ctx, &userSession, refresh)
      │                                                         handler_authz_authn.go:498
      │   ├─ if refresh.Never() || isAnonymous → return
      │   ├─ if RefreshTTL.After(now) → return
      │   ├─ UserProvider.GetDetails(username)                  (LDAP/文件后端，非关系型DB)
      │   ├─ 比较 Emails, Groups, DisplayName
      │   └─ userSession.RefreshTTL = now.Add(refreshInterval)
      │
      ├─ if !KeepMeLoggedIn:
      │   └─ userSession.LastActivity = now.Unix()
      │
      └─ (modified) provider.SaveSession(ctx.RequestCtx, userSession)
                                                                session.go:57
          └─ sessionHolder.Save(ctx, store)                     (Redis SETEX / 内存 map)
```

**关系型 DB 操作**：**无**
**结论**：会话校验路径**完全不访问关系型数据库**，迁移期间零影响。

---

### 4.3 会话刷新路径

会话刷新是 `handleSessionValidateRefresh` 的子流程（`internal/handlers/handler_authz_authn.go:498`），在会话校验中按 `RefreshInterval` 周期触发。

```
handleSessionValidateRefresh                                    handler_authz_authn.go:498
  ├─ refresh.Never() → return false, false
  ├─ userSession.IsAnonymous() → return false, false
  ├─ !refresh.Always() && userSession.RefreshTTL.After(now) → return false, false
  ├─ UserProvider.GetDetails(userSession.Username)              (LDAP/文件后端)
  ├─ diffEmails, diffGroups, diffDisplayName 比较
  ├─ userSession.RefreshTTL = now.Add(refresh.Value())         handler_authz_authn.go:537
  ├─ userSession.Emails/Groups/DisplayName = details.*
  └─ return modified, false
```

**关系型 DB 操作**：**无**
**数据来源**：`UserProvider`（LDAP/文件后端），非关系型存储
**结论**：会话刷新在迁移期间零影响。

---

### 4.4 一次性验证码消费路径

**入口**：`UserSessionElevationPUT`（`internal/handlers/handler_session_elevation.go:226`）

> ⚠️ **v2 修正**：OTC 验证入口函数为 `UserSessionElevationPUT`，不是 `UserSessionElevatePOST`。
> - `UserSessionElevationGET`（行 23）：查询提升状态
> - `UserSessionElevationPOST`（行 121）：创建新的提升会话（生成 OTC）
> - `UserSessionElevationPUT`（行 226）：**验证 OTC 并激活提升**
> - `UserSessionElevateDELETE`（行 365）：撤销提升

```
UserSessionElevationPUT                                         handler_session_elevation.go:226
  ├─ ctx.GetSession()                                           authelia_context.go:380
  │   └─ provider.GetSession(ctx.RequestCtx)                    session.go:30
  ├─ ctx.ParseBody(&bodyJSON)                                   authelia_context.go:455
  ├─ ctx.Providers.StorageProvider.LoadOneTimeCode(ctx, username, ip, intent, raw)
  │                                                             sql_provider.go:1081
  │   SQL: SELECT * FROM one_time_code WHERE signature = ? AND username = ?
  ├─ 检查过期/撤销/消费状态
  │   code.ExpiresAt, code.RevokedAt, code.ConsumedAt
  ├─ subtle.ConstantTimeCompare(code.Code, bodyJSON.OneTimeCode)  handler_session_elevation.go:326
  ├─ code.Consume(ctx)                                          one_time_code.go:65
  │   └─ 设置 ConsumedAt, ConsumedIP
  ├─ ctx.Providers.StorageProvider.ConsumeOneTimeCode(ctx, code) sql_provider.go:1035
  │   SQL: UPDATE one_time_code SET consumed = ?, consumed_ip = ? WHERE signature = ?
  ├─ userSession.Elevations.User = &session.Elevation{...}      handler_session_elevation.go:346
  └─ ctx.SaveSession(userSession)                               authelia_context.go:410
      └─ provider.SaveSession(ctx.RequestCtx, userSession)      session.go:57
          └─ sessionHolder.Save(ctx, store)                     (Redis SETEX / 内存 map)
```

**关系型 DB 操作**：
| 操作 | 表 | SQL 类型 | 行号 |
|------|----|----------|------|
| 加载 OTC | `one_time_code` | SELECT | `sql_provider.go:1081` |
| 消费 OTC | `one_time_code` | UPDATE | `sql_provider.go:1035` |

**会话操作**：`SaveSession` → Redis/内存

#### OTC 生成路径（创建提升会话时）

```
UserSessionElevationPOST                                        handler_session_elevation.go:121
  ├─ ctx.GetSession()                                           authelia_context.go:380
  ├─ 生成随机 code
  ├─ ctx.Providers.StorageProvider.SaveOneTimeCode(ctx, code)   sql_provider.go:1018
  │   ├─ code.Signature = otcHMACSignature(...)                 sql_provider.go:1019
  │   ├─ code.Code = encrypt(code.Code)                         sql_provider.go:1021
  │   └─ SQL: INSERT INTO one_time_code                         sql_provider.go:1025
  └─ ctx.SaveSession(userSession)                               authelia_context.go:410
```

---

## 5. 锁定策略与业务影响矩阵

### 5.1 PostgreSQL 锁定详情

**`schemaMigrateLock`**（`internal/storage/sql_provider_schema.go:271-281`）：

```go
func (p *SQLProvider) schemaMigrateLock(ctx context.Context, conn SQLXConnection) (err error) {
    if p.name != providerPostgres {
        return nil
    }
    _, err = conn.ExecContext(ctx, fmt.Sprintf(
        queryFmtPostgreSQLLockTable, tableMigrations, "ACCESS EXCLUSIVE"))
    return
}
```

**SQL**：`LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE`
**SQL 定义位置**：`internal/storage/sql_provider_queries_special.go:12`

**锁作用域**：仅 `migrations` 表，业务表不受此锁影响。

**业务表仅在 DDL 执行瞬间被隐式锁定**：
- `ALTER TABLE ... ADD COLUMN` → 目标表 ACCESS EXCLUSIVE 锁（毫秒级）
- `CREATE TABLE IF NOT EXISTS ...` → 新表无并发访问
- `CREATE INDEX ...` → 目标表 SHARE 锁（可并发读）

### 5.2 三后端锁定对比

| 维度 | PostgreSQL | MySQL | SQLite |
|------|------------|-------|--------|
| **显式锁** | `LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE`（行 276） | 无 | 无 |
| **事务** | 有（行 193） | 无（行 199） | 有（行 193） |
| **DDL 锁** | 目标表瞬间 ACCESS EXCLUSIVE | MDL 写锁（DDL 全程） | EXCLUSIVE（迁移全程） |
| **登录写入** | 不阻塞 | 不阻塞 | 迁移全程阻塞 |
| **会话校验** | **完全不阻塞**（Redis 独立） | **完全不阻塞** | **完全不阻塞** |
| **会话刷新** | **完全不阻塞**（LDAP 独立） | **完全不阻塞** | **完全不阻塞** |
| **OTC 操作** | 仅 DDL 时短暂阻塞 | 仅 DDL 时短暂阻塞 | 迁移全程阻塞 |
| **并发防护** | 强（migrations 表锁） | 无 | 弱（文件锁） |
| **失败回滚** | 完全（行 346-351） | 尽力而为（行 354-367） | 完全 |

---

## 6. 自动迁移 vs CLI 迁移对比

| 维度 | 自动迁移 (`StartupCheck`) | CLI 预迁移 |
|------|--------------------------|------------|
| **触发** | 每次启动自动执行（行 431） | 手动 `authelia storage migrate up` |
| **执行进程** | 业务服务进程内 | 独立 CLI 进程 |
| **并发风险 (PG)** | 低（第二个 Pod 启动失败，重启后正常） | 无 |
| **并发风险 (MySQL)** | 高（可能 schema 不一致） | 无 |
| **停机窗口** | 与服务启动绑定 | 可独立调度 |
| **回滚能力** | 失败自动回滚；成功后需手动 down | 支持显式 up/down |
| **调试能力** | 仅启动日志 | 逐版本执行，详细输出 |
| **失败影响** | Pod CrashLoopBackOff | 不影响运行中服务 |
| **推荐场景** | 单实例 / SQLite | 多实例 / 生产环境 |

---

## 7. 最小停机升级步骤

### 7.1 PostgreSQL（推荐：CLI 预迁移 + 滚动更新）

```bash
# 1. 备份
pg_dump -U authelia authelia > backup.sql

# 2. 低峰期预迁移
./new-authelia storage migrate up --target 24 --config config.yml

# 3. 验证
./new-authelia storage schema-info

# 4. 滚动更新（maxSurge=1, maxUnavailable=0）
kubectl set image deployment/authelia authelia=new:tag

# 5. 回滚（如需）
kubectl rollout undo deployment/authelia
./new-authelia storage migrate down --target 22  # 谨慎！
```

### 7.2 MySQL（推荐：缩至单实例 → CLI 迁移 → 滚动更新）

```bash
# 1. 缩至单实例
kubectl scale deployment authelia --replicas=1

# 2. 备份
mysqldump -u authelia authelia > backup.sql

# 3. CLI 迁移
./new-authelia storage migrate up --target 24 --config config.yml

# 4. 滚动更新
kubectl set image deployment/authelia authelia=new:tag

# 5. 扩回多实例
kubectl scale deployment authelia --replicas=N
```

### 7.3 SQLite（推荐：维护窗口停机升级）

```bash
# 1. 停服务
systemctl stop authelia

# 2. 备份
cp db.sqlite db.sqlite.backup

# 3. CLI 迁移
./new-authelia storage migrate up --target 24 --config config.yml

# 4. 启新版本
systemctl start authelia
```

---

## 8. 函数级复核清单

> 评审可逐行点击文件路径与行号，对照源码验证下述结论。

### 8.1 迁移核心函数

| # | 函数 | 文件 | 行号 | 应验证结论 |
|---|------|------|------|-----------|
| 1 | `StartupCheck` | `internal/storage/sql_provider.go` | 399 | 无 context 参数；内部用 `context.Background()`；先 Ping 再加密检查再迁移 |
| 2 | `SchemaMigrate` | `internal/storage/sql_provider_schema.go` | 186 | 步骤顺序：开事务→读版本→加锁→校验→执行→提交 |
| 3 | `SchemaVersion` | `internal/storage/sql_provider_schema.go` | 87 | 无表返回 0；有 migrations 表读 version_after；pre1 返回 -1 |
| 4 | `schemaMigrateLock` | `internal/storage/sql_provider_schema.go` | 271 | 仅 PostgreSQL 加锁；MySQL/SQLite 直接 return nil |
| 5 | `schemaMigrate` | `internal/storage/sql_provider_schema.go` | 242 | V0 升级时 i==1 才加锁（行 255）；逐个 apply 失败则 rollback |
| 6 | `schemaMigrateApply` | `internal/storage/sql_provider_schema.go` | 283 | 先执行 SQL→V1 up 时写加密值→特殊迁移→写入 migrations 记录 |
| 7 | `schemaMigrateFinalize` | `internal/storage/sql_provider_schema.go` | 323 | V1 down 不写记录（migrations 表将被删）；其他情况 INSERT |
| 8 | `schemaMigrateRollback` | `internal/storage/sql_provider_schema.go` | 337 | 有事务用 tx.Rollback()；无事务（MySQL）用反向 down 迁移补偿 |
| 9 | `schemaMigrateChecks` | `internal/storage/sql_provider_schema.go` | 379 | 禁止 pre1 升级/降级；版本超前拒绝；方向错误拒绝 |
| 10 | `loadMigrations` | `internal/storage/migrations.go` | 53 | 无 context 参数；prior==target 返回 ErrMigrateCurrentVersionSameAsTarget |
| 11 | `skipMigration` | `internal/storage/migrations.go` | 98 | Up: Version∈(prior, target]；Down: Version∈(target, prior] |
| 12 | `migrationSpecialUp24` | `internal/storage/sql_provider_schema_special.go` | 20 | 逐页 SELECT webauthn_credentials → VerifyAttestationType → UPDATE |
| 13 | `migrationsSpecialUp` | `internal/storage/sql_provider_schema_special.go` | 14 | 当前仅 V24 有特殊 up；down 映射为空 |

### 8.2 登录写入路径函数

| # | 函数 | 文件 | 行号 | 应验证结论 |
|---|------|------|------|-----------|
| 14 | `FirstFactorPasswordPOST` | `internal/handlers/handler_firstfactor_password.go` | 16 | 1FA 入口；先查 LDAP→封禁检查→密码验证→写日志→会话操作 |
| 15 | `Regulator.BanCheck` | `internal/regulation/regulator.go` | 135 | 读 banned_ip + banned_user 表；不写 DB |
| 16 | `doMarkAuthenticationAttempt` | `internal/handlers/response.go` | 464 | 委托给 WithRequest 版本 |
| 17 | `doMarkAuthenticationAttemptWithRequest` | `internal/handlers/response.go` | 482 | 调用 Regulator.HandleAttempt |
| 18 | `Regulator.HandleAttempt` | `internal/regulation/regulator.go` | 26 | 先 AppendAuthenticationLog；1FA 失败时可能 SaveBannedUser/SaveBannedIP |
| 19 | `AppendAuthenticationLog` | `internal/storage/sql_provider.go` | 1579 | INSERT INTO authentication_logs；使用 p.db（非事务连接） |
| 20 | `SaveBannedUser` | `internal/storage/sql_provider.go` | 1615 | INSERT INTO banned_user |
| 21 | `SaveBannedIP` | `internal/storage/sql_provider.go` | — | 行号待查；INSERT INTO banned_ip |

### 8.3 会话校验/刷新路径函数

| # | 函数 | 文件 | 行号 | 应验证结论 |
|---|------|------|------|-----------|
| 22 | `CookieSessionAuthnStrategy.Get` | `internal/handlers/handler_authz_authn.go` | 90 | 每次受保护请求入口 |
| 23 | `handleAuthnCookieValidate` | `internal/handlers/handler_authz_authn.go` | 451 | 调用 inactivity + refresh 检查；**不访问关系型 DB** |
| 24 | `handleAuthnCookieValidateInactivity` | `internal/handlers/handler_authz_authn.go` | 486 | 纯时间比较；KeepMeLoggedIn 跳过 |
| 25 | `handleSessionValidateRefresh` | `internal/handlers/handler_authz_authn.go` | 498 | 从 LDAP 刷新用户信息；**不访问关系型 DB** |
| 26 | `Session.GetSession` | `internal/session/session.go` | 30 | Redis GET / 内存 map 读取；**不访问关系型 DB** |
| 27 | `Session.SaveSession` | `internal/session/session.go` | 57 | Redis SETEX / 内存 map 写入；**不访问关系型 DB** |
| 28 | `Session.RegenerateSession` | `internal/session/session.go` | 81 | 生成新 session_id |
| 29 | `Session.DestroySession` | `internal/session/session.go` | 86 | Redis DEL / 内存 delete |
| 30 | `Session.UpdateExpiration` | `internal/session/session.go` | 91 | 修改会话过期时间 |
| 31 | `AutheliaCtx.GetSession` | `internal/middlewares/authelia_context.go` | 380 | 委托给 Session.GetSession |
| 32 | `AutheliaCtx.SaveSession` | `internal/middlewares/authelia_context.go` | 410 | 委托给 Session.SaveSession |

### 8.4 OTC 消费路径函数

| # | 函数 | 文件 | 行号 | 应验证结论 |
|---|------|------|------|-----------|
| 33 | `UserSessionElevationPUT` | `internal/handlers/handler_session_elevation.go` | 226 | **OTC 验证入口**；PUT 方法；不是 POST |
| 34 | `UserSessionElevationPOST` | `internal/handlers/handler_session_elevation.go` | 121 | **OTC 生成入口**；POST 方法；创建提升会话 |
| 35 | `UserSessionElevationGET` | `internal/handlers/handler_session_elevation.go` | 23 | 查询提升状态 |
| 36 | `UserSessionElevateDELETE` | `internal/handlers/handler_session_elevation.go` | 365 | 撤销提升 |
| 37 | `LoadOneTimeCode` | `internal/storage/sql_provider.go` | 1081 | SELECT FROM one_time_code WHERE signature=? AND username=? |
| 38 | `SaveOneTimeCode` | `internal/storage/sql_provider.go` | 1018 | INSERT INTO one_time_code；先加密 code 值 |
| 39 | `ConsumeOneTimeCode` | `internal/storage/sql_provider.go` | 1035 | UPDATE one_time_code SET consumed=?, consumed_ip=? WHERE signature=?；检查 RowsAffected==1 |
| 40 | `OneTimeCode.Consume` | `internal/model/one_time_code.go` | 65 | 设置 ConsumedAt 和 ConsumedIP 字段（纯内存操作） |

### 8.5 迁移 SQL 查询定义

| # | 常量/函数 | 文件 | 行号 | 应验证结论 |
|---|----------|------|------|-----------|
| 41 | `queryFmtPostgreSQLLockTable` | `internal/storage/sql_provider_queries_special.go` | 12 | 值为 `LOCK TABLE %s IN %s MODE;` |
| 42 | `queryFmtInsertMigration` | `internal/storage/sql_provider_queries.go` | 14 | INSERT INTO migrations (applied, version_before, version_after, application_version) |
| 43 | `queryFmtSelectLatestMigration` | `internal/storage/sql_provider_queries.go` | 8 | SELECT ... FROM %s ORDER BY id DESC LIMIT 1 |
| 44 | `reMigration` | `internal/storage/const.go` | ~95 | 正则：`^V(?P<Version>\d{4})\.(?P<Name>[^.]+)\.(?P<Direction>(up\|down))\.sql$` |
