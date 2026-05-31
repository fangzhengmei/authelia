# Authelia 存储迁移锁定与并发边界深度分析

## 1. PostgreSQL ACCESS EXCLUSIVE 锁的影响范围分析

### 1.1 锁的获取时机与作用域

**锁获取代码位置**：`internal/storage/sql_provider_schema.go:271-281`

```go
func (p *SQLProvider) schemaMigrateLock(ctx context.Context, conn SQLXConnection) (err error) {
    if p.name != providerPostgres {
        return nil  // 仅 PostgreSQL 加锁
    }
    if _, err = conn.ExecContext(ctx, fmt.Sprintf(queryFmtPostgreSQLLockTable, tableMigrations, "ACCESS EXCLUSIVE")); err != nil {
        return fmt.Errorf("failed to lock tables: %w", err)
    }
    return nil
}
```

**锁的 SQL**：`LOCK TABLE migrations IN ACCESS EXCLUSIVE MODE;`

**关键事实**：Authelia 只对 `migrations` 表加 ACCESS EXCLUSIVE 锁，**不会直接锁定其他业务表**。

---

### 1.2 认证写路径的阻塞行为分析

#### 路径 1：登录认证日志写入 (`AppendAuthenticationLog`)

**涉及表**：`authentication_logs`

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

**阻塞行为**：

| 场景 | 行为 | 原因 |
|------|------|------|
| 迁移期间写入 `authentication_logs` | **正常执行，不阻塞** | 只锁定了 `migrations` 表，`authentication_logs` 表未被锁定 |
| 迁移期间执行 `ALTER TABLE authentication_logs` | **短暂阻塞** | DDL 语句会自动获取目标表的 ACCESS EXCLUSIVE 锁，但该锁只在 DDL 执行期间持有 |
| 迁移事务持有锁期间 | **不阻塞** | ACCESS EXCLUSIVE 锁只作用于 `migrations` 表 |

**结论**：登录日志写入在**绝大多数时间**不受迁移影响，仅当迁移脚本恰好执行 `authentication_logs` 表的 DDL 时短暂阻塞。

---

#### 路径 2：TOTP 配置保存与更新

**涉及表**：`totp_configurations`

**代码位置**：`internal/storage/sql_provider.go:589-611`

```go
func (p *SQLProvider) SaveTOTPConfiguration(ctx context.Context, config model.TOTPConfiguration) (err error) {
    if config.Secret, err = p.encrypt(config.Secret); err != nil {
        return fmt.Errorf("error encrypting TOTP configuration secret for user '%s': %w", config.Username, err)
    }
    if _, err = p.db.ExecContext(ctx, p.sqlUpsertTOTPConfig, ...); err != nil {
        return fmt.Errorf("error upserting TOTP configuration for user '%s': %w", config.Username, err)
    }
    return nil
}
```

**阻塞行为**：

| 场景 | 行为 |
|------|------|
| 常规迁移期间（无 `totp_configurations` 表变更） | **完全不阻塞** |
| 迁移包含 `totp_configurations` 表 DDL 时 | **仅 DDL 执行期间阻塞** |
| 迁移事务持有锁期间 | **正常执行** |

**特殊情况 - 版本 1 迁移**：V1 迁移是初始化整个 schema，会创建 `totp_configurations` 表。此时：
- 创建表的 `CREATE TABLE` 语句会获取该表的 ACCESS EXCLUSIVE 锁
- 但由于是新创建的表，实际上没有并发访问问题

---

#### 路径 3：一次性验证码写入 (`SaveOneTimeCode`)

**涉及表**：`one_time_code`

**代码位置**：`internal/storage/sql_provider.go:1018-1031`

```go
func (p *SQLProvider) SaveOneTimeCode(ctx context.Context, code model.OneTimeCode) (signature string, err error) {
    code.Signature = p.otcHMACSignature([]byte(code.Username), code.IssuedIP.IP, []byte(code.Intent), code.Code)
    if code.Code, err = p.encrypt(code.Code); err != nil {
        return "", fmt.Errorf("error encrypting the one-time code value for user '%s' with signature '%s': %w", code.Username, code.Signature, err)
    }
    if _, err = p.db.ExecContext(ctx, p.sqlInsertOneTimeCode, ...); err != nil {
        return "", fmt.Errorf("error inserting one-time code for user '%s' with signature '%s': %w", code.Username, code.Signature, err)
    }
    return code.Signature, nil
}
```

**阻塞行为**：

| 场景 | 行为 | 影响 |
|------|------|------|
| 无 OTC 表 DDL 的迁移 | **不阻塞** | 密码重置、邮箱验证等流程完全正常 |
| 有 OTC 表 DDL 的迁移 | **DDL 执行期间阻塞 INSERT** | 验证码写入会等待 DDL 完成，超时则失败 |

---

#### 路径 4：身份验证记录保存 (`SaveIdentityVerification`)

**涉及表**：`identity_verification`

**代码位置**：`internal/storage/sql_provider.go:953-961`

```go
func (p *SQLProvider) SaveIdentityVerification(ctx context.Context, verification model.IdentityVerification) (err error) {
    if _, err = p.db.ExecContext(ctx, p.sqlInsertIdentityVerification,
        verification.JTI, verification.IssuedAt, verification.IssuedIP, verification.ExpiresAt,
        verification.Username, verification.Action); err != nil {
        return fmt.Errorf("error inserting identity verification for user '%s' with uuid '%s': %w", verification.Username, verification.JTI, err)
    }
    return nil
}
```

**阻塞行为**：与 OTC 表完全相同。

---

#### 路径 5：WebAuthn 凭证保存 (`SaveWebAuthnCredential`)

**涉及表**：`webauthn_credentials`

**代码位置**：`internal/storage/sql_provider.go:728-740`

```go
func (p *SQLProvider) SaveWebAuthnCredential(ctx context.Context, credential model.WebAuthnCredential) (err error) {
    if credential.PublicKey, err = p.encrypt(credential.PublicKey); err != nil {
        return fmt.Errorf("error encrypting WebAuthn credential public key for user '%s': %w", credential.Username, err)
    }
    if _, err = p.db.ExecContext(ctx, p.sqlInsertWebAuthnCredential, ...); err != nil {
        return fmt.Errorf("error inserting WebAuthn credential for user '%s': %w", credential.Username, err)
    }
    return nil
}
```

**特殊情况 - 版本 24 迁移**：

V0024.WebAuthnAttestationType 迁移包含：
1. SQL DDL：`ALTER TABLE webauthn_credentials RENAME COLUMN attestation_type TO attestation_format; ALTER TABLE webauthn_credentials ADD COLUMN attestation_type VARCHAR(32) NOT NULL DEFAULT '';`
2. 特殊 Go 迁移：逐页加载所有 WebAuthn 凭证，调用 `credential.VerifyAttestationType()` 后更新

**阻塞行为分析**：

```
阶段 1: ALTER TABLE (重命名 + 新增列)
  └─ 获取 webauthn_credentials 表的 ACCESS EXCLUSIVE 锁
  └─ 阻塞所有读写该表的操作
  └─ 持续时间: 毫秒级（仅元数据变更）

阶段 2: 特殊迁移 - 逐页 SELECT + UPDATE
  └─ 读取: 共享锁，不阻塞读
  └─ 写入: 行级锁，不影响其他行
  └─ 持续时间: 取决于凭证数量（可能很长）
```

**关键结论**：WebAuthn 凭证注册在 DDL 阶段短暂阻塞，但在特殊迁移的数据处理阶段**可以正常写入**。

---

#### 路径 6：OAuth2 会话写入

**涉及表**：`oauth2_access_token_session`, `oauth2_refresh_token_session`, `oauth2_consent_session` 等

**阻塞行为**：与其他业务表一致，仅当迁移包含对应表的 DDL 时短暂阻塞。

---

### 1.3 PostgreSQL 锁机制总结

| 锁类型 | 作用域 | 获取时机 | 释放时机 | 影响 |
|--------|--------|----------|----------|------|
| ACCESS EXCLUSIVE (显式) | `migrations` 表 | 迁移开始前（非 V0 升级）或 V1 迁移后 | 事务提交/回滚 | 阻止其他迁移执行，但不影响业务表 |
| ACCESS EXCLUSIVE (隐式) | 各业务表 | DDL 语句执行时 | DDL 语句完成 | 短暂阻塞该表的所有操作 |
| 行级锁 | 数据行 | UPDATE/DELETE 执行时 | 语句完成 | 不影响并发 |

**最重要的认知**：Authelia 的迁移锁策略是**细粒度的**，不是"迁移期间整个库不可用"。`migrations` 表的锁只用于防止并发迁移，业务表只有在执行 DDL 的瞬间被锁定。

---

## 2. MySQL 与 SQLite 锁定对比分析

### 2.1 MySQL 锁定行为

**核心差异**：MySQL 不使用显式锁，也**不使用事务包裹迁移**（`sql_provider_schema.go:192-200`）。

```go
if p.name != providerMySQL {
    if tx, err = p.db.BeginTxx(ctx, nil); err != nil {  // PostgreSQL/SQLite 开启事务
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    conn = tx
} else {
    conn = p.db  // MySQL 直接使用 db 连接，不开启事务
}
```

#### MySQL DDL 的隐式提交与锁定

MySQL 的 DDL 语句（`ALTER TABLE`、`CREATE TABLE` 等）会：
1. **隐式提交**当前事务（这就是为什么不用事务包裹）
2. 获取表级锁（MDL 锁 - Metadata Lock）
3. 执行 DDL
4. 释放锁

**阻塞行为**：

| 操作 | 锁定方式 | 影响范围 | 持续时间 |
|------|----------|----------|----------|
| CREATE TABLE | 表级 MDL 写锁 | 仅新表 | 极短 |
| ALTER TABLE (添加列) | 表级 MDL 写锁 | 整个表 | 取决于表大小（可能很长！） |
| CREATE INDEX | 表级 MDL 写锁 | 整个表 | 取决于表大小 |

**MySQL 最大风险**：`ALTER TABLE` 在 MySQL 5.6 之前是阻塞的，即使是 Online DDL 也需要短暂的 MDL 锁获取。如果表很大（如 `authentication_logs`），ALTER TABLE 可能需要**几分钟甚至几小时**，期间该表完全不可用。

#### MySQL 并发迁移风险

由于没有 `LOCK TABLE migrations`，多个 Authelia 实例**可能同时执行迁移**：

```
实例 A: SELECT version_before -> 22
实例 B: SELECT version_before -> 22
实例 A: 执行 V23 迁移 SQL
实例 B: 执行 V23 迁移 SQL  ← 重复执行！
```

**结果**：
- `CREATE TABLE IF NOT EXISTS` - 安全
- `ALTER TABLE ADD COLUMN` - 第二次执行报错（列已存在）
- 迁移失败，服务启动失败

---

### 2.2 SQLite 锁定行为

**核心特性**：SQLite 使用文件级锁，支持事务性 DDL。

#### SQLite 的锁定机制

```go
if p.name != providerMySQL {
    if tx, err = p.db.BeginTxx(ctx, nil); err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    conn = tx  // SQLite 使用事务
}
```

**SQLite 锁定级别**（从低到高）：
1. `SHARED` - 读锁，多个连接可同时持有
2. `RESERVED` - 预备写锁
3. `PENDING` - 等待写锁
4. `EXCLUSIVE` - 写锁，独占数据库

**迁移期间的锁定行为**：

```
阶段 1: BEGIN TRANSACTION
  └─ 获取 SHARED 锁

阶段 2: 执行 DDL (CREATE TABLE / ALTER TABLE)
  └─ 升级到 EXCLUSIVE 锁
  └─ 阻塞所有其他连接的读写操作
  └─ 持续到事务结束

阶段 3: COMMIT
  └─ 释放所有锁
```

**关键结论**：SQLite 在迁移期间**整个数据库文件被独占锁定**，所有其他连接的读写操作都会阻塞或失败（取决于超时设置）。这是最激进的锁定策略。

---

### 2.3 三种后端锁定对比矩阵

| 维度 | PostgreSQL | MySQL | SQLite |
|------|------------|-------|--------|
| **显式迁移锁** | ACCESS EXCLUSIVE on `migrations` | 无 | 无（但事务隐式锁定） |
| **事务包裹迁移** | 是 | 否 | 是 |
| **DDL 原子性** | 事务内原子，可回滚 | 每条 DDL 隐式提交，不可回滚 | 事务内原子，可回滚 |
| **业务表锁定** | 仅 DDL 执行瞬间 | DDL 执行期间（可能很长） | 整个迁移期间 |
| **并发迁移防护** | 强（migrations 表锁） | 无 | 弱（文件锁竞争） |
| **停机窗口** | 最小（各 DDL 时间之和） | 中等（大表 ALTER 很慢） | 最大（整个迁移期间） |
| **失败回滚能力** | 完全 | 尽力而为（可能残留） | 完全 |

---

## 3. 自动迁移 vs CLI 迁移详细对比

### 3.1 自动迁移（StartupCheck）

**触发时机**：每次 Authelia 服务启动时，在 `StartupCheck()` 中自动执行。

**代码位置**：`internal/storage/sql_provider.go:399-449`

```go
func (p *SQLProvider) StartupCheck(ctx context.Context, config *schema.Configuration) (err error) {
    // ... 加密密钥检查 ...
    
    switch err = p.SchemaMigrate(ctx, true, SchemaLatest); err {
    case nil:
        break
    case ErrSchemaAlreadyUpToDate:
        p.log.Infof("Storage schema is already up to date")
    default:
        return fmt.Errorf("error during schema migrate: %w", err)
    }
    
    return nil
}
```

#### 停机窗口分析

**场景**：滚动更新部署，新版本 Pod 启动时自动执行迁移。

```
旧版本 Pod 1: 正常运行
旧版本 Pod 2: 正常运行
新版本 Pod 1: 启动 → StartupCheck → 开始迁移
  └─ 迁移期间：
     ├─ PostgreSQL: 短暂 DDL 锁
     ├─ MySQL: 可能长时间锁大表
     └─ SQLite: 整个库锁定
  └─ 迁移完成
新版本 Pod 1: 就绪 → 接收流量
旧版本 Pod 1: 终止
... 滚动继续 ...
```

**停机时间**：
- **PostgreSQL**：约等于各 DDL 语句执行时间之和（通常 < 1秒）
- **MySQL**：可能很长，取决于是否有大表变更
- **SQLite**：整个迁移执行时间

#### 回滚可恢复性

| 后端 | 迁移中失败 | 迁移后发现问题 |
|------|------------|----------------|
| PostgreSQL | 自动回滚事务，schema 回到迁移前状态 | 手动执行 down 迁移，再回滚应用 |
| MySQL | 部分执行，schema 处于中间状态，需手动修复 | 手动执行 down 迁移 + 手动补偿 |
| SQLite | 自动回滚事务 | 手动执行 down 迁移 |

#### 并发多实例风险

```
多个新版本 Pod 同时启动：
Pod A: SchemaVersion() -> 22
Pod B: SchemaVersion() -> 22
Pod A: 开始迁移 V23
Pod B: 开始迁移 V23  ← 竞态！
```

**PostgreSQL**：Pod B 的 `LOCK TABLE migrations` 会阻塞，直到 Pod A 提交事务。然后 Pod B 重新读取版本号，发现已是 23，跳过迁移。**安全**。

**MySQL**：两个 Pod 都执行相同的 DDL。`CREATE TABLE IF NOT EXISTS` 安全，但 `ALTER TABLE` 第二次执行会报错。**可能失败**。

**SQLite**：文件锁序列化执行，实际上是安全的，但第二个会超时或等待。**基本安全但性能差**。

---

### 3.2 CLI 迁移

**执行方式**：使用 `authelia storage migrate up` 命令手动执行。

**代码入口**：`internal/commands/storage.go` → `newStorageMigrateCmd()`

#### 停机窗口分析

**场景**：CLI 预迁移，再滚动更新。

```
阶段 1: 所有旧版本 Pod 正常运行
阶段 2: 执行 CLI 迁移
  authelia storage migrate up --target 24
  └─ 迁移期间业务照常（除了短暂的 DDL 锁）
阶段 3: 验证迁移结果
  authelia storage schema-info
阶段 4: 滚动更新应用到新版本
  └─ 新版本 StartupCheck 发现已是最新版本，直接启动
```

**关键优势**：
1. 迁移与应用部署解耦
2. 可以在业务低峰期执行迁移
3. 迁移失败不影响正在运行的服务
4. 可以先在预发环境验证迁移

#### 回滚可恢复性

**CLI 迁移支持明确的回滚操作**：

```bash
# 回滚到指定版本（需输入 DESTROY 确认）
authelia storage migrate down --target 22
```

**迁移前回滚**：CLI 执行失败 → 事务自动回滚（PostgreSQL/SQLite）
**迁移后回滚**：发现问题 → 执行 `migrate down` → 再决定是否回滚应用

#### 并发风险

CLI 迁移是**单进程执行**，不存在多实例并发问题。

---

### 3.3 两种迁移方式对比矩阵

| 维度 | 自动迁移 (StartupCheck) | CLI 预迁移 |
|------|-------------------------|------------|
| **停机窗口** | 与应用启动绑定 | 可独立调度，与部署解耦 |
| **可控性** | 自动执行，不可干预 | 完全可控，可先验证再部署 |
| **回滚灵活性** | 失败自动回滚，成功后需手动 down | 支持显式 up/down，可逐版本验证 |
| **并发风险** | PostgreSQL 安全，MySQL 有风险 | 无并发风险 |
| **运维复杂度** | 低（全自动） | 中（需额外步骤） |
| **失败影响** | 服务启动失败 | 不影响运行中的服务 |
| **调试能力** | 只有启动日志 | 可逐版本执行，详细输出 |
| **大表迁移** | 可能阻塞滚动更新 | 可在低峰期单独执行 |

---

## 4. 最小停机升级可执行步骤

### 4.1 升级前检查清单

#### 步骤 0：环境与版本确认

```bash
# 1. 确认当前 Authelia 版本
authelia --version

# 2. 确认当前数据库 schema 版本
authelia storage schema-info

# 3. 确认目标版本支持的最大 schema 版本
#    - 查看新版本二进制: authelia storage schema-info
#    - 或查看代码: internal/storage/const.go 中的迁移数量

# 4. 备份数据库（CRITICAL!）
# PostgreSQL:
pg_dump -U authelia -W authelia > authelia_backup_$(date +%Y%m%d).sql

# MySQL:
mysqldump -u authelia -p authelia > authelia_backup_$(date +%Y%m%d).sql

# SQLite:
cp /path/to/db.sqlite /path/to/db.sqlite.backup.$(date +%Y%m%d)
```

#### 步骤 0.5：分析迁移影响

查看目标版本之间的迁移脚本，识别高风险操作：

```bash
# 列出所有待执行的迁移
# - 查看 migrations/{provider}/ 目录
# - 特别关注:
#   - ALTER TABLE on 大表 (authentication_logs, oauth2_*_session)
#   - 需要全表扫描的特殊迁移 (如 V24)
#   - CREATE INDEX on 大表
```

**高风险迁移识别标志**：
- `ALTER TABLE ... ALTER COLUMN` - 可能需要重写表
- `ALTER TABLE ... ADD COLUMN ... NOT NULL DEFAULT` - PostgreSQL 11+ 快，旧版慢
- `CREATE INDEX CONCURRENTLY` - PostgreSQL 专用，不锁表但慢
- 有 `migrationsSpecialUp` 注册的版本（当前只有 V24）

---

### 4.2 PostgreSQL 后端最小停机升级流程

**推荐方式**：CLI 预迁移 + 滚动更新

#### 阶段 1：预迁移（业务低峰期）

```bash
# 1. 使用新版本二进制执行迁移
#    注意: 使用新版本的 authelia 可执行文件！
./new-authelia storage migrate up --target N --config /path/to/config.yml

# 2. 验证迁移结果
./new-authelia storage schema-info
# 应输出: Schema version: N (Latest: N)

# 3. 查看迁移历史
./new-authelia storage migrate history
```

**预期影响**：
- 各 DDL 执行期间短暂阻塞对应表（毫秒级）
- 特殊迁移（如 V24）数据处理期间不阻塞写入
- 总体业务几乎无感知

#### 阶段 2：滚动更新应用

```bash
# Kubernetes 示例:
kubectl set image deployment/authelia authelia=new-version:tag

# 或者使用 Helm:
helm upgrade authelia authelia/authelia --version x.y.z

# 验证:
kubectl rollout status deployment/authelia
```

**关键**：新版本 Pod 启动时，`StartupCheck` 会发现 schema 已是最新版本，直接启动服务。

#### 阶段 3：验证与监控

```bash
# 1. 检查日志中无迁移错误
kubectl logs -l app=authelia | grep -i "migration\|schema"

# 2. 验证认证流程正常
#    - 测试用户名密码登录
#    - 测试 TOTP
#    - 测试 WebAuthn
#    - 测试 OAuth2/OpenID Connect

# 3. 监控数据库连接和锁
# PostgreSQL:
psql -c "SELECT * FROM pg_locks WHERE mode = 'AccessExclusiveLock';"
```

#### 回滚流程（如发现问题）

```bash
# 1. 先回滚应用到旧版本
kubectl rollout undo deployment/authelia

# 2. 确认旧版本正常运行后，再考虑 schema 回滚
#    注意: schema 回滚可能导致数据丢失！
#    只有在 schema 不兼容导致旧版本无法运行时才需要

# 3. 如需回滚 schema（谨慎!）:
./new-authelia storage migrate down --target N-1
# 需输入 "DESTROY" 确认
```

---

### 4.3 MySQL 后端最小停机升级流程

**特殊注意**：MySQL 无事务包裹，大表 ALTER TABLE 可能造成长时间停机。

#### 阶段 1：预迁移准备

```bash
# 1. 特别检查是否有大表变更
#    查看 migrations/mysql/V*.up.sql 中的 ALTER TABLE

# 2. 估算 ALTER TABLE 时间（可选，在备库测试）
#    在测试环境执行:
SET profiling = 1;
ALTER TABLE big_table ADD COLUMN ...;
SHOW PROFILES;

# 3. 调整业务（如需要）
#    - 如预期停机 > 30 秒，建议公告维护窗口
#    - 或考虑使用 pt-online-schema-change 等外部工具先执行变更
```

#### 阶段 2：低峰期 CLI 迁移

```bash
# 1. 执行迁移
./new-authelia storage migrate up --target N --config /path/to/config.yml

# 2. 持续监控
# MySQL:
SHOW PROCESSLIST;
SHOW OPEN TABLES WHERE In_use > 0;
```

**如果遇到长时间锁等待**：
- 评估是继续等待还是中断
- 中断后可能需要手动清理部分执行的迁移

#### 阶段 3 & 4：同 PostgreSQL

---

### 4.4 SQLite 后端最小停机升级流程

**特性**：SQLite 迁移期间整个数据库锁定，停机时间 = 迁移执行时间。

#### 方案 A：维护窗口停机升级（推荐，因为 SQLite 通常单实例）

```bash
# 1. 停止 Authelia 服务
systemctl stop authelia
# 或
kubectl scale deployment authelia --replicas=0

# 2. 备份数据库
cp /path/to/db.sqlite /path/to/db.sqlite.backup.pre_upgrade

# 3. 执行迁移
./new-authelia storage migrate up --target N --config /path/to/config.yml

# 4. 更新应用二进制/镜像
# ...

# 5. 启动服务
systemctl start authelia
# 或
kubectl scale deployment authelia --replicas=N
```

**总停机时间**：迁移执行时间 + 应用重启时间（通常几秒到几十秒）

#### 方案 B：如果必须最小化停机

SQLite 不支持真正的零停机迁移，但可以这样优化：

```bash
# 1. 准备新版本代码和配置
# 2. 执行迁移（会有短暂写入阻塞）
./new-authelia storage migrate up --target N --config /path/to/config.yml
# 3. 立即热重启/快速切换到新版本
```

---

### 4.5 多实例部署特殊注意事项

#### 并发迁移防护

**PostgreSQL**：自动防护（`migrations` 表锁），无需额外操作。

**MySQL**：必须确保只有一个实例执行迁移。

```bash
# 安全的多实例 MySQL 升级步骤:
# 1. 将所有实例设置为 maintenance 模式（如果支持）
# 2. 或只启动一个新版本实例执行迁移
# 3. 迁移完成后再启动其他实例

# Kubernetes 可通过 initContainer 实现:
initContainers:
- name: migrate
  image: new-authelia:tag
  command: ["authelia", "storage", "migrate", "up"]
  args: ["--target", "N"]
  # 使用 readOnlyRootFilesystem + 合适的 securityContext
```

**SQLite**：不建议多实例部署（文件锁争用严重）。如果必须多实例，使用 `?_busy_timeout=30000` 延长锁等待超时。

---

### 4.6 验证脚本（升级后执行）

```bash
#!/bin/bash
# upgrade-validation.sh

echo "=== Schema Version Check ==="
authelia storage schema-info

echo ""
echo "=== Migration History ==="
authelia storage migrate history | head -20

echo ""
echo "=== Basic Authentication Test ==="
# 使用 API 或 UI 自动化测试...

echo ""
echo "=== Database Health Check ==="
# PostgreSQL:
# psql -c "SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"

# MySQL:
# mysql -e "SHOW TABLE STATUS;"

echo ""
echo "=== Error Log Check ==="
# journalctl -u authelia --since "10 minutes ago" | grep -i error
# kubectl logs -l app=authelia --tail=100 | grep -i error

echo ""
echo "=== Upgrade Validation Complete ==="
```

---

## 5. 关键代码路径索引

| 功能 | 文件 | 行号 |
|------|------|------|
| PostgreSQL 锁获取 | `internal/storage/sql_provider_schema.go` | 271-281 |
| 迁移事务开始逻辑 | `internal/storage/sql_provider_schema.go` | 186-200 |
| 自动迁移 StartupCheck | `internal/storage/sql_provider.go` | 399-449 |
| 登录日志写入 | `internal/storage/sql_provider.go` | 1579-1587 |
| OTC 写入 | `internal/storage/sql_provider.go` | 1018-1031 |
| WebAuthn 凭证写入 | `internal/storage/sql_provider.go` | 728-740 |
| V24 特殊迁移注册 | `internal/storage/sql_provider_schema_special.go` | 14-18 |
| CLI 迁移命令 | `internal/commands/storage.go` | 777-875 |
| 锁查询 SQL | `internal/storage/sql_provider_queries_special.go` | 12 |
