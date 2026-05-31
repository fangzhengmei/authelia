# Authelia Storage Schema 演进与迁移机制深度分析

## 1. 架构概览

Authelia 的存储层采用统一的 `SQLProvider` 抽象，支持三种关系型后端：

| 后端 | Provider 名称 | 驱动 | 特殊处理 |
|------|--------------|------|---------|
| PostgreSQL | `postgres` | `pgx` | 参数占位符 `$1` 重绑定、UPSERT 使用 `ON CONFLICT`、迁移锁 `LOCK TABLE` |
| MySQL | `mysql` | `go-sql-driver/mysql` | `MultiStatements=true`、`RENAME` 语法差异、**无事务包裹迁移** |
| SQLite | `sqlite` | `sqlite3e`(自定义驱动) | 注册 `BIN2B64`/`B642BIN` 函数、TRUNCATE 用 DELETE+VACUUM 模拟 |

入口函数 `NewProvider()`（`internal/storage/sql_provider.go:24`）根据配置动态选择后端实现。所有后端共享同一个 `SQLProvider` 结构体，通过字段覆盖实现 SQL 方言差异。

---

## 2. Schema 版本检测机制

### 2.1 版本号语义

版本号是一个整数，含义如下（`internal/storage/sql_provider_schema.go:87-117`）：

| 版本值 | 含义 |
|--------|------|
| `-2` | 未知状态（检测出错或 pre1 混入了 v1 表） |
| `-1` | pre1（Authelia v3 遗留 schema，含 `totp_secrets`/`identity_verification_tokens`/`u2f_devices`） |
| `0` | 空数据库（无任何表） |
| `1..24` | 正式版本号 |

### 2.2 版本检测流程

`SchemaVersion()` 方法的检测逻辑如下：

```
1. 查询所有表名 → SchemaTables()
2. 如果无任何表 → 返回 0（空数据库）
3. 如果存在 migrations 表 → 查询最新一条迁移记录的 version_after → 返回该值
4. 如果不存在 migrations 表但存在 pre1 特征表 → 检查是否混入 v1 表
   - 若纯 pre1 表集合 → 返回 -1
   - 若同时含 v1 表 → 返回 -2（错误状态）
5. 其他情况 → 返回 0
```

关键点：**版本号由 `migrations` 表中最新记录的 `version_after` 字段决定**，而非迁移文件数量。`migrations` 表结构（`V0001.Initial_Schema.up.sql`）：

```sql
CREATE TABLE IF NOT EXISTS migrations (
    id SERIAL PRIMARY KEY,
    applied TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version_before INTEGER NULL DEFAULT NULL,
    version_after INTEGER NOT NULL,
    application_version VARCHAR(128) NOT NULL
);
```

### 2.3 最新可用版本检测

`SchemaLatestVersion()` → `latestMigrationVersion()`（`internal/storage/migrations.go:19`）扫描嵌入文件系统中指定 provider 目录下所有 `*.up.sql` 文件，取版本号最大值。当前最新版本为 **24**。

---

## 3. 迁移脚本的注册与发现

### 3.1 文件系统嵌入

迁移脚本通过 `//go:embed migrations/*` 编译进二进制（`internal/storage/migrations.go:17`），目录结构：

```
migrations/
├── mysql/
│   ├── V0001.Initial_Schema.up.sql
│   ├── V0001.Initial_Schema.down.sql
│   ├── V0002.WebAuthn.up.sql
│   └── ...
├── postgres/
│   ├── V0001.Initial_Schema.up.sql
│   └── ...
└── sqlite/
    ├── V0001.Initial_Schema.up.sql
    └── ...
```

### 3.2 文件名解析规则

正则表达式（`internal/storage/const.go:95`）：

```
^V(?P<Version>\d{4})\.(?P<Name>[^.]+)\.(?P<Direction>(up|down))\.sql$
```

示例：`V0024.WebAuthnAttestationType.up.sql` → Version=24, Name="WebAuthnAttestationType", Direction=up

`scanMigration()` 函数解析文件名并读取文件内容，构造 `SchemaMigration` 结构体：

```go
type SchemaMigration struct {
    Version  int      // 版本号
    Name     string   // 迁移名称（下划线转空格）
    Provider string   // 后端名称
    Up       bool     // true=up, false=down
    Query    string   // SQL 内容
}
```

### 3.3 特殊迁移（Go 代码迁移）

部分迁移不仅需要执行 SQL，还需要运行 Go 逻辑。通过 `migrationsSpecialUp` 和 `migrationsSpecialDown` 映射表注册（`internal/storage/sql_provider_schema_special.go`）：

```go
var migrationsSpecialUp = map[int][]fSchemaMigration{
    24: {migrationSpecialUp24},
}
var migrationsSpecialDown = map[int][]fSchemaMigration{}
```

当前仅版本 24（WebAuthnAttestationType）有特殊 up 迁移：执行 SQL 后逐页加载 WebAuthn 凭证，调用 `credential.VerifyAttestationType()` 校验并更新 attestation_type 字段。

特殊迁移函数签名：

```go
type fSchemaMigration func(ctx context.Context, conn SQLXConnection, provider *SQLProvider, prior, target int) error
```

### 3.4 迁移加载与过滤

`loadMigrations(providerName, prior, target)` 的核心逻辑（`internal/storage/migrations.go:53`）：

1. 如果 `prior == target`，直接返回 `ErrMigrateCurrentVersionSameAsTarget`
2. 判断方向：`up = prior < target`
3. 扫描嵌入文件系统中该 provider 的所有迁移文件
4. 对每个迁移调用 `skipMigration(up, target, prior, &migration)` 过滤
5. 排序：up 按版本号升序，down 按版本号降序

`skipMigration()` 过滤规则（`internal/storage/migrations.go:98`）：

- **Up 方向**：只保留 `Up=true` 且 `prior < Version <= target` 的迁移
- **Down 方向**：只保留 `Up=false` 且 `target < Version <= prior` 的迁移

---

## 4. 前向迁移（Up）路径

### 4.1 完整流程

`SchemaMigrate(ctx, up=true, version)` 方法（`internal/storage/sql_provider_schema.go:186`）：

```
1. 【事务开始】PostgreSQL/SQLite: 开启事务 tx；MySQL: 不开事务，直接用 db 连接
2. 读取当前版本 currentVersion
3. 如果 currentVersion != 0，执行 schemaMigrateLock() 锁定
4. 执行 schemaMigrateChecks() 校验
5. 执行 schemaMigrate() 逐个应用迁移：
   a. 加载迁移列表 loadMigrations()
   b. 对每个迁移调用 schemaMigrateApply()：
      i.   若 Query 非空，执行 SQL
      ii.  若为 V1 up，写入加密校验值
      iii. 若有特殊迁移函数，依次调用
      iv.  调用 schemaMigrateFinalize() 写入 migrations 表记录
   c. 若某个迁移失败 → 调用 schemaMigrateRollback()
6. 【事务提交】PostgreSQL/SQLite: commit（失败则 rollback）
```

### 4.2 关键校验（schemaMigrateChecks）

```
- currentVersion == -1 → 禁止从 pre1 升级（建议用 4.37.2 版本）
- targetVersion == -1 → 禁止降级到 pre1
- targetVersion == currentVersion → 已在目标版本
- currentVersion > latest → 当前版本超出已知范围，必须先降级
- Up 方向额外校验：
  - target < current → 错误
  - target == SchemaLatest 且 latest == current → 已是最新
  - target != SchemaLatest 且 latest < target → 目标版本不存在
```

### 4.3 V0→V1 特殊处理

当 `prior == 0` 且是 up 迁移时，锁在第一个迁移（V1）执行后才获取（`schemaMigrate.go:255-258`）。这是因为 V0（空数据库）不存在 migrations 表，无法对其加锁。

### 4.4 迁移记录写入

`schemaMigrateFinalize()` 在每次迁移成功后向 `migrations` 表插入一条记录：

```sql
INSERT INTO migrations (applied, version_before, version_after, application_version)
VALUES (?, ?, ?, ?)
```

其中 `application_version` 记录执行迁移的 Authelia 二进制版本。**V1 down 迁移不写入记录**（因为 down 到 V0 时 migrations 表将被删除）。

---

## 5. 回滚（Down）路径

### 5.1 与 Up 的差异

| 维度 | Up | Down |
|------|-----|------|
| 迁移排序 | 版本号升序 | 版本号降序 |
| 过滤条件 | `Up=true` 的迁移 | `Up=false` 的迁移 |
| 目标默认值 | `SchemaLatest`（最大 int32） | **必须手动指定** |
| 安全确认 | 无 | 需输入 "DESTROY" 确认（CLI） |
| pre1 支持 | 禁止从 pre1 升级 | 禁止降级到 pre1 |

### 5.2 回滚失败处理

迁移失败时的回滚策略分两种情况（`schemaMigrateRollback()`，`internal/storage/sql_provider_schema.go:337`）：

**有事务（PostgreSQL/SQLite）**：直接 `tx.Rollback()`，事务自动撤销所有已执行的 DDL/DML。

**无事务（MySQL）**：调用 `schemaMigrateRollbackWithoutTx()`，从当前失败版本反向执行 down 迁移至 prior 版本。这是**尽力而为**的补偿，不一定能完全恢复（例如 DROP TABLE 不可逆）。

### 5.3 MySQL 为什么不用事务

MySQL 的 DDL 语句（`ALTER TABLE`、`CREATE TABLE` 等）会隐式提交事务，无法在事务中回滚。因此对 MySQL，迁移直接在 `db` 连接上执行，不包裹事务。这是 Authelia 代码中明确的设计取舍（`sql_provider_schema.go:192-199`）。

---

## 6. 写入锁定策略

### 6.1 PostgreSQL：ACCESS EXCLUSIVE 锁

`schemaMigrateLock()` 方法（`internal/storage/sql_provider_schema.go:271`）：

```go
func (p *SQLProvider) schemaMigrateLock(ctx context.Context, conn SQLXConnection) error {
    if p.name != providerPostgres {
        return nil
    }
    _, err = conn.ExecContext(ctx, fmt.Sprintf("LOCK TABLE %s IN ACCESS EXCLUSIVE MODE", tableMigrations))
    return err
}
```

**仅 PostgreSQL 加锁**。`ACCESS EXCLUSIVE` 是 PostgreSQL 最严格的锁模式：
- 阻塞所有并发读写该表的操作
- 确保迁移期间没有其他进程修改 `migrations` 表
- 在事务内持有，事务提交/回滚后释放

### 6.2 MySQL 和 SQLite：无显式锁

- **MySQL**：依赖 DDL 隐式提交的原子性，不使用显式锁。由于没有事务包裹，每个 DDL 语句独立执行并隐式提交。
- **SQLite**：依赖内置的文件级写锁。SQLite 在 WAL 模式下支持并发读，但写操作串行化。

### 6.3 锁获取时机

1. **当前版本非零时**：在 `SchemaMigrate()` 中，校验之前获取锁（`sql_provider_schema.go:208`）
2. **从零升级时**：在 `schemaMigrate()` 中，V1 迁移执行完后才获取锁（`sql_provider_schema.go:255-258`），因为 V0 状态不存在 migrations 表

---

## 7. 启动时自动迁移与业务共存

### 7.1 StartupCheck 自动迁移

`SQLProvider.StartupCheck()`（`internal/storage/sql_provider.go:399`）在服务启动时自动执行：

```go
switch err = p.SchemaMigrate(ctx, true, SchemaLatest); err {
case nil:
    break
case ErrSchemaAlreadyUpToDate:
    p.log.Infof("Storage schema is already up to date")
default:
    return fmt.Errorf("error during schema migrate: %w", err)
}
```

这意味着**每次 Authelia 启动都会尝试自动迁移到最新版本**。

### 7.2 停机影响分析

当前设计中，**迁移与业务不可真正零停机共存**，原因如下：

#### 7.2.1 DDL 操作的非原子性

大多数迁移脚本执行 `ALTER TABLE`/`CREATE TABLE` 等 DDL。在 PostgreSQL 和 SQLite 中，DDL 在事务内执行（PostgreSQL 事务性 DDL），但：

- **PostgreSQL**：`ACCESS EXCLUSIVE` 锁阻塞所有并发访问，迁移期间相关表完全不可读写
- **SQLite**：写锁阻塞所有并发写操作
- **MySQL**：DDL 隐式提交，每个 ALTER TABLE 执行时短暂锁表，但无全局事务保护

#### 7.2.2 特殊迁移的数据遍历

版本 24 的特殊迁移需要逐页加载所有 WebAuthn 凭证并验证更新。这会持有事务连接并长时间占用锁，在数据量大时可能造成显著停机。

#### 7.2.3 加密密钥验证

StartupCheck 在迁移前先执行加密密钥校验（`SchemaEncryptionCheckKey`），如果密钥不匹配则直接拒绝启动。

### 7.3 最小停机策略建议

基于代码分析，实际运维中可采用以下策略：

#### 方案一：CLI 预迁移（推荐）

```bash
# 1. 在新版本二进制替换前，用 CLI 执行迁移
authelia storage migrate up --target 24

# 2. 验证迁移结果
authelia storage schema-info

# 3. 滚动更新 Authelia 服务
```

优势：迁移与业务服务解耦。由于 `SchemaMigrate` 可通过 CLI 独立调用（`internal/commands/storage.go` 的 `newStorageMigrateCmd`），迁移可以在不停服务的情况下执行，但**迁移期间数据库仍会短暂锁表**。

#### 方案二：单实例滚动更新

1. 缩减至单实例运行
2. 部署新版本，启动时自动迁移
3. 迁移完成后扩展至多实例

注意：**不能同时运行新旧版本**，因为 `currentVersion > latest` 检查会导致旧版本拒绝启动。

#### 方案三：PostgreSQL 专属优化

对于 PostgreSQL 后端，可利用其事务性 DDL 的优势：
- 迁移在事务内完成，要么全部成功要么全部回滚
- `ACCESS EXCLUSIVE` 锁确保一致性
- 停机时间 = DDL 执行时间（通常极短，毫秒到秒级）

### 7.4 多实例部署的竞态条件

当前代码**没有分布式锁**机制来防止多个 Authelia 实例同时执行迁移。PostgreSQL 的 `LOCK TABLE` 仅在单连接事务内有效。如果多实例同时启动：

1. 实例 A 和实例 B 同时调用 `SchemaMigrate`
2. 两者都读取到相同的 `currentVersion`
3. 两者都尝试执行相同的迁移
4. PostgreSQL：第二个实例的 `LOCK TABLE` 会阻塞直到第一个提交
5. MySQL：可能导致重复 DDL 执行（某些 ALTER TABLE 可幂等，某些不可）
6. SQLite：写锁串行化，但可能超时

**实际缓解**：Authelia 的 `StartupCheck` 在迁移失败时会阻止服务启动，因此即使竞态发生，最坏情况是多余实例启动失败而非数据损坏。

---

## 8. 版本兼容性边界

### 8.1 Pre1（V3 遗留）处理

- 当前版本（V4）**不再支持从 pre1 升级或降级到 pre1**
- 建议使用 Authelia 4.37.2 作为中间版本完成 pre1→V1 的迁移
- pre1 检测通过比对特征表名实现（`tablesPre1` 列表）

### 8.2 版本超前检测

如果数据库的 schema 版本高于当前 Authelia 二进制支持的最新版本（`currentVersion > latest`），启动会被拒绝。这防止了新版本写入的数据结构被旧版本错误解读。

### 8.3 迁移历史完整性

`schemaMigrateFinalize()` 在每次迁移后写入记录，但 V1 down 迁移除外（因为 migrations 表会被删除）。迁移历史可通过 CLI 查看：

```bash
authelia storage migrate history
```

---

## 9. 加密密钥与迁移的交互

### 9.1 加密校验值

V1 up 迁移后，`setNewEncryptionCheckValue()` 会向 `encryption` 表写入一条 `name="check"` 的记录，用于后续验证加密密钥是否正确。

### 9.2 加密密钥轮换

加密密钥轮换（`SchemaEncryptionChangeKey`）和 HMAC 密钥轮换（`SchemaEncryptionRotateHMACKey`）是独立于 schema 迁移的操作：
- 密钥轮换使用事务包裹，逐表解密-重加密
- HMAC 轮换是破坏性操作，会截断相关表数据

### 9.3 启动时的密钥验证

`StartupCheck` 在迁移前先检查加密密钥有效性。如果密钥不匹配，直接返回 `ErrSchemaEncryptionInvalidKey`，不执行迁移。

---

## 10. 迁移脚本编写规范（从代码推断）

1. **文件名格式**：`V{4位版本号}.{名称}.up.sql` / `V{4位版本号}.{名称}.down.sql`
2. **版本号递增**：每个新迁移递增 1，当前最大为 24
3. **三种后端都需要**：mysql/、postgres/、sqlite/ 三个目录必须各有一份
4. **Down 迁移应可逆**：down 脚本应精确撤销 up 脚本的变更
5. **特殊迁移注册**：如果需要 Go 代码逻辑，在 `migrationsSpecialUp`/`migrationsSpecialDown` 中注册
6. **空迁移**：Query 为空的迁移会被跳过 SQL 执行，但仍会写入迁移记录
7. **幂等性**：由于 MySQL 无事务包裹，up 脚本应尽量保持幂等（如使用 `IF NOT EXISTS`）

---

## 11. 关键代码路径索引

| 功能 | 文件 | 行号 |
|------|------|------|
| Provider 工厂 | `internal/storage/sql_provider.go` | 24 |
| StartupCheck + 自动迁移 | `internal/storage/sql_provider.go` | 399-449 |
| 版本检测 | `internal/storage/sql_provider_schema.go` | 87-117 |
| 迁移主流程 | `internal/storage/sql_provider_schema.go` | 186-240 |
| 锁获取 | `internal/storage/sql_provider_schema.go` | 271-281 |
| 迁移应用（含特殊迁移） | `internal/storage/sql_provider_schema.go` | 283-321 |
| 迁移记录写入 | `internal/storage/sql_provider_schema.go` | 323-335 |
| 回滚处理 | `internal/storage/sql_provider_schema.go` | 337-367 |
| 校验逻辑 | `internal/storage/sql_provider_schema.go` | 379-423 |
| 迁移文件加载与过滤 | `internal/storage/migrations.go` | 53-96 |
| 迁移文件名解析 | `internal/storage/migrations.go` | 125-157 |
| 特殊迁移注册 | `internal/storage/sql_provider_schema_special.go` | 14-18 |
| SchemaMigration 模型 | `internal/model/schema_migration.go` | 8-37 |
| Migration 记录模型 | `internal/model/migration.go` | 8-14 |
| CLI 迁移命令 | `internal/commands/storage.go` | 777-875 |
| 迁移执行 CLI | `internal/commands/storage_run.go` | 635-688 |
| 常量与正则 | `internal/storage/const.go` | 1-101 |
