# Authelia 多源配置组合与敏感字段处理深度解析

本文档基于代码深度分析，详细说明 Authelia 的多源配置组合机制、敏感字段处理、以及配置热更新/重启时的行为。

---

## 1. 配置源优先级与合并规则

### 1.1 配置源类型

Authelia 使用 **knadh/koanf/v2** 作为配置管理库，支持多种配置源。在 `internal/configuration/sources.go` 中定义了以下配置源类型：

| 源类型 | 优先级 | 说明 | 对应结构体 |
|--------|--------|------|------------|
| 默认值 (Defaults) | 1 (最低) | 硬编码的默认配置值 | `MapSource` |
| YAML 文件 | 2 | 从指定路径加载的 YAML 配置文件 | `FileSource` |
| 环境变量 | 3 | `AUTHELIA_` 前缀的环境变量 | `EnvironmentSource` |
| Secrets 文件 | 4 (最高) | `AUTHELIA_*_FILE` 前缀指向的文件内容 | `SecretsSource` |

### 1.2 配置源加载顺序 (关键代码)

在 `sources.go:377-393` 的 `NewDefaultSources()` 函数中明确定义了加载顺序：

```go
func NewDefaultSources(paths []string, prefix, delimiter string, additionalSources ...Source) (sources []Source) {
    sources = []Source{NewMapSource(defaults)}           // 1. 默认值

    fileSources := NewFileSources(paths)
    for _, source := range fileSources {
        sources = append(sources, source)                // 2. YAML 文件
    }

    sources = append(sources, NewEnvironmentSource(prefix, delimiter))  // 3. 环境变量
    sources = append(sources, NewSecretsSource(prefix, delimiter))      // 4. Secrets

    // ... 额外源
}
```

**合并规则**：在 `provider.go:150-169` 的 `loadSources()` 函数中，按顺序加载每个源并调用 `Merge()` 方法。后加载的源会**覆盖**先加载的源中相同键的值。

```go
func loadSources(ko *koanf.Koanf, val *schema.StructValidator, sources ...Source) (err error) {
    for _, source := range sources {
        if err = source.Load(val); err != nil {
            // 记录错误但继续
        }
        if err = source.Merge(ko, val); err != nil {
            // 记录错误但继续
        }
    }
}
```

### 1.3 配置加载完整流程

完整的配置加载流程在 `commands/context.go:437-456` 中：

```
1. 解析命令行参数，获取配置文件路径和过滤器
2. 创建配置源列表 (NewDefaultSourcesWithDefaults)
   - 默认值 → 文件 → 环境变量 → Secrets
3. 加载定义 (LoadDefinitions)
4. 加载主配置 (LoadAdvanced)
   - 加载所有源
   - 合并到 koanf 实例
   - 键名重映射 (处理废弃键)
   - 反序列化为 Configuration 结构体
   - 应用定义映射
5. 验证配置 (ValidateConfiguration)
```

---

## 2. 环境变量处理机制

### 2.1 环境变量命名规则

- **前缀**：`AUTHELIA_` (定义在 `const.go:10`)
- **分隔符**：`_` (定义在 `const.go:13`)
- **转换规则**：
  - 配置键 `storage.mysql.password` → 环境变量 `AUTHELIA_STORAGE_MYSQL_PASSWORD`
  - 转换函数：`helpers.go:82-84` 的 `ToEnvironmentKey()`

```go
func ToEnvironmentKey(key, prefix, delimiter string) string {
    return prefix + strings.ToUpper(strings.ReplaceAll(key, constDelimiter, delimiter))
}
```

### 2.2 环境变量回调处理

在 `koanf_callbacks.go:15-34` 中定义了环境变量转换回调：

```go
func koanfEnvironmentCallback(keyMap map[string]string, ignoredKeys []string, prefix, delimiter string) func(key, value string) (finalKey string, finalValue any) {
    return func(key, value string) (finalKey string, finalValue any) {
        if k, ok := keyMap[key]; ok {
            return k, value  // 精确匹配映射
        }
        if utils.IsStringInSlice(key, ignoredKeys) {
            return "", nil   // 忽略 Secrets 环境变量
        }
        // 自动转换：AUTHELIA_X_Y → x.y
        formattedKey := strings.TrimPrefix(key, prefix)
        formattedKey = strings.ReplaceAll(strings.ToLower(formattedKey), delimiter, constDelimiter)
        if utils.IsStringInSlice(formattedKey, schema.Keys) {
            return formattedKey, value
        }
        return key, value
    }
}
```

**关键点**：
1. `keyMap` 预先生成了所有有效配置键的环境变量映射
2. `ignoredKeys` 包含所有 Secrets 环境变量（`*_FILE`），避免被普通环境变量处理器处理
3. 只有在 `schema.Keys` 列表中的键才会被接受

### 2.3 环境变量键映射生成

在 `helpers.go:10-57` 的 `getEnvConfigMap()` 中生成键映射：

```go
func getEnvConfigMap(keys []string, prefix, delimiter string, ds map[string]Deprecation, dms []MultiKeyMappedDeprecation) (keyMap map[string]string, ignoredKeys []string) {
    keyMap = make(map[string]string)
    for _, key := range keys {
        keyMap[ToEnvironmentKey(key, prefix, delimiter)] = key
        // Secret envs should be ignored by the env parser.
        if IsSecretKey(key) {
            ignoredKeys = append(ignoredKeys, ToEnvironmentSecretKey(key, prefix, delimiter))
        }
    }
    // ... 处理废弃键的映射
}
```

---

## 3. Secrets 文件处理机制

### 3.1 Secrets 识别规则

在 `helpers.go:92-110` 的 `IsSecretKey()` 函数中定义了敏感字段的识别规则：

```go
func IsSecretKey(key string) (isSecretKey bool) {
    if strings.Contains(key, "[]") {        // 排除数组键
        return false
    }
    if strings.Contains(key, ".*.") {       // 排除通配符键
        return false
    }
    if utils.IsStringInSlice(key, secretExclusionExact) {  // 精确排除列表
        return false
    }
    if utils.IsStringInSliceF(key, secretExclusionPrefix, strings.HasPrefix) {  // 前缀排除
        return false
    }
    return utils.IsStringInSliceF(key, secretSuffix, strings.HasSuffix)  // 后缀匹配
}
```

**敏感后缀** (`const.go:80`)：
```go
secretSuffix = []string{"key", "secret", "password", "token", "certificate_chain"}
```

**排除前缀** (`const.go:81`)：
```go
secretExclusionPrefix = []string{"identity_providers.oidc.lifespans."}
```

**精确排除** (`const.go:82`)：
```go
secretExclusionExact = []string{"server.tls.key", "authentication_backend.disable_reset_password", "tls_key"}
```

### 3.2 Secrets 环境变量命名

Secrets 环境变量在普通环境变量基础上增加 `_FILE` 后缀：
- 配置键 `storage.mysql.password` → Secrets 环境变量 `AUTHELIA_STORAGE_MYSQL_PASSWORD_FILE`
- 转换函数：`helpers.go:87-89` 的 `ToEnvironmentSecretKey()`

```go
func ToEnvironmentSecretKey(key, prefix, delimiter string) string {
    return prefix + strings.ToUpper(strings.ReplaceAll(key, constDelimiter, delimiter)) + constSecretSuffix
}
```

### 3.3 Secrets 加载流程

在 `koanf_callbacks.go:37-64` 的 `koanfEnvironmentSecretsCallback()` 中处理 Secrets：

```go
func koanfEnvironmentSecretsCallback(keyMap map[string]string, validator *schema.StructValidator) func(key, value string) (finalKey string, finalValue any) {
    return func(key, value string) (finalKey string, finalValue any) {
        k, ok := keyMap[key]
        if !ok {
            return "", nil  // 不在 Secrets 映射中的键被忽略
        }
        switch v, err := loadSecret(value); err {
        case nil:
            return k, v  // 成功读取文件内容
        default:
            // 处理文件不存在、权限错误等
            switch {
            case os.IsNotExist(err):
                validator.Push(fmt.Errorf(errFmtSecretOSNotExist, value, k, err))
            case os.IsPermission(err):
                validator.Push(fmt.Errorf(errFmtSecretOSPermission, value, k, err))
            default:
                validator.Push(fmt.Errorf(errFmtSecretOSError, value, k, err))
            }
            return "", nil
        }
    }
}
```

**文件读取** (`helpers.go:112-119`)：
```go
func loadSecret(path string) (value string, err error) {
    content, err := os.ReadFile(path)
    if err != nil {
        return "", err
    }
    return strings.TrimRight(string(content), "\n"), err  // 自动去掉末尾换行
}
```

### 3.4 Secrets 合并时的冲突检测

在 `sources.go:303-313` 的 `SecretsSource.Merge()` 中实现了冲突检测：

```go
func (s *SecretsSource) Merge(ko *koanf.Koanf, val *schema.StructValidator) (err error) {
    for _, key := range s.koanf.Keys() {
        value, ok := ko.Get(key).(string)
        if ok && value != "" {
            // 如果该键已在其他源中定义且非空，报错
            val.Push(fmt.Errorf(errFmtSecretAlreadyDefined, key))
        }
    }
    return ko.Merge(s.koanf)
}
```

**重要安全特性**：如果一个敏感字段已经通过其他配置源（如 YAML 文件）定义了非空值，再通过 Secrets 定义会触发验证错误。这防止了 Secrets 被意外覆盖。

---

## 4. 配置过滤器（Filters）触发条件与生效逻辑

### 4.1 过滤器的触发条件

配置过滤器只在特定条件下生效，定义在 `commands/root.go:43` 和 `commands/util.go:233-239`：

```go
// 命令行标志定义 (root.go:43)
cmd.PersistentFlags().StringSlice(cmdFlagNameConfigExpFilters, nil, 
    "list of filters to apply to all configuration files, ...")

// 过滤器加载 (util.go:233-239)
if filterNames, _, err = loadXEnvCLIStringSliceValue(cmd, 
    cmdFlagEnvNameConfigFilters, cmdFlagNameConfigExpFilters); err != nil {
    return nil, nil, err
}

if filters, err = configuration.NewFileFilters(filterNames); err != nil {
    return nil, nil, fmt.Errorf("error occurred loading configuration: "+
        "flag '--%s' is invalid: %w", cmdFlagNameConfigExpFilters, err)
}
```

**触发条件**：

| 触发方式 | 说明 | 对应常量 |
|---------|------|---------|
| 命令行参数 | `--config.experimental.filters=template,expand-env` | `cmdFlagNameConfigExpFilters` |
| 环境变量 | `X_AUTHELIA_CONFIG_FILTERS=template,expand-env` | `cmdFlagEnvNameConfigFilters` |

**优先级规则**（`util.go:66-88` 的 `loadXEnvCLIStringSliceValue`）：
- 如果通过命令行参数显式指定了过滤器，环境变量会被**完全忽略**
- 如果命令行参数未指定，则尝试从环境变量读取
- 如果两者都未指定，则不应用任何过滤器

### 4.2 过滤器的生效范围

过滤器**只对 YAML 配置文件生效**，不对环境变量和 Secrets 文件生效。生效流程在 `koanf_provider_filtered_file.go:34-55`：

```go
func (f *FilteredFile) ReadBytes() (data []byte, err error) {
    if f.data != nil {
        return f.data, nil
    }

    if f.data, err = os.ReadFile(f.path); err != nil {  // 1. 读取原始文件
        return nil, err
    }

    if len(f.data) == 0 || len(f.filters) == 0 {  // 2. 无过滤器直接返回
        return f.data, nil
    }

    for _, filter := range f.filters {  // 3. 按顺序应用过滤器
        if f.data, err = filter.Filter(f.data); err != nil {
            return nil, err
        }
    }

    return f.data, nil  // 4. 返回过滤后的内容供 YAML 解析
}
```

**关键点**：
1. 过滤器在**文件读取后、YAML 解析前**生效
2. 过滤器按**指定顺序**处理，不能重复（`NewFileFilters` 会检测重复）
3. 只处理 `.yml` 和 `.yaml` 扩展名的文件
4. 目录加载时，目录下的所有 YAML 文件都会应用相同的过滤器

### 4.3 可用过滤器类型

在 `koanf_provider_filtered_file.go:131-157` 中定义了两种过滤器：

```go
func NewFileFilters(names []string) (filters []BytesFilter, err error) {
    for i, name := range names {
        name = strings.ToLower(name)
        switch name {
        case filterTemplate:     // "template"
            filters[i] = NewTemplateFileFilter()
        case filterExpandEnv:    // "expand-env"
            filters[i] = NewExpandEnvFileFilter()
        default:
            return nil, fmt.Errorf("invalid filter named '%s'", name)
        }
        // 检测重复过滤器
        if _, ok := filterMap[name]; ok {
            return nil, fmt.Errorf("duplicate filter named '%s'", name)
        }
        filterMap[name] = 1
    }
}
```

| 过滤器名称 | 功能 | 状态 |
|-----------|------|------|
| `template` | 使用 Go `text/template` 处理配置文件 | 正式功能 |
| `expand-env` | 展开 `${VAR}` 形式的环境变量引用 | 已废弃（DEPRECATED） |

### 4.4 过滤器的处理顺序与缓存

**处理顺序**（`sources.go:395-412` 的 `NewDefaultSourcesFiltered`）：
```
配置源加载顺序：
1. 默认值 → 2. 过滤后的 YAML 文件 → 3. 环境变量 → 4. Secrets
```

**缓存机制**：
- `FilteredFile.ReadBytes()` 有内存缓存（`f.data` 字段）
- 同一文件只会被读取和过滤一次
- 目录加载时，每个文件独立缓存（`s.providers[file]` map）

### 4.5 过滤器的安全风险

**Trace 日志泄露风险**（`koanf_provider_filtered_file.go:79-83` 和 `114-118`）：

```go
// ExpandEnvBytesFilter 的 Trace 日志
if f.log.Level >= logrus.TraceLevel {
    f.log.
        WithField("content", base64.RawStdEncoding.EncodeToString(out)).
        Trace("Expanded Env File Filter completed successfully")
}

// TemplateBytesFilter 的 Trace 日志
if f.log.Level >= logrus.TraceLevel {
    f.log.
        WithField("content", base64.RawStdEncoding.EncodeToString(out)).
        Trace("Templated File Filter completed successfully")
}
```

**重要**：当日志级别为 `trace` 时，过滤后的配置内容会以 base64 编码形式输出到日志。虽然是 base64 编码，但可以轻易解码。生产环境必须禁用 `trace` 级别。

---

## 5. 敏感字段完整迁移清单与例外规则

### 5.1 敏感字段识别规则回顾

在 `helpers.go:92-110` 的 `IsSecretKey()` 函数中：

```go
func IsSecretKey(key string) (isSecretKey bool) {
    if strings.Contains(key, "[]") {        // 排除数组项（如 clients[].client_secret）
        return false
    }
    if strings.Contains(key, ".*.") {       // 排除通配符键
        return false
    }
    if utils.IsStringInSlice(key, secretExclusionExact) {  // 精确排除
        return false
    }
    if utils.IsStringInSliceF(key, secretExclusionPrefix, strings.HasPrefix) {  // 前缀排除
        return false
    }
    return utils.IsStringInSliceF(key, secretSuffix, strings.HasSuffix)  // 后缀匹配
}
```

### 5.2 完整的敏感后缀列表

定义在 `const.go:80`：
```go
secretSuffix = []string{"key", "secret", "password", "token", "certificate_chain"}
```

### 5.3 例外规则（排除规则）

定义在 `const.go:81-82`：
```go
secretExclusionPrefix = []string{"identity_providers.oidc.lifespans."}
secretExclusionExact  = []string{
    "server.tls.key", 
    "authentication_backend.disable_reset_password", 
    "tls_key"
}
```

**排除规则说明**：

| 排除类型 | 排除键 | 排除原因 |
|---------|--------|---------|
| 精确排除 | `server.tls.key` | TLS 私钥文件路径，不是密钥本身 |
| 精确排除 | `authentication_backend.disable_reset_password` | 布尔值配置，不是敏感字段 |
| 精确排除 | `tls_key` | 旧版本键名，同上 |
| 前缀排除 | `identity_providers.oidc.lifespans.*` | OIDC 生命周期配置（如 `access_token`）是时间值，不是密钥 |
| 模式排除 | 包含 `[]` 的键 | 数组项（如 `clients[].client_secret`）不支持 secrets |
| 模式排除 | 包含 `.*.` 的键 | 通配符配置项不支持 secrets |

### 5.4 路径型字段 vs 内容型字段：核心判定原则

在进行 Secrets 迁移前，必须区分两种完全不同的配置模式：

| 类型 | 配置含义 | 支持 `*_FILE` | 正确迁移方式 | 示例字段 |
|------|---------|--------------|-------------|----------|
| **内容型字段** | 配置值就是密钥/密码**内容本身** | ✅ 支持 | 使用 `*_FILE` 环境变量指向包含内容的文件 | `storage.encryption_key`、`session.secret` |
| **路径型字段** | 配置值是**文件路径字符串**，Authelia 自己读取文件 | ⚠️ 不建议 | 直接配置路径字符串，或挂载 secrets 文件 | `server.tls.key`、`storage.postgres.ssl.key` |

**代码判定依据**：

| 字段 | Schema 类型 | 实际读取方式 | 类型判定 |
|------|------------|-------------|---------|
| `*.tls.private_key` | `CryptographicPrivateKey` | 直接解析 PEM 内容 | 内容型 |
| `*.tls.certificate_chain` | `X509CertificateChain` | 直接解析 PEM 内容 | 内容型 |
| `server.tls.key` | `string` | 调用 `os.ReadFile(path)` | 路径型 |
| `storage.postgres.ssl.key` | `string` | 调用 `os.ReadFile(path)` | 路径型 |

**关键发现**：`storage.postgres.ssl.key` 虽然被 `IsSecretKey()` 识别为敏感字段（返回 `true`），但它实际上是**文件路径**，不是内容。用 `*_FILE` 注入会导致"路径的路径"问题。

### 5.5 可用 *_FILE 迁移的敏感字段完整清单

> 以下清单共 **24 个内容型字段**，按模块分组，含环境变量和 Secrets 环境变量的完整映射。

| # | 配置键 | 对应环境变量 | 对应 Secrets 环境变量 | 字段类型 | 来源 |
|---|--------|-------------|----------------------|---------|------|
| **认证后端 (LDAP)** | | | | | |
| 1 | `authentication_backend.ldap.password` | `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD` | `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE` | 密码字符串 | keys.go |
| 2 | `authentication_backend.ldap.tls.certificate_chain` | `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_TLS_CERTIFICATE_CHAIN` | `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_TLS_CERTIFICATE_CHAIN_FILE` | PEM 内容 | keys.go |
| 3 | `authentication_backend.ldap.tls.private_key` | `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_TLS_PRIVATE_KEY` | `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_TLS_PRIVATE_KEY_FILE` | PEM 内容 | keys.go |
| **Duo API** | | | | | |
| 4 | `duo_api.integration_key` | `AUTHELIA_DUO_API_INTEGRATION_KEY` | `AUTHELIA_DUO_API_INTEGRATION_KEY_FILE` | API Key 字符串 | keys.go |
| 5 | `duo_api.secret_key` | `AUTHELIA_DUO_API_SECRET_KEY` | `AUTHELIA_DUO_API_SECRET_KEY_FILE` | API Secret 字符串 | keys.go |
| **OIDC 身份提供者** | | | | | |
| 6 | `identity_providers.oidc.hmac_secret` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_HMAC_SECRET` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_HMAC_SECRET_FILE` | HMAC 密钥 | keys.go |
| 7 | `identity_providers.oidc.issuer_certificate_chain` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_ISSUER_CERTIFICATE_CHAIN` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_ISSUER_CERTIFICATE_CHAIN_FILE` | PEM 内容 | keys.go + deprecation.go |
| 8 | `identity_providers.oidc.issuer_private_key` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_ISSUER_PRIVATE_KEY` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_ISSUER_PRIVATE_KEY_FILE` | PEM 内容 | keys.go + deprecation.go |
| **身份验证** | | | | | |
| 9 | `identity_validation.reset_password.jwt_secret` | `AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET` | `AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE` | JWT 密钥 | keys.go |
| **邮件通知 (SMTP)** | | | | | |
| 10 | `notifier.smtp.password` | `AUTHELIA_NOTIFIER_SMTP_PASSWORD` | `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE` | 密码字符串 | keys.go |
| 11 | `notifier.smtp.tls.certificate_chain` | `AUTHELIA_NOTIFIER_SMTP_TLS_CERTIFICATE_CHAIN` | `AUTHELIA_NOTIFIER_SMTP_TLS_CERTIFICATE_CHAIN_FILE` | PEM 内容 | keys.go |
| 12 | `notifier.smtp.tls.private_key` | `AUTHELIA_NOTIFIER_SMTP_TLS_PRIVATE_KEY` | `AUTHELIA_NOTIFIER_SMTP_TLS_PRIVATE_KEY_FILE` | PEM 内容 | keys.go |
| **会话管理** | | | | | |
| 13 | `session.secret` | `AUTHELIA_SESSION_SECRET` | `AUTHELIA_SESSION_SECRET_FILE` | Session 密钥 | keys.go |
| 14 | `session.redis.password` | `AUTHELIA_SESSION_REDIS_PASSWORD` | `AUTHELIA_SESSION_REDIS_PASSWORD_FILE` | Redis 密码 | keys.go |
| 15 | `session.redis.high_availability.sentinel_password` | `AUTHELIA_SESSION_REDIS_HIGH_AVAILABILITY_SENTINEL_PASSWORD` | `AUTHELIA_SESSION_REDIS_HIGH_AVAILABILITY_SENTINEL_PASSWORD_FILE` | Sentinel 密码 | keys.go |
| 16 | `session.redis.tls.certificate_chain` | `AUTHELIA_SESSION_REDIS_TLS_CERTIFICATE_CHAIN` | `AUTHELIA_SESSION_REDIS_TLS_CERTIFICATE_CHAIN_FILE` | PEM 内容 | keys.go |
| 17 | `session.redis.tls.private_key` | `AUTHELIA_SESSION_REDIS_TLS_PRIVATE_KEY` | `AUTHELIA_SESSION_REDIS_TLS_PRIVATE_KEY_FILE` | PEM 内容 | keys.go |
| **存储 (通用)** | | | | | |
| 18 | `storage.encryption_key` | `AUTHELIA_STORAGE_ENCRYPTION_KEY` | `AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE` | 加密密钥 | keys.go |
| **存储 (MySQL)** | | | | | |
| 19 | `storage.mysql.password` | `AUTHELIA_STORAGE_MYSQL_PASSWORD` | `AUTHELIA_STORAGE_MYSQL_PASSWORD_FILE` | 数据库密码 | keys.go |
| 20 | `storage.mysql.tls.certificate_chain` | `AUTHELIA_STORAGE_MYSQL_TLS_CERTIFICATE_CHAIN` | `AUTHELIA_STORAGE_MYSQL_TLS_CERTIFICATE_CHAIN_FILE` | PEM 内容 | keys.go |
| 21 | `storage.mysql.tls.private_key` | `AUTHELIA_STORAGE_MYSQL_TLS_PRIVATE_KEY` | `AUTHELIA_STORAGE_MYSQL_TLS_PRIVATE_KEY_FILE` | PEM 内容 | keys.go |
| **存储 (PostgreSQL)** | | | | | |
| 22 | `storage.postgres.password` | `AUTHELIA_STORAGE_POSTGRES_PASSWORD` | `AUTHELIA_STORAGE_POSTGRES_PASSWORD_FILE` | 数据库密码 | keys.go |
| 23 | `storage.postgres.tls.certificate_chain` | `AUTHELIA_STORAGE_POSTGRES_TLS_CERTIFICATE_CHAIN` | `AUTHELIA_STORAGE_POSTGRES_TLS_CERTIFICATE_CHAIN_FILE` | PEM 内容 | keys.go |
| 24 | `storage.postgres.tls.private_key` | `AUTHELIA_STORAGE_POSTGRES_TLS_PRIVATE_KEY` | `AUTHELIA_STORAGE_POSTGRES_TLS_PRIVATE_KEY_FILE` | PEM 内容 | keys.go |

**废弃但仍可用的敏感字段**（通过 `deprecation.go` 的 `getSecretConfigMap()` 路径生效）：

| # | 废弃配置键 | 对应 Secrets 环境变量 | 替代键 | 废弃版本 |
|---|-----------|----------------------|--------|---------|
| D1 | `jwt_secret` | `AUTHELIA_JWT_SECRET_FILE` | `identity_validation.reset_password.jwt_secret` | 4.38 |
| D2 | `identity_providers.oidc.issuer_private_key` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_ISSUER_PRIVATE_KEY_FILE` | `identity_providers.oidc.jwks`（AutoMap=false） | 4.38 |
| D3 | `identity_providers.oidc.issuer_certificate_chain` | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_ISSUER_CERTIFICATE_CHAIN_FILE` | `identity_providers.oidc.jwks`（AutoMap=false） | 4.38 |

> **注意**：D2 和 D3 虽然仍在 `schema.Keys` 中存在（#7、#8），但其废弃映射在 `deprecation.go:257-276` 中标注为 `AutoMap: false`，意味着它们不会自动映射到新键 `identity_providers.oidc.jwks`，用户需手动调整配置。

### 5.6 不支持 *_FILE 迁移的字段及原因

> 以下字段名字看似含敏感后缀，但因各种原因**不建议或不支持** Secrets 文件加载。

| 配置键 | 敏感后缀 | 字段类型 | `IsSecretKey()` | 不支持原因 | 排除规则 |
|--------|---------|---------|----------------|-----------|---------|
| **精确排除 (路径型字段)** | | | | | |
| `server.tls.key` | `.key` | 路径字符串 | **false** | 指向 TLS 私钥的文件路径，不是密钥内容本身 | `secretExclusionExact` |
| `tls_key`（废弃） | `_key` | 路径字符串 | **false** | 废弃键名，映射到 `server.tls.key`，同样是路径 | `secretExclusionExact` |
| **设计缺陷：路径型但被误判** | | | | | |
| `storage.postgres.ssl.key` | `.key` | 路径字符串 | **true** ⚠️ | 已废弃的旧 SSL 配置，是文件路径，Authelia 自己 `os.ReadFile()` 读取 | 无排除，设计缺陷 |
| `storage.postgres.ssl.certificate` | 无 | 路径字符串 | **false** | 已废弃的旧 SSL 配置，是文件路径，后缀是 `certificate` 非 `certificate_chain` | 后缀不匹配 |
| `storage.postgres.ssl.root_certificate` | 无 | 路径字符串 | **false** | 已废弃的旧 SSL 配置，是文件路径 | 后缀不匹配 |
| `server.tls.certificate` | 无 | 路径字符串 | **false** | 指向 TLS 证书的文件路径，后缀是 `certificate` | 后缀不匹配 |
| **布尔值误用后缀** | | | | | |
| `authentication_backend.disable_reset_password` | `.password` | 布尔值 | **false** | 布尔开关 `true/false`，非密码 | `secretExclusionExact` |
| **前缀排除 (生命周期配置)** | | | | | |
| `identity_providers.oidc.lifespans.access_token` | `_token` | 时间值 | **false** | OIDC 生命周期时间配置，非密钥 | `secretExclusionPrefix` |
| `identity_providers.oidc.lifespans.id_token` | `_token` | 时间值 | **false** | OIDC 生命周期时间配置，非密钥 | `secretExclusionPrefix` |
| `identity_providers.oidc.lifespans.refresh_token` | `_token` | 时间值 | **false** | OIDC 生命周期时间配置，非密钥 | `secretExclusionPrefix` |
| `identity_providers.oidc.lifespans.minimum_parameter_entropy` | `_key` | 数字值 | **false** | 最小参数熵配置，非密钥 | `secretExclusionPrefix` |
| `identity_providers.oidc.lifespans.custom.*` 子键 | `_token` / `_key` | 时间值 | **false** | 通配符 + 前缀双重排除 | `secretExclusionPrefix` + `.*.` |
| **数组项排除** | | | | | |
| `identity_providers.oidc.clients[].client_secret` | `_secret` | 字符串 | **false** | OIDC 客户端数组项，不支持 Secrets | `[]` 排除 |
| `identity_providers.oidc.clients[].jwks[].key` | `.key` | 内容型 | **false** | 客户端 JWKS 数组项 | `[]` 排除 |
| `identity_providers.oidc.clients[].jwks[].certificate_chain` | `_chain` | 内容型 | **false** | 客户端 JWKS 数组项 | `[]` 排除 |
| `identity_providers.oidc.jwks[].key` | `.key` | 内容型 | **false** | 全局 JWKS 数组项 | `[]` 排除 |
| `identity_providers.oidc.jwks[].certificate_chain` | `_chain` | 内容型 | **false** | 全局 JWKS 数组项 | `[]` 排除 |
| `storage.postgres.servers[].tls.certificate_chain` | `_chain` | 内容型 | **false** | PostgreSQL 多服务器数组项 | `[]` 排除 |
| `storage.postgres.servers[].tls.private_key` | `_key` | 内容型 | **false** | PostgreSQL 多服务器数组项 | `[]` 排除 |
| **后缀不匹配** | | | | | |
| `*.key_length` 系列 | 无 | 数字值 | **false** | 以 `_length` 结尾，非 `_key` | 后缀不匹配 |
| `*_key_id` 系列 | 无 | 字符串 | **false** | 以 `_key_id` 结尾，非 `_key` | 后缀不匹配 |
| `*.password_reset.disable` | 无 | 布尔值 | **false** | 以 `_disable` 结尾，非 `_password` | 后缀不匹配 |
| `*.password_reset.custom_url` | 无 | URL | **false** | 以 `_url` 结尾，非 `_password` | 后缀不匹配 |

### 5.7 特别说明：`storage.postgres.ssl.key` 的设计缺陷

这是最容易混淆的字段，需要特别注意：

| 对比项 | `server.tls.key` | `storage.postgres.ssl.key` | `storage.postgres.tls.private_key` |
|--------|-----------------|---------------------------|----------------------------------|
| Schema 类型 | `string` | `string` | `CryptographicPrivateKey` |
| jsonschema 描述 | "Path to the Private Key" | "Path to the Private Key to use" | "The private key" |
| 读取方式 | Authelia 调用 `os.ReadFile` | Authelia 调用 `os.ReadFile` | 直接解析 PEM 内容 |
| `IsSecretKey()` | **false**（精确排除） | **true**（设计缺陷） | **true**（正确） |
| 支持 `*_FILE` | ❌ 不支持 | ❌ **不建议使用**（虽然技术上可以） | ✅ 正确支持 |
| 状态 | 活跃 | 已废弃（deprecated） | 新的标准方式 |

**代码验证**（`const.go:82`）：
```go
secretExclusionExact = []string{
    "server.tls.key", 
    "authentication_backend.disable_reset_password", 
    "tls_key"
}
```

`storage.postgres.ssl.key` 不在精确排除列表中，但它实际上和 `server.tls.key` 完全一样，都是**文件路径**，不是内容。这是一个设计疏忽。

**风险说明**：
- 如果你用 `AUTHELIA_STORAGE_POSTGRES_SSL_KEY_FILE=/path/to/key.pem`，Authelia 会把 `/path/to/key.pem` 读成字符串内容 `"-----BEGIN PRIVATE KEY-----\n..."`
- 然后 Authelia 会尝试用这个 PEM 内容字符串作为**文件路径**去调用 `os.ReadFile()`
- 结果必然是文件不存在错误

**正确迁移方式**：
```yaml
# 旧方式（已废弃，配置路径）
storage:
  postgres:
    ssl:
      key: /etc/authelia/pg-client-key.pem  # 路径字符串

# 新方式（推荐，配置内容，支持 *_FILE）
storage:
  postgres:
    tls:
      private_key: |
        -----BEGIN PRIVATE KEY-----
        MIIEvg...
        -----END PRIVATE KEY-----
# 或者用 *_FILE 环境变量
# AUTHELIA_STORAGE_POSTGRES_TLS_PRIVATE_KEY_FILE=/run/secrets/pg-client-key.pem
```

### 5.8 迁移判定矩阵（可直接执行）

> ✅ = 可用，❌ = 不可用，⚠️ = 有风险，🚀 = 推荐方式
>
> **判定依据**：Schema 类型 + 实际读取方式 + jsonschema 描述

| 类别 | 配置键 | Schema 类型 | 读取方式 | `IsSecretKey()` | 支持 `*_FILE` | 风险等级 | 正确迁移方式 | 代码引用 |
|------|--------|------------|---------|----------------|--------------|---------|-------------|---------|
| **✅ 密码字符串** | | | | | | | | |
| | `authentication_backend.ldap.password` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE` | `schema/authentication.go` |
| | `notifier.smtp.password` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_NOTIFIER_SMTP_PASSWORD_FILE` | `schema/notifier.go` |
| | `session.redis.password` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_SESSION_REDIS_PASSWORD_FILE` | `schema/session.go` |
| | `session.redis.high_availability.sentinel_password` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_SESSION_REDIS_HIGH_AVAILABILITY_SENTINEL_PASSWORD_FILE` | `schema/session.go` |
| | `storage.mysql.password` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_STORAGE_MYSQL_PASSWORD_FILE` | `schema/storage.go:28` |
| | `storage.postgres.password` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_STORAGE_POSTGRES_PASSWORD_FILE` | `schema/storage.go:28` |
| **✅ 密钥/Secret 字符串** | | | | | | | | |
| | `session.secret` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_SESSION_SECRET_FILE` | `schema/session.go` |
| | `storage.encryption_key` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_STORAGE_ENCRYPTION_KEY_FILE` | `schema/storage.go:15` |
| | `identity_validation.reset_password.jwt_secret` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE` | `schema/identity_validation.go` |
| | `identity_providers.oidc.hmac_secret` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_IDENTITY_PROVIDERS_OIDC_HMAC_SECRET_FILE` | `schema/identity_providers.go` |
| | `duo_api.integration_key` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_DUO_API_INTEGRATION_KEY_FILE` | `schema/duo.go` |
| | `duo_api.secret_key` | `string` | 直接使用 | true | ✅ | 低 | `AUTHELIA_DUO_API_SECRET_KEY_FILE` | `schema/duo.go` |
| **✅ TLS 内容型字段（推荐 🚀）** | | | | | | | | |
| | `*.tls.private_key` | `CryptographicPrivateKey` | 直接解析 PEM | true | ✅ | 低 | `*_PRIVATE_KEY_FILE` | `schema/shared.go:15` |
| | `*.tls.certificate_chain` | `X509CertificateChain` | 直接解析 PEM | true | ✅ | 低 | `*_CERTIFICATE_CHAIN_FILE` | `schema/shared.go:16` |
| **⚠️ 路径型字段（设计缺陷）** | | | | | | | | |
| | `storage.postgres.ssl.key` | `string` | `os.ReadFile()` | true ⚠️ | ❌ **不建议** | 高 | 直接配置路径，或改用 `storage.postgres.tls.private_key` | `schema/storage.go:60` + `storage/sql_provider_backend_postgres.go:333` |
| | `storage.postgres.ssl.certificate` | `string` | `os.ReadFile()` | false | ❌ | 中 | 直接配置路径，或改用 `storage.postgres.tls.certificate_chain` | `schema/storage.go:59` + `storage/sql_provider_backend_postgres.go:337` |
| | `storage.postgres.ssl.root_certificate` | `string` | `os.ReadFile()` | false | ❌ | 中 | 直接配置路径字符串 | `schema/storage.go:58` + `storage/sql_provider_backend_postgres.go:317` |
| **❌ 路径型字段（正确排除）** | | | | | | | | |
| | `server.tls.key` | `string` | `os.ReadFile()` | false | ❌ | 低 | 直接配置路径字符串 | `schema/server.go:49` |
| | `server.tls.certificate` | `string` | `os.ReadFile()` | false | ❌ | 低 | 直接配置路径字符串 | `schema/server.go:48` |
| | `server.tls.client_certificates[]` | `[]string` | `os.ReadFile()` | false | ❌ | 低 | 直接配置路径字符串列表 | `schema/server.go:50` |
| **❌ 数组项（不支持 Secrets）** | | | | | | | | |
| | `identity_providers.oidc.clients[].client_secret` | `string` | 直接使用 | false | ❌ | 中 | 在 YAML 中配置，或使用模板过滤器 | 含 `[]` 排除 |
| | `identity_providers.oidc.jwks[].key` | `CryptographicPrivateKey` | 直接解析 PEM | false | ❌ | 中 | 在 YAML 中配置 | 含 `[]` 排除 |
| | `storage.postgres.servers[].tls.*` | 内容型 | 直接解析 PEM | false | ❌ | 中 | 在 YAML 中配置 | 含 `[]` 排除 |
| **❌ 生命周期配置（前缀排除）** | | | | | | | | |
| | `identity_providers.oidc.lifespans.*_token` | `time.Duration` | 时间值 | false | ❌ | 低 | 正常配置，非敏感 | 前缀 `identity_providers.oidc.lifespans.` |

### 5.8.1 迁移决策流程图

```
配置键检查
    │
    ├─ 含 "[]" → ❌ 数组项，不支持 *_FILE
    │
    ├─ 前缀匹配 "identity_providers.oidc.lifespans." → ❌ 时间配置
    │
    ├─ 精确匹配排除列表（server.tls.key 等） → ❌ 路径型字段
    │
    ├─ IsSecretKey() = false → ❌ 不支持
    │
    └─ IsSecretKey() = true
        │
        ├─ 检查 Schema 类型和读取方式
        │   ├─ 内容型（CryptographicPrivateKey 等） → ✅ 支持 *_FILE
        │   └─ 路径型（string + os.ReadFile） → ⚠️ 不建议，改用新配置
        │
        └─ 验证 jsonschema 描述
            ├─ "Path to..." → ❌ 路径型
            └─ "The secret/password/key" → ✅ 内容型
```

### 5.8.2 高风险字段迁移示例

#### 错误示例：`storage.postgres.ssl.key` 使用 `*_FILE`

```bash
# ❌ 错误：路径型字段使用 *_FILE 会导致"路径的路径"问题
export AUTHELIA_STORAGE_POSTGRES_SSL_KEY_FILE=/run/secrets/pg-client-key.pem
# Authelia 会把文件内容（PEM字符串）当作文件路径去 os.ReadFile()
# 结果：open -----BEGIN PRIVATE KEY-----\n...: no such file or directory
```

#### 正确示例 1：继续使用路径型配置（挂载 Secret 文件）

```yaml
# ✅ 正确：直接配置文件路径，Secret 挂载到该路径
storage:
  postgres:
    ssl:
      key: /run/secrets/pg-client-key.pem  # Docker/K8s 挂载到此处
```

#### 正确示例 2：迁移到内容型配置（推荐）

```bash
# ✅ 正确：使用新的 tls.private_key（内容型）支持 *_FILE
export AUTHELIA_STORAGE_POSTGRES_TLS_PRIVATE_KEY_FILE=/run/secrets/pg-client-key.pem
```

```yaml
# YAML 中删除 ssl.key，改用 tls 配置
storage:
  postgres:
    tls:
      # private_key 内容从 *_FILE 环境变量注入
      minimum_version: TLS1.2
```

### 5.9 废弃键的 Secrets 处理路径

废弃键的 `_FILE` 环境变量通过 `getSecretConfigMap()` 的第二条遍历路径生效（`helpers.go:70-78`）：

```go
for key := range ds {  // ds = deprecations 映射
    if IsSecretKey(key) {
        originalKey := strings.ToUpper(strings.ReplaceAll(key, constDelimiter, delimiter)) + constSecretSuffix
        keyMap[prefix+originalKey] = key
    }
}
```

这意味着即使配置键已从 `schema.Keys` 中移除（如 `jwt_secret`），只要仍保留在 `deprecations` 映射中，其 `*_FILE` 环境变量依然有效，但值会被映射到废弃键本身，然后通过 `koanfRemapKeys()` 重映射到新键。

### 5.10 迁移清单验证

可以通过以下代码验证敏感字段识别（来自 `helpers_test.go:91-103` 和 `provider_test.go:28-68`）：

```go
// 验证废弃键的 _FILE 映射
func TestGetSecretConfigMap(t *testing.T) {
    keys := getSecretConfigMap(schema.Keys, DefaultEnvPrefix, DefaultEnvDelimiter, deprecations)
    
    key, ok := keys[DefaultEnvPrefix + "JWT_SECRET_FILE"]
    assert.True(t, ok)
    assert.Equal(t, "jwt_secret", key)
}

// 集成测试：验证所有 _FILE 环境变量均被正确解析
func TestShouldErrorSecretNotExist(t *testing.T) {
    testSetEnv(t, "IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET_FILE", ...)
    testSetEnv(t, "DUO_API_SECRET_KEY_FILE", ...)
    testSetEnv(t, "SESSION_SECRET_FILE", ...)
    testSetEnv(t, "AUTHENTICATION_BACKEND_LDAP_PASSWORD_FILE", ...)
    testSetEnv(t, "NOTIFIER_SMTP_PASSWORD_FILE", ...)
    testSetEnv(t, "SESSION_REDIS_PASSWORD_FILE", ...)
    testSetEnv(t, "SESSION_REDIS_HIGH_AVAILABILITY_SENTINEL_PASSWORD_FILE", ...)
    testSetEnv(t, "STORAGE_MYSQL_PASSWORD_FILE", ...)
    testSetEnv(t, "STORAGE_POSTGRES_PASSWORD_FILE", ...)
    testSetEnv(t, "IDENTITY_PROVIDERS_OIDC_ISSUER_PRIVATE_KEY_FILE", ...)
    testSetEnv(t, "IDENTITY_PROVIDERS_OIDC_HMAC_SECRET_FILE", ...)
    // ...
}
```

---

## 6. Secrets 文件换行处理边界细节

### 6.1 换行处理的核心代码

在 `helpers.go:112-119` 的 `loadSecret()` 函数中：

```go
func loadSecret(path string) (value string, err error) {
    content, err := os.ReadFile(path)
    if err != nil {
        return "", err
    }

    return strings.TrimRight(string(content), "\n"), err
}
```

**关键实现**：只使用 `strings.TrimRight(string(content), "\n")` 处理换行。

### 6.2 不同换行格式的处理结果

`strings.TrimRight(s, "\n")` 只会移除字符串末尾连续的 `\n`（LF）字符，对其他字符不做处理。

| 文件内容（十六进制） | 换行格式 | 处理后内容 | 说明 |
|---------------------|---------|-----------|------|
| `6d 79 6b 65 79 0a` | `mykey\n`（LF） | `mykey` | 正常，末尾 `\n` 被移除 |
| `6d 79 6b 65 79 0d 0a` | `mykey\r\n`（CRLF） | `mykey\r` | **危险！** `\r` 被保留 |
| `6d 79 6b 65 79 0d` | `mykey\r`（CR） | `mykey\r` | **危险！** `\r` 被保留 |
| `6d 79 6b 65 79 0a 0a` | `mykey\n\n`（多换行） | `mykey` | 正常，所有末尾 `\n` 被移除 |
| `6d 79 0a 6b 65 79 0a` | `my\nkey\n`（中间换行） | `my\nkey` | **危险！** 中间 `\n` 被保留 |
| `20 6d 79 6b 65 79 0a` | ` mykey\n`（前导空格） | ` mykey` | **危险！** 前导空格被保留 |
| `6d 79 6b 65 79 20 0a` | `mykey \n`（尾随空格） | `mykey ` | **危险！** 尾随空格被保留 |
| `6d 79 6b 65 79 09 0a` | `mykey\t\n`（尾随制表符） | `mykey\t` | **危险！** 尾随制表符被保留 |

### 6.3 CRLF 换行的潜在风险

**问题场景**：
1. 在 Windows 系统上编辑 secrets 文件，默认保存为 CRLF 换行
2. 文件内容：`supersecret\r\n`
3. `loadSecret()` 处理后：`supersecret\r`（保留了 `\r`）
4. 实际使用时，密码/密钥末尾多出一个 `\r` 字符
5. 导致认证失败，且错误日志不会显示实际值，难以排查

**风险等级**：高。这是一个常见的跨平台问题，特别是在 Windows 环境下生成的 secrets 文件。

### 6.4 其他空白字符的处理边界

`strings.TrimRight(content, "\n")` 只移除 `\n`，以下字符**不会被移除**：

| 字符 | 名称 | 十六进制 | 是否被移除 |
|-----|------|---------|-----------|
| `\n` | 换行 (LF) | `0x0A` | 是（仅末尾） |
| `\r` | 回车 (CR) | `0x0D` | 否 |
| `\t` | 制表符 | `0x09` | 否 |
| ` ` | 空格 | `0x20` | 否 |
| `\v` | 垂直制表符 | `0x0B` | 否 |
| `\f` | 换页符 | `0x0C` | 否 |
| `\u00A0` | 不间断空格 | `0xC2 0xA0` | 否 |

### 6.5 正确创建 Secrets 文件的方法

**推荐方式（Linux/macOS）**：
```bash
# 使用 printf，不会自动添加换行
printf 'your-secret-key-here' > /path/to/secret.txt

# 或使用 echo -n
echo -n 'your-secret-key-here' > /path/to/secret.txt

# 检查文件大小（应为密钥长度，不含换行）
wc -c /path/to/secret.txt

# 检查十六进制内容，确认没有 0d 或 0a 后缀
xxd /path/to/secret.txt
```

**不推荐的方式**：
```bash
# 避免使用普通 echo，会添加 \n（虽然 TrimRight 会处理）
echo 'your-secret-key-here' > /path/to/secret.txt

# 绝对避免在 Windows 记事本中编辑后直接使用
# 避免使用重定向时自动添加 CRLF 的编辑器
```

**Docker Secrets 注意事项**：
- Docker Secrets 默认会在文件末尾添加一个换行符 `\n`
- `loadSecret()` 会正确移除这个 `\n`
- 但如果是通过 `docker secret create` 从 Windows 主机创建，可能包含 `\r`

### 6.6 多行密钥的处理

对于包含多行的密钥（如 PEM 格式的私钥）：

```
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...
-----END PRIVATE KEY-----
```

**处理结果**：
- 中间的 `\n` 会被保留（正确）
- 末尾的 `\n` 会被移除（通常不影响 PEM 解析）
- 但如果末尾有 `\r\n`，则会变成 `\r` 结尾，可能导致解析失败

### 6.7 测试用例验证

从 `koanf_callbacks_test.go:48-82` 的测试可以确认处理行为：

```go
func TestKoanfSecretCallbackWithValidSecrets(t *testing.T) {
    // ...
    // testCreateFile 直接写入内容，不添加换行
    assert.NoError(t, testCreateFile(secretOne, "value one", 0600))
    assert.NoError(t, testCreateFile(secretTwo, "value two", 0600))
    // ...
    key, value = callback("AUTHELIA_FAKE_KEY", secretOne)
    assert.Equal(t, "value one", value)  // 期望值完全匹配
}
```

`testCreateFile` 实现（`provider_test.go:1283-1285`）：
```go
func testCreateFile(path, value string, perm os.FileMode) (err error) {
    return os.WriteFile(path, []byte(value), perm)  // 直接写入，不添加换行
}
```

---

## 7. 敏感字段脱敏处理

### 7.1 解析阶段的脱敏

**配置文件过滤器** (`koanf_provider_filtered_file.go`) 支持两种过滤器：

1. **ExpandEnvBytesFilter** - 扩展环境变量
   - 使用 `os.Expand()` 处理 `${VAR}` 或 `$VAR` 语法
   - Trace 级别日志会输出 base64 编码的内容（潜在风险！）

2. **TemplateBytesFilter** - Go 模板处理
   - 使用 `text/template` 处理配置文件
   - Trace 级别日志会输出 base64 编码的内容（潜在风险！）

**注意**：在 `koanf_provider_filtered_file.go:79-83` 和 `114-118` 中，当日志级别为 Trace 时，会输出 base64 编码的配置内容。虽然是 base64 编码，但仍然可以解码，生产环境应避免使用 Trace 级别。

### 7.2 校验阶段的脱敏

配置验证器 (`internal/configuration/validator/`) 在输出错误信息时，**不会输出敏感字段的实际值**，只会输出字段名。

例如，在 `validator/storage.go:14-17` 中：
```go
if config.EncryptionKey == "" {
    validator.Push(errors.New(errStrStorageEncryptionKeyMustBeProvided))
} else if len(config.EncryptionKey) < 20 {
    validator.Push(errors.New(errStrStorageEncryptionKeyTooShort))
}
```

错误信息只包含键名和错误描述，不包含实际值。

### 7.3 日志输出的脱敏

**全局日志脱敏**：Authelia 没有实现全局的敏感字段自动脱敏机制。日志库使用 `sirupsen/logrus`，在 `internal/logging/logger.go` 中配置。

**手动脱敏示例**：在 `handlers/util.go:82-100` 中实现了邮箱地址的手动脱敏：

```go
func redactEmail(email string) string {
    parts := strings.Split(email, "@")
    if len(parts) != 2 {
        return ""
    }
    localRunes := []rune(parts[0])
    domain := parts[1]
    if len(localRunes) <= 2 {
        return strings.Repeat("*", len(localRunes)) + "@" + domain
    }
    first := string(localRunes[0])
    last := string(localRunes[len(localRunes)-1])
    middle := strings.Repeat("*", len(localRunes)-2)
    return first + middle + last + "@" + domain
}
```

**日志级别安全建议**：
- `trace` 级别：可能包含 base64 编码的配置内容，生产环境禁用
- `debug` 级别：相对安全，但需注意自定义调试日志
- `info` 及以上：安全

### 7.4 敏感字段类型的 String() 方法

部分敏感类型实现了自定义的字符串表示，避免意外泄露：

- **PasswordDigest** (`schema/types.go:61-138`)：包装了 `algorithm.Digest`，其 `String()` 方法由底层库实现，通常返回安全的哈希格式
- **X509CertificateChain** (`schema/types.go:268-433`)：内部存储证书链，没有直接暴露敏感内容的 `String()` 方法
- **CryptographicKey**：`any` 类型，实际内容取决于具体实现

---

## 8. 配置热更新机制

### 8.1 支持热更新的组件

**只有用户数据库文件支持热更新**，在 `service/file_watcher.go` 中实现：

```go
func ProvisionUsersFileWatcher(ctx Context) (service Provider, err error) {
    config := ctx.GetConfiguration()
    providers := ctx.GetProviders()
    if config.AuthenticationBackend.File != nil && config.AuthenticationBackend.File.Watch {
        provider, ok := providers.UserProvider.(*authentication.FileUserProvider)
        // ... 创建文件监听器
    }
}
```

**热更新触发条件**：
- `authentication_backend.file.watch` 设置为 `true`
- 监听 `authentication_backend.file.path` 指定的文件
- 使用 `fsnotify/fsnotify` 库监听文件系统事件

### 8.2 热更新实现细节

在 `authentication/file_user_provider.go:55-78` 中实现了 `Reload()` 方法：

```go
func (p *FileUserProvider) Reload() (reloaded bool, err error) {
    now := time.Now()
    p.mutex.Lock()
    defer p.mutex.Unlock()

    if now.Before(p.timeoutReload) {  // 冷却时间：500ms
        return false, &errReload{err: ErrWatcherCooldown}
    }

    switch err = p.database.Load(); {
    case err == nil:
        p.setTimeoutReload(now)
    case errors.Is(err, ErrWatcherNoContent):
        return false, &errReload{err: err}
    default:
        return false, &errReload{err: fmt.Errorf("failed to reload: %w", err), critical: true}
    }

    p.setTimeoutReload(now)
    return true, nil
}
```

**热更新限制**：
- 冷却时间：500ms，防止频繁重载
- 互斥锁：确保线程安全
- 只重载用户数据库，不重载主配置

### 8.3 不支持热更新的组件

**主配置文件不支持热更新**。以下配置变更需要重启：
- 所有在 YAML 文件中的主配置
- 环境变量变更
- Secrets 文件内容变更
- 日志配置变更（SIGHUP 只能重新打开日志文件，不能修改日志级别等配置）

### 8.4 SIGHUP 信号处理

在 `service/signal.go` 中，SIGHUP 信号只用于重新打开日志文件：

```go
func ProvisionLoggingSignal(ctx Context) (service Provider, err error) {
    config := ctx.GetConfiguration()
    if config == nil || len(config.Log.FilePath) == 0 {
        return nil, nil
    }
    return &Signal{
        name:    "log-reload",
        signals: []os.Signal{syscall.SIGHUP},
        action:  logging.Reopen,  // 只重新打开日志文件
        // ...
    }, nil
}
```

---

## 9. 重启时环境变量对各模块的影响

### 9.1 配置加载时机

配置在启动时一次性加载，流程如下 (`commands/root.go:28-37`)：

```go
PreRunE: ctx.ChainRunE(
    ctx.ConfigEnsureExistsRunE,       // 确保配置文件存在
    ctx.HelperConfigLoadRunE,         // 加载配置（含环境变量和Secrets）
    ctx.LogConfigure,                 // 配置日志
    ctx.LogProcessCurrentUserRunE,
    ctx.HelperConfigValidateKeysRunE, // 验证配置键
    ctx.HelperConfigValidateRunE,     // 验证配置值
    ctx.ConfigValidateLogRunE,
),
```

### 9.2 各模块对配置变更的敏感度

| 模块 | 配置变更是否需要重启 | 相关文件 | 说明 |
|------|----------------------|----------|------|
| **Server** | 是 | `internal/server/server.go` | 监听地址、TLS 配置等需要重启才能生效 |
| **Session** | 是 | `internal/session/provider.go` | Redis 连接、Cookie 配置等 |
| **Storage** | 是 | `internal/storage/provider.go` | 数据库连接、加密密钥等 |
| **Authentication Backend** | 部分 | `internal/authentication/` | LDAP 配置需重启，文件用户库支持热更新 |
| **Notifier** | 是 | `internal/notification/notifier.go` | SMTP 配置、文件路径等 |
| **Identity Providers (OIDC)** | 是 | `internal/oidc/provider.go` | 客户端配置、密钥、签发者等 |
| **Access Control** | 是 | `internal/authorization/` | ACL 规则 |
| **Regulation** | 是 | `internal/regulation/regulator.go` | 限流配置 |
| **TOTP/WebAuthn/Duo** | 是 | `internal/otp/`, `internal/duo/` | 双因素认证配置 |
| **NTP** | 是 | `internal/ntp/ntp.go` | 时间同步配置 |
| **Telemetry** | 是 | `internal/metrics/metrics.go` | 监控配置 |
| **Logging** | 部分 | `internal/logging/logger.go` | SIGHUP 可重新打开日志文件，但级别等配置需重启 |

### 9.3 环境变量变更的影响

由于配置在启动时一次性加载，**所有环境变量变更都需要重启才能生效**，包括：

1. **普通环境变量**（`AUTHELIA_*`）：
   - 每次启动时重新读取
   - 运行时修改不会影响已启动的进程

2. **Secrets 环境变量**（`AUTHELIA_*_FILE`）：
   - 环境变量本身在启动时读取
   - 指向的文件内容也只在启动时读取
   - 即使文件内容变更，不重启也不会重新加载

### 9.4 Secrets 轮转的正确方式

由于 Secrets 文件内容只在启动时读取，密钥轮转需要：

1. **双密钥阶段**：同时支持旧密钥和新密钥
2. **更新 Secrets 文件**：写入新密钥
3. **滚动重启**：逐个重启实例
4. **移除旧密钥支持**：确认所有实例使用新密钥后，移除旧密钥支持

**注意**：对于 `storage.encryption_key` 等用于数据加密的密钥，不能简单替换，需要执行数据迁移。

---

## 10. 关键安全注意事项

### 10.1 Secrets 与其他配置源的互斥

如 `sources.go:303-310` 所示，Secrets 源在合并时会检测冲突：

```go
for _, key := range s.koanf.Keys() {
    value, ok := ko.Get(key).(string)
    if ok && value != "" {
        val.Push(fmt.Errorf(errFmtSecretAlreadyDefined, key))
    }
}
```

**最佳实践**：敏感字段只通过 Secrets 定义，不要在 YAML 文件中出现。

### 10.2 避免 Trace 级别日志

在 `koanf_provider_filtered_file.go:79-83` 中，Trace 级别会输出 base64 编码的配置内容：

```go
if f.log.Level >= logrus.TraceLevel {
    f.log.
        WithField("content", base64.RawStdEncoding.EncodeToString(out)).
        Trace("Expanded Env File Filter completed successfully")
}
```

**生产环境必须设置日志级别为 `info` 或更高**。

### 10.3 配置文件权限

配置文件（特别是包含 Secrets 的文件）应设置严格的文件权限：
- YAML 配置文件：`0600`
- Secrets 目录：`0700`
- Secrets 文件：`0400`

### 10.4 Docker Secrets 支持

Authelia 的 Secrets 机制天然支持 Docker Secrets（通常挂载在 `/run/secrets/` 下）：

```bash
AUTHELIA_STORAGE_MYSQL_PASSWORD_FILE=/run/secrets/mysql_password
AUTHELIA_SESSION_SECRET_FILE=/run/secrets/session_secret
```

### 10.5 CRLF 换行风险

如第 6 章所述，Windows 系统下的 CRLF 换行可能导致密钥末尾多出 `\r` 字符。创建 Secrets 文件时务必：
- 使用 `printf` 或 `echo -n` 避免自动添加换行
- 用 `xxd` 或 `hexdump` 验证文件内容
- 避免在 Windows 记事本中编辑 Secrets 文件

---

## 11. 完整的配置覆盖示例

### 11.1 多源配置覆盖示例

假设以下配置：

**1. 默认值** (`defaults.go:3-16`)：
```go
"regulation.max_retries": 3
```

**2. YAML 文件** (`config.yml`)：
```yaml
regulation:
  max_retries: 5
session:
  secret: "yaml_secret_here"  # 不推荐！
```

**3. 环境变量**：
```bash
AUTHELIA_REGULATION_MAX_RETRIES=7
AUTHELIA_SESSION_NAME=my_session
```

**4. Secrets 文件** (`/secrets/session_secret`)：
```
super_secret_value_from_file
```

**Secrets 环境变量**：
```bash
AUTHELIA_SESSION_SECRET_FILE=/secrets/session_secret
```

**最终生效配置**：
```go
regulation.max_retries = 7     # 环境变量覆盖了 YAML 和默认值
session.secret = "super_secret_value_from_file"  # Secrets 优先级最高
session.name = "my_session"   # 来自环境变量
```

**注意**：如果 YAML 文件中已经定义了 `session.secret`，Secrets 源会检测到冲突并报错。

---

## 12. 代码引用速查表

| 功能 | 文件位置 | 行号 |
|------|----------|------|
| 配置源加载顺序 | `internal/configuration/sources.go` | 377-393 |
| 配置合并逻辑 | `internal/configuration/provider.go` | 150-169 |
| 敏感字段识别 | `internal/configuration/helpers.go` | 92-110 |
| 敏感后缀定义 | `internal/configuration/const.go` | 80 |
| 敏感字段排除规则 | `internal/configuration/const.go` | 81-82 |
| Secrets 加载 | `internal/configuration/koanf_callbacks.go` | 37-64 |
| Secrets 冲突检测 | `internal/configuration/sources.go` | 303-313 |
| Secrets 文件读取 | `internal/configuration/helpers.go` | 112-119 |
| 环境变量转换 | `internal/configuration/koanf_callbacks.go` | 15-34 |
| 键映射生成 | `internal/configuration/helpers.go` | 10-57 |
| 配置过滤器定义 | `internal/configuration/koanf_provider_filtered_file.go` | 1-172 |
| 过滤器类型与验证 | `internal/configuration/koanf_provider_filtered_file.go` | 131-157 |
| 过滤器触发条件 | `internal/commands/root.go` | 43 |
| 过滤器加载逻辑 | `internal/commands/util.go` | 233-239 |
| 完整配置键列表 | `internal/configuration/schema/keys.go` | 10-502 |
| 用户文件热更新 | `internal/service/file_watcher.go` | 1-179 |
| 用户数据库重载 | `internal/authentication/file_user_provider.go` | 55-78 |
| SIGHUP 处理 | `internal/service/signal.go` | 1-79 |
| 配置验证入口 | `internal/configuration/validator/configuration.go` | 17-77 |
| 启动配置加载 | `internal/commands/context.go` | 437-456 |
| 过滤器帮助文档 | `internal/commands/const.go` | 910-932 |
| **内容型 TLS 配置结构 | `internal/configuration/schema/shared.go` | 8-17 |
| **路径型 Server TLS 结构 | `internal/configuration/schema/server.go` | 47-51 |
| **PostgreSQL 遗留 SSL 结构 | `internal/configuration/schema/storage.go` | 55-61 |
| **PostgreSQL SSL 路径读取 | `internal/storage/sql_provider_backend_postgres.go` | 305-351 |
| **PostgreSQL SSL key 读取 | `internal/storage/sql_provider_backend_postgres.go` | 328-348 |
| **MySQL TLS 配置处理 | `internal/storage/sql_provider_backend_mysql.go` | 35-59 |

---

## 总结

Authelia 的配置系统设计得相当安全和灵活：

1. **优先级清晰**：默认值 → 文件 → 环境变量 → Secrets，层层覆盖
2. **Secrets 安全**：通过 `_FILE` 后缀从文件读取，避免环境变量泄露
3. **冲突检测**：Secrets 与其他源的冲突会被检测并报错
4. **热更新有限**：仅支持用户数据库文件热更新，主配置变更需重启
5. **脱敏依赖开发者**：没有全局自动脱敏，需在代码中手动处理
6. **Trace 日志风险**：生产环境禁用 Trace 级别，避免配置泄露
7. **CRLF 风险**：Windows 换行可能导致密钥认证失败，需特别注意
8. **数组项限制**：包含 `[]` 的配置项（如 OIDC 客户端密钥）不支持 Secrets 加载

在将生产密钥从明文 YAML 中移除时，应：
1. 对照第 5 章的敏感字段清单，识别所有需要迁移的字段
2. 注意第 5.5 节的例外规则，某些字段不支持 Secrets 加载
3. 为每个支持的敏感字段创建 Secrets 文件
4. 按照第 6 章的指导正确创建 Secrets 文件，避免 CRLF 问题
5. 设置对应的 `AUTHELIA_*_FILE` 环境变量
6. 从 YAML 文件中删除敏感字段
7. 滚动重启所有实例
8. 验证配置是否正确加载（使用 `authelia config validate`）
