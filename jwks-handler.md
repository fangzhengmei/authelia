# JWKS 端点与令牌签发衔接分析

## 一、核心架构概览

```
配置文件 (jwks 数组 / issuer_private_key)
        │
        ▼
配置验证 (validateOIDCIssuer) ── 互斥校验
        │
        ▼
Issuer 结构体
├─ kid: 默认签名密钥 ID (第一个 RS256 sig 密钥)
└─ jwks: 完整 JWKS (含私钥)
        │
        ├─────────────────────────────────┐
        │                                 │
        ▼                                 ▼
令牌签发 (仅两类流程调用 GetKeyID)       JWKS 端点
├─ 授权码流程 (authorization)         ├─ GetPublicJSONWebKeys
├─ 设备授权流程 (device auth)         └─ jwk.Public() → 仅公钥
├─ 刷新令牌流程 (refresh)
└─ 客户端凭证流程 (client_credentials)
        │
        ├─ GetKeyID(kid, alg) → 仅在创建 session 时调用
        └─ oauth2 库内部签名 → 通过存储的 kid 查找私钥
```

## 二、密钥配置与初始化

### 2.1 配置定义 (`schema.JWK`)

**文件**: `internal/configuration/schema/shared.go:33-39`

```go
type JWK struct {
    KeyID            string               // 密钥 ID
    Use              string               // 用途: "sig" (签名) / "enc" (加密)
    Algorithm        string               // 算法: RS256, ES256, PS256 等
    Key              CryptographicKey     // 私钥材料 (配置时为 Base64 PEM 字符串，运行时解析为 Go crypto 类型: *rsa.PrivateKey / *ecdsa.PrivateKey 等)
    CertificateChain X509CertificateChain // 可选证书链
}
```

### 2.2 配置来源与互斥校验

**文件**: `internal/configuration/validator/identity_providers.go:315-329`

```go
func validateOIDCIssuer(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
    switch {
    // 分支 1: 新旧配置同时存在 → 报错
    case len(config.JSONWebKeys) != 0 && (config.IssuerPrivateKey != nil || config.IssuerCertificateChain.HasCertificates()):
        validator.Push(fmt.Errorf("identity_providers: oidc: option `jwks` must not be configured at the same time as 'issuer_private_key' or 'issuer_certificate_chain'"))

    // 分支 2: 仅配置了旧版 issuer_private_key → 转换为 JWK 格式
    case config.IssuerPrivateKey != nil:
        validateOIDCIssuerPrivateKey(config)
        fallthrough // 继续执行分支 3 的验证逻辑

    // 分支 3: 配置了 jwks (或从分支 2 fallthrough 而来) → 验证并收集元数据
    case len(config.JSONWebKeys) != 0:
        validateOIDCIssuerJSONWebKeys(config, validator)
        validateOIDDIssuerSigningAlgsDiscovery(config, validator)

    // 分支 4: 未配置任何密钥 → 报错
    default:
        validator.Push(errors.New(errFmtOIDCProviderNoPrivateKey))
    }
}
```

**旧配置兼容逻辑** (`validateOIDCIssuerPrivateKey`):

**文件**: `internal/configuration/validator/identity_providers.go:353-360`

```go
func validateOIDCIssuerPrivateKey(config *schema.IdentityProvidersOpenIDConnect) {
    // 将旧版私钥转换为标准 JWK 格式，插入到 JWK 列表头部
    config.JSONWebKeys = append([]schema.JWK{{
        Algorithm:        oidc.SigningAlgRSAUsingSHA256, // 固定为 RS256
        Use:              oidc.KeyUseSignature,          // 固定为 sig
        Key:              config.IssuerPrivateKey,
        CertificateChain: config.IssuerCertificateChain,
    }}, config.JSONWebKeys...)
}
```

### 2.3 JWK 列表详细验证

**文件**: `internal/configuration/validator/identity_providers.go:363-434`

```go
func validateOIDCIssuerJSONWebKeys(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
    for i := 0; i < len(config.JSONWebKeys); i++ {
        // 1. 检查密钥是否为空
        if config.JSONWebKeys[i].Key == nil { /* 报错 */ }

        // 2. 自动计算缺失的 Key ID (基于密钥指纹)
        if len(config.JSONWebKeys[i].KeyID) == 0 {
            config.JSONWebKeys[i].KeyID, _ = jwkCalculateKID(...)
        }

        // 3. 按 use 字段分类收集
        switch config.JSONWebKeys[i].Use {
        case oidc.KeyUseEncryption:
            // 收集到 ResponseObjectEncryptionKeyIDs
            config.Discovery.ResponseObjectEncryptionKeyIDs = append(...)
        default: // 包括 sig 和空值
            // 收集到 ResponseObjectSigningKeyIDs
            config.Discovery.ResponseObjectSigningKeyIDs = append(...)
        }

        // 4. 验证 kid 格式唯一性
        // 5. 验证算法与密钥类型匹配
        // 6. 验证公私钥对匹配
    }

    // 强制要求至少有一个 RS256 签名密钥 (OIDC 规范要求)
    if !utils.IsStringInSlice(oidc.SigningAlgRSAUsingSHA256, config.Discovery.ResponseObjectSigningAlgs) {
        validator.Push(fmt.Errorf("must have at least one %s signing key", oidc.SigningAlgRSAUsingSHA256))
    }
}
```

### 2.4 Issuer 初始化

**文件**: `internal/oidc/issuer.go:15-17`

```go
func NewIssuer(keys []schema.JWK) (issuer *Issuer) {
    return &Issuer{
        jwks: NewJSONWebKeySet(keys),     // 转换为 go-jose 的 JWKS (含完整私钥)
        kid:  NewIssuerDefaultKeyID(keys), // 默认密钥: 第一个 RS256 sig 密钥
    }
}
```

**默认密钥选择逻辑** (`NewIssuerDefaultKeyID`):

**文件**: `internal/oidc/issuer.go:19-29`

```go
func NewIssuerDefaultKeyID(keys []schema.JWK) (kid string) {
    for _, key := range keys {
        // 遍历所有密钥，找到第一个 use=sig 且 algorithm=RS256 的密钥
        if key.Use != KeyUseSignature || key.Algorithm != SigningAlgRSAUsingSHA256 {
            continue
        }
        return key.KeyID
    }
    return "" // 如果没有 RS256 密钥，返回空
}
```

## 三、JWKS 端点：公钥暴露

### 3.1 端点处理程序

**文件**: `internal/handlers/handler_oauth2_jwks.go:12-28`

```go
func OAuth2JSONWebKeySetGET(ctx *middlewares.AutheliaCtx) {
    if _, err = ctx.IssuerURL(); err != nil {
        ctx.ReplyStatusCode(fasthttp.StatusInternalServerError)
        return
    }

    ctx.SetContentTypeApplicationJSON()
    // 关键：只返回公钥部分
    if err = json.NewEncoder(ctx).Encode(
        ctx.Providers.OpenIDConnect.Issuer.GetPublicJSONWebKeys(ctx),
    ); err != nil {
        ctx.GetLogger().WithError(err).Error("Error occurred encoding JSON web key set")
    }
}
```

### 3.2 公钥提取逻辑

**文件**: `internal/oidc/issuer.go:89-99`

```go
func (i *Issuer) GetPublicJSONWebKeys(ctx Context) (jwks *jose.JSONWebKeySet) {
    keys := make([]jose.JSONWebKey, len(i.jwks.Keys))
    for j, jwk := range i.jwks.Keys {
        keys[j] = jwk.Public()  // 关键：调用 go-jose 的 Public() 方法剥离私钥
    }
    return &jose.JSONWebKeySet{Keys: keys}
}
```

**安全要点**:
- 内部存储的 `i.jwks` 包含完整的私钥材料（`*rsa.PrivateKey` / `*ecdsa.PrivateKey`）
- `jwk.Public()` 返回同密钥对的公钥部分（`*rsa.PublicKey` / `*ecdsa.PublicKey`）
- 序列化时公钥会被编码为 JWK 格式，仅包含 `n, e` (RSA) 或 `x, y` (EC) 参数，不包含私钥参数 `d, p, q` 等
- 外部无法获取私钥，只能获取用于验证签名的公钥

## 四、令牌签发：全流程密钥使用

### 4.1 授权码流程 (Authorization Code Flow)

**文件**: `internal/handlers/handler_oauth2_authorization.go:147`

```go
session := oidc.NewSessionWithRequester(
    ctx, issuer,
    // 选择 ID Token 的签名密钥
    ctx.Providers.OpenIDConnect.Issuer.GetKeyID(
        ctx,
        client.GetIDTokenSignedResponseKeyID(),  // 客户端指定的 kid (可选)
        client.GetIDTokenSignedResponseAlg(),    // 客户端指定的 alg (默认 RS256)
    ),
    details.Username,
    // ... 其他参数
)
```

### 4.2 设备授权流程 (Device Authorization Flow)

**文件**: `internal/handlers/handler_oauth2_device_authorization.go:214`

```go
session := oidc.NewSessionWithRequester(
    ctx, issuer,
    // 设备授权流程使用相同的密钥选择逻辑
    ctx.Providers.OpenIDConnect.Issuer.GetKeyID(
        ctx,
        client.GetIDTokenSignedResponseKeyID(),  // 同样使用 ID Token 的密钥配置
        client.GetIDTokenSignedResponseAlg(),
    ),
    details.Username,
    // ... 其他参数
)
```

> **关键点**: 设备授权流程与授权码流程使用**完全相同**的密钥选择逻辑，都是为后续签发 ID Token 做准备。

### 4.3 Token 端点：实际签发

**文件**: `internal/handlers/handler_oauth2_token.go:15-88`

```go
func OAuth2TokenPOST(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
    session := oidc.NewSessionWithRequestedAt(ctx.GetClock().Now())

    // oauth2 库内部会根据 session 中存储的 kid 查找对应的私钥进行签名
    if requester, err = ctx.Providers.OpenIDConnect.NewAccessRequest(ctx, req, session); err != nil {
        // ...
    }

    // 生成最终的令牌响应 (包含 ID Token / Access Token)
    if responder, err = ctx.Providers.OpenIDConnect.NewAccessResponse(ctx, requester); err != nil {
        // ...
    }

    ctx.Providers.OpenIDConnect.WriteAccessResponse(ctx, rw, requester, responder)
}
```

> **重要说明**: Token 端点本身**不调用** `GetKeyID`。kid 是在之前的授权流程（授权码/设备授权）中通过 `GetKeyID` 选择并注入到 session 的 JWT Header 中的。刷新令牌和客户端凭证流程复用已存储的 session 或直接使用默认密钥，不经过 `GetKeyID`。

### 4.3.1 刷新令牌流程

刷新令牌流程不经过 `GetKeyID`。oauth2 库从存储的 session 中读取之前已注入的 kid，直接用于签名。

### 4.3.2 客户端凭证流程

**文件**: `internal/oidc/util.go:284-309`

```go
func HydrateClientCredentialsFlowSessionWithAccessRequest(ctx Context, client oauthelia2.Client, session *Session) (err error) {
    InitializeSessionDefaults(session)

    session.Subject = ""
    session.ClientID = client.GetID()
    session.Claims.Subject = client.GetID()
    session.Claims.Issuer = issuer.String()
    // ...
    // 注意：此处没有设置 kid，oauth2 库会使用默认密钥签名
    return nil
}
```

客户端凭证流程也不经过 `GetKeyID`。session 初始化时不会注入特定 kid，oauth2 库会使用默认签名密钥（第一个 RS256 sig 密钥）。

### 4.4 GetKeyID 解析逻辑

**文件**: `internal/oidc/issuer.go:81-87`

```go
func (i *Issuer) GetKeyID(ctx context.Context, kid, alg string) string {
    // 优先尝试严格匹配客户端指定的 kid/alg
    if jwk, err := i.GetIssuerStrictJWK(ctx, kid, alg, KeyUseSignature); err == nil {
        return jwk.KeyID
    }
    // 匹配失败则返回默认密钥 ID (第一个 RS256 sig 密钥)
    return i.kid
}
```

### 4.5 kid 注入 JWT Header

**文件**: `internal/oidc/session.go:153-166`

```go
func (s *Session) SetValuesGeneral(ctx Context, issuer *url.URL, kid string, ...) {
    // ...
    if len(kid) != 0 {
        // 将 kid 存入 JWT Header，客户端验证时通过这个 kid 匹配公钥
        s.Headers.Extra[JWTHeaderKeyIdentifier] = kid
    }
    // ...
}
```

### 4.6 密钥搜索 (内部使用私钥)

**文件**: `internal/oidc/issuer.go:101-106`

```go
func (i *Issuer) GetIssuerJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
    return jwt.SearchJWKS(i.jwks, kid, alg, use, false)  // 宽松搜索
}

func (i *Issuer) GetIssuerStrictJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
    return jwt.SearchJWKS(i.jwks, kid, alg, use, true)   // 严格搜索
}
```

**搜索逻辑**:
- `i.jwks` 包含完整的私钥材料（Go crypto 类型：`*rsa.PrivateKey` / `*ecdsa.PrivateKey` 等）
- `jwt.SearchJWKS` 从私钥集合中按 kid + alg + use 条件查找
- 找到的密钥（含私钥）被 oauth2 库用于实际的 JWT 签名操作

## 五、发现文档与验签闭环

### 5.1 发现文档中 jwks_uri 的构造

**文件**: `internal/oidc/provider.go:38-70`

```go
// OAuth 2.0 发现文档
func (p *OpenIDConnectProvider) GetOAuth2WellKnownConfiguration(issuer string) OAuth2WellKnownConfiguration {
    options := p.discovery.OAuth2WellKnownConfiguration.Copy()
    options.Issuer = issuer
    options.JWKSURI = fmt.Sprintf("%s%s", issuer, EndpointPathJWKs)  // 拼接 jwks_uri
    // ... 其他端点
    return options
}

// OpenID Connect 发现文档
func (p *OpenIDConnectProvider) GetOpenIDConnectWellKnownConfiguration(issuer string) OpenIDConnectWellKnownConfiguration {
    options := p.discovery.Copy()
    options.Issuer = issuer
    options.JWKSURI = fmt.Sprintf("%s%s", issuer, EndpointPathJWKs)  // 同样包含 jwks_uri
    // ... 其他端点
    return options
}
```

**常量定义**:
- `EndpointPathJWKs` = `/jwks.json`

### 5.2 完整验签闭环流程

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      客户端 (Relying Party)                                      │
├─────────────────────────────────────────────────────────────────────────────────┤
│  1. 发现阶段                                                                     │
│     GET /.well-known/openid-configuration                                       │
│     ↓                                                                           │
│     解析响应，获取 jwks_uri: "https://auth.example.com/jwks.json"                │
│                                                                                 │
│  2. 预取公钥阶段                                                                 │
│     GET /jwks.json                                                              │
│     ↓                                                                           │
│     缓存 JWKS: [{kid: "rsa-1", kty: "RSA", n: "...", e: "AQAB", use: "sig"}, ...]│
│                                                                                 │
│  3. 令牌获取阶段                                                                 │
│     POST /token                                                                 │
│     ↓                                                                           │
│     收到 ID Token:                                                              │
│     Header: {"alg": "RS256", "kid": "rsa-1", "typ": "JWT"}                      │
│     Payload: {"iss": "https://auth.example.com", "sub": "...", ...}             │
│     Signature: <base64url 编码的签名值>                                          │
│                                                                                 │
│  4. 验签阶段                                                                     │
│     a) 从 JWT Header 提取 kid: "rsa-1"                                           │
│     b) 从缓存的 JWKS 中查找 kid="rsa-1" 的公钥                                   │
│     c) 使用该公钥的 RSA 公钥验证 JWT 签名                                        │
│     d) 验证通过 → 信任令牌内容                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 5.3 kid 匹配机制

**签发时** (服务端):
1. `GetKeyID()` 选择签名密钥的 kid（如 "rsa-1"）
2. kid 被写入 JWT Header (`s.Headers.Extra["kid"] = "rsa-1"`)
3. 使用对应私钥对 JWT 签名

**验证时** (客户端):
1. 从 JWT Header 读取 kid ("rsa-1")
2. 从 JWKS 端点获取的公钥列表中查找 `kid == "rsa-1"` 的条目
3. 使用找到的公钥验证签名

> **密钥轮换支持**: 服务端可以配置多个签名密钥。签发时使用其中一个，客户端通过 kid 自动匹配正确的公钥进行验证。

## 六、密钥流转关系图

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                           配置加载阶段                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│  config.IdentityProviders.OIDC                                               │
│  ├─ JSONWebKeys: []JWK              (新配置，推荐)                            │
│  │  (配置时 Key 为 Base64 PEM 字符串)                                         │
│  ├─ IssuerPrivateKey: *rsa.PrivateKey (旧配置，兼容)                           │
│  └─ IssuerCertificateChain: X509Chain   (旧配置，可选)                         │
│                                    ↓                                          │
│  配置解析与验证                                                               │
│  ├─ PEM 字符串 → 解析为 Go crypto 类型 (*rsa.PrivateKey / *ecdsa.PrivateKey)  │
│  └─ validateOIDCIssuer()                                                     │
│     ├─ 互斥校验：不能同时配置新旧方式                                          │
│     ├─ 旧配置转换：IssuerPrivateKey → 包装为 JWK                              │
│     └─ 验证 JWK 列表                                                         │
│        ├─ 自动生成 kid (如果未配置)                                           │
│        ├─ 按 use 分类 (sig / enc)                                            │
│        └─ 收集算法信息到 Discovery                                            │
│                                    ↓                                          │
│  NewIssuer(keys)                                                             │
│  ├─ jwks: NewJSONWebKeySet(keys)  → 内存私钥集合 (*jose.JSONWebKeySet)        │
│  └─ kid:  NewIssuerDefaultKeyID(keys) → 默认 RS256 签名密钥 ID                │
└──────────────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┴─────────────────────────┐
          ▼                                                   ▼
┌──────────────────────────┐                      ┌──────────────────────────┐
│      令牌签发路径         │                      │      JWKS 端点路径        │
├──────────────────────────┤                      ├──────────────────────────┤
│                                                          │ GET /jwks.json      │
│  ┌─ 授权码流程 (authorization) ──┐                      │    ↓                │
│  │  session 创建点             │                      │ GetPublicJSONWebKeys()│
│  │    ↓                        │                      │    ↓                │
│  │  GetKeyID(kid, alg)         │                      │ 遍历 i.jwks.Keys     │
│  │    ↓                        │                      │ 对每个 jwk 调用 Public()│
│  │  kid 注入 JWT Header        │                      │    ↓                │
│  └──────────────────────────────┘                      │ 返回仅含公钥的 JWKS   │
│                                                          └──────────────────────┘
│  ┌─ 设备授权流程 (device auth) ──┐
│  │  session 创建点             │
│  │    ↓                        │
│  │  GetKeyID(kid, alg)         │
│  │    ↓                        │
│  │  kid 注入 JWT Header        │
│  └──────────────────────────────┘
│
│  ┌─ 刷新令牌流程 (refresh) ─────┐
│  │  不调用 GetKeyID             │
│  │  复用 session 中已有的 kid   │
│  └──────────────────────────────┘
│
│  ┌─ 客户端凭证流程 (client_creds) ─┐
│  │  不调用 GetKeyID                 │
│  │  不注入特定 kid                  │
│  │  oauth2 库使用默认密钥签名       │
│  └──────────────────────────────┘
│
│  Token 端点
│    ↓
│  oauth2 库签名 JWT
│  (通过 session 中的 kid 查找私钥)
│    ↓
│  返回签名后的令牌
└──────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         客户端验证闭环                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│  1. 从 /.well-known/openid-configuration 获取 jwks_uri                        │
│  2. 从 jwks_uri 下载公钥集合 (JWKS)                                           │
│  3. 接收 JWT，从 Header 提取 kid                                              │
│  4. 用 kid 在 JWKS 中查找对应公钥                                             │
│  5. 用公钥验证 JWT 签名                                                       │
│  6. 验证通过 → 信任令牌                                                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 七、关键设计要点

### 7.1 密钥隔离机制

| 层级 | 密钥类型 | 访问范围 | 用途 |
|------|---------|---------|------|
| 配置文件 | 私钥 (Base64 PEM 字符串) | 管理员 | 配置签名密钥 |
| 内存 `Issuer.jwks` | 私钥 + 公钥 (Go crypto 类型: `*rsa.PrivateKey` / `*ecdsa.PrivateKey` 等) | Authelia 服务内部 | 签发令牌时签名 |
| JWKS 端点响应 | 仅公钥 (JWK 格式 JSON) | 外部公开 | 客户端验证签名 |

### 7.2 密钥选择优先级

1. **客户端指定 kid 优先**: 如果客户端配置了 `id_token_signed_response_key_id`，且能在密钥集合中找到匹配项，则使用该密钥
2. **客户端指定 alg 匹配**: 如果只配置了 `id_token_signed_response_alg`，则选择第一个匹配该算法的签名密钥
3. **默认回退**: 都不匹配时使用第一个 `use=sig` 且 `algorithm=RS256` 的密钥

### 7.3 多密钥与密钥轮换

- 支持同时配置多个签名密钥
- 每个密钥有唯一的 `kid`（自动生成或手动配置）
- 签发时使用哪个密钥取决于客户端配置和默认规则
- 所有公钥都在 JWKS 端点暴露，客户端通过 JWT Header 中的 kid 自动匹配
- 密钥轮换：添加新密钥→逐步切换签发用的密钥→旧密钥保留在 JWKS 中直到所有旧令牌过期→最后移除旧密钥

### 7.4 密钥用途区分

- `use=sig`: 用于签名（ID Token、Userinfo Response、Discovery Response 等）
- `use=enc`: 用于加密（JWE 场景，如加密的 ID Token、Userinfo Response）
- 验证时严格检查 `use` 字段，防止用签名密钥解密或用加密密钥验签

## 八、代码引用路径

| 功能 | 文件 | 行号 |
|------|------|------|
| JWKS 端点处理 | `internal/handlers/handler_oauth2_jwks.go` | 12-28 |
| Issuer 定义 | `internal/oidc/issuer.go` | 75-107 |
| 公钥提取 | `internal/oidc/issuer.go` | 89-99 |
| 密钥搜索 | `internal/oidc/issuer.go` | 101-106 |
| GetKeyID 逻辑 | `internal/oidc/issuer.go` | 81-87 |
| 默认密钥选择 | `internal/oidc/issuer.go` | 19-29 |
| 配置互斥校验 | `internal/configuration/validator/identity_providers.go` | 315-329 |
| 旧配置转换 | `internal/configuration/validator/identity_providers.go` | 353-360 |
| JWK 列表验证 | `internal/configuration/validator/identity_providers.go` | 363-434 |
| 授权码流程密钥选择 | `internal/handlers/handler_oauth2_authorization.go` | 147 |
| 设备授权流程密钥选择 | `internal/handlers/handler_oauth2_device_authorization.go` | 214 |
| Token 端点签发 | `internal/handlers/handler_oauth2_token.go` | 15-88 |
| kid 注入 JWT Header | `internal/oidc/session.go` | 153-166 |
| 发现文档 jwks_uri 构造 | `internal/oidc/provider.go` | 43, 60 |
| JWK Schema | `internal/configuration/schema/shared.go` | 33-39 |
