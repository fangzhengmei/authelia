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
        ├─────────────────────────────────────────┐
        │                                         │
        ▼                                         ▼
令牌签发策略构造                              JWKS 端点
├─ Strategy.JWT: jwt.DefaultStrategy          ├─ GetPublicJSONWebKeys
├─ Strategy.Core: oauth2.CoreStrategy         └─ jwk.Public() → 仅公钥
│  (由 JWTResponseAccessTokens 开关决定)
└─ Strategy.OpenID: openid.DefaultStrategy
        │
        ▼
各授权流程
├─ 授权码流程: GetKeyID (仅 ID Token)
├─ 设备授权流程: GetKeyID (仅 ID Token)
├─ 刷新令牌流程: 复用 session 中的 kid
└─ 客户端凭证流程: 直接使用客户端配置
        │
        ├─ ID Token: 始终 JWT，用 JWKS 私钥签名
        └─ Access Token: JWT (用 JWKS) 或 Opaque (用 HMAC)
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

### 4.3 CoreStrategy 构造：JWT vs Opaque Token 的总开关

**文件**: `internal/oidc/config.go:61-70`

```go
c.Strategy.JWT = &jwt.DefaultStrategy{
    Config: c,
    Issuer: issuer,
}

// 全局开关：JWTResponseAccessTokens 决定 CoreStrategy 是否支持 JWT Access Token
if config.Discovery.JWTResponseAccessTokens {
    c.Strategy.Core = oauth2.NewCoreStrategy(c, fmtAutheliaOpaqueOAuth2Token, c.Strategy.JWT)
} else {
    c.Strategy.Core = oauth2.NewCoreStrategy(c, fmtAutheliaOpaqueOAuth2Token, nil)
}

c.Strategy.OpenID = &openid.DefaultStrategy{
    Strategy: c.Strategy.JWT,
    Config:   c,
}
```

**构造逻辑说明**:

| 全局开关 `JWTResponseAccessTokens` | CoreStrategy 参数 | 能力 |
|----------------------------------|------------------|------|
| `true` | 传入 `c.Strategy.JWT` | 支持生成 JWT Access Token |
| `false` | 传入 `nil` | 只能生成 Opaque Access Token |

**常量定义**:
- `fmtAutheliaOpaqueOAuth2Token` = `"authelia_%s_"`（Opaque token 前缀）
- `fmtValueOAuth2AccessToken` = `"at"`（Access Token 类型标识）
- Opaque token 完整前缀 = `"authelia_at_"`

### 4.4 客户端级 JWT Access Token 开关

**文件**: `internal/oidc/client.go:508-510`

```go
// GetEnableJWTProfileOAuthAccessTokens 返回是否启用 RFC9068 JWT Profile Access Token
func (c *RegisteredClient) GetEnableJWTProfileOAuthAccessTokens() (enable bool) {
    return c.GetAccessTokenSignedResponseAlg() != SigningAlgNone && 
           len(c.GetAccessTokenSignedResponseKeyID()) > 0
}
```

**启用条件**（必须同时满足）:
1. `access_token_signed_response_alg` 不为 `none`（如配置为 `RS256`）
2. `access_token_signed_response_key_id` 配置了非空的 kid

### 4.5 Token 端点：两类令牌的签名路径

**文件**: `internal/handlers/handler_oauth2_token.go:15-88`

```go
func OAuth2TokenPOST(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
    session := oidc.NewSessionWithRequestedAt(ctx.GetClock().Now())

    if requester, err = ctx.Providers.OpenIDConnect.NewAccessRequest(ctx, req, session); err != nil {
        // ...
    }

    // 生成最终的令牌响应
    if responder, err = ctx.Providers.OpenIDConnect.NewAccessResponse(ctx, requester); err != nil {
        // ...
    }

    ctx.Providers.OpenIDConnect.WriteAccessResponse(ctx, rw, requester, responder)
}
```

Token 端点本身**不调用** `GetKeyID`。实际签名路径分为两类：

#### 4.5.1 ID Token 签名路径

ID Token 始终使用 `Strategy.OpenID`（`openid.DefaultStrategy`），始终是 JWT 格式：

```
Strategy.OpenID (openid.DefaultStrategy)
        │
        ├─ Strategy: c.Strategy.JWT (jwt.DefaultStrategy)
        └─ Config:   c
```

**ID Token 的 kid 来源**:
- **授权码流程**：在 `handler_oauth2_authorization.go:147` 中通过 `GetKeyID(client.GetIDTokenSignedResponseKeyID(), client.GetIDTokenSignedResponseAlg())` 选择，注入 session.Headers
- **设备授权流程**：在 `handler_oauth2_device_authorization.go:214` 中通过相同的 `GetKeyID` 选择，注入 session.Headers
- **刷新令牌流程**：从存储的 session 中读取已有的 kid，不重新调用 `GetKeyID`
- **客户端凭证流程**：不签发 ID Token（无用户身份）

#### 4.5.2 Access Token 签名路径

Access Token 使用 `Strategy.Core`（`oauth2.CoreStrategy`），可能是 JWT 或 Opaque：

```
Strategy.Core (oauth2.CoreStrategy)
        │
        ├─ 全局开关 JWTResponseAccessTokens: 是否传入了 jwtStrategy
        └─ 客户端开关 GetEnableJWTProfileOAuthAccessTokens(): 是否配置了 alg+kid
```

**Access Token 类型判断逻辑**:

| 全局开关 | 客户端开关 | Access Token 类型 | 签名密钥来源 |
|---------|-----------|------------------|-------------|
| `false` | 任意 | **Opaque Token** | HMAC-SHA256 (GlobalSecret) |
| `true` | `false` | **Opaque Token** | HMAC-SHA256 (GlobalSecret) |
| `true` | `true` | **JWT Token** | JWKS 中的私钥（通过 kid 查找） |

**Opaque Token 格式**: `authelia_at_<random_token>.<hmac_signature>`

**JWT Access Token 的 kid 来源**:
- **授权码/设备授权流程**：使用 `client.GetAccessTokenSignedResponseKeyID()` 配置的 kid（若为空则回退默认）
- **刷新令牌流程**：从存储的 session 中读取，或重新根据客户端配置选择
- **客户端凭证流程**：使用 `client.GetAccessTokenSignedResponseKeyID()` 配置的 kid

### 4.6 各授权流程的完整签名链路

#### 4.6.1 授权码流程 (Authorization Code Flow)

```
授权请求到达 (handler_oauth2_authorization.go)
    │
    ├─ GetKeyID(client.IDTokenKid, client.IDTokenAlg) → kid_idtoken
    ├─ kid_idtoken 注入 session.Headers (用于 ID Token)
    └─ session 存入存储
            │
            ▼
Token 端点 (handler_oauth2_token.go)
    │
    ├─ ID Token:
    │   └─ Strategy.OpenID → 从 session.Headers 读取 kid_idtoken
    │      └─ jwt.DefaultStrategy → 通过 kid 查找 JWKS 私钥签名
    │
    └─ Access Token:
        └─ Strategy.Core → 检查全局+客户端开关
           ├─ 开关关闭 → 生成 Opaque Token (HMAC 签名)
           └─ 开关开启 → 使用 client.AccessTokenKid
              └─ jwt.DefaultStrategy → 通过 kid 查找 JWKS 私钥签名
```

#### 4.6.2 设备授权流程 (Device Authorization Flow)

与授权码流程**完全相同**：
- 在 `handler_oauth2_device_authorization.go:214` 中调用 `GetKeyID` 选择 ID Token 的 kid
- Token 端点的签名逻辑一致

#### 4.6.3 刷新令牌流程 (Refresh Token Flow)

```
刷新令牌请求到达
    │
    ├─ 从存储读取原始 session（包含已注入的 kid_idtoken）
    │
    ├─ ID Token:
    │   └─ Strategy.OpenID → 复用 session 中的 kid_idtoken
    │      └─ 查找 JWKS 私钥签名（不调用 GetKeyID）
    │
    └─ Access Token:
        └─ Strategy.Core → 检查全局+客户端开关
           ├─ 开关关闭 → 生成新的 Opaque Token
           └─ 开关开启 → 复用或重新选择 kid
              └─ 查找 JWKS 私钥签名（不调用 GetKeyID）
```

**关键点**: 刷新令牌流程**不调用** `GetKeyID`，直接复用或重新根据配置查找密钥。

#### 4.6.4 客户端凭证流程 (Client Credentials Flow)

**文件**: `internal/oidc/util.go:284-309`

```go
func HydrateClientCredentialsFlowSessionWithAccessRequest(ctx Context, client oauthelia2.Client, session *Session) (err error) {
    InitializeSessionDefaults(session)

    session.Subject = ""
    session.ClientID = client.GetID()
    session.Claims.Subject = client.GetID()
    session.Claims.Issuer = issuer.String()
    // 注意：此处不注入任何 kid（无 ID Token）
    return nil
}
```

```
客户端凭证请求到达
    │
    ├─ HydrateClientCredentialsFlowSessionWithAccessRequest()
    │   └─ 初始化 session，不注入 kid（无 ID Token）
    │
    └─ Access Token:
        └─ Strategy.Core → 检查全局+客户端开关
           ├─ 开关关闭 → 生成 Opaque Token (HMAC 签名)
           └─ 开关开启 → 使用 client.AccessTokenKid
              └─ jwt.DefaultStrategy → 通过 kid 查找 JWKS 私钥签名
```

**关键点**:
- 不签发 ID Token（无用户身份）
- 不调用 `GetKeyID`
- Access Token 的 kid 直接来自客户端配置 `access_token_signed_response_key_id`

### 4.7 GetKeyID 解析逻辑（仅 ID Token 使用）

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
│  ├─ IssuerCertificateChain: X509Chain   (旧配置，可选)                         │
│  ├─ Discovery.JWTResponseAccessTokens: bool (全局 JWT AT 开关)                 │
│  └─ HMACSecret: string (用于 Opaque token)                                    │
│                                    ↓                                          │
│  配置解析与验证                                                               │
│  ├─ PEM 字符串 → 解析为 Go crypto 类型 (*rsa.PrivateKey / *ecdsa.PrivateKey)  │
│  ├─ HMACSecret → SHA256 哈希为 GlobalSecret                                   │
│  └─ validateOIDCIssuer()                                                     │
│     ├─ 互斥校验：不能同时配置新旧方式                                          │
│     ├─ 旧配置转换：IssuerPrivateKey → 包装为 JWK                              │
│     └─ 验证 JWK 列表                                                         │
│        ├─ 自动生成 kid (如果未配置)                                           │
│        ├─ 按 use 分类 (sig / enc)                                            │
│        └─ 收集算法信息到 Discovery                                            │
│                                    ↓                                          │
│  NewConfig(config, issuer, templates)                                         │
│  ├─ Strategy.JWT: jwt.DefaultStrategy (关联 Issuer)                          │
│  ├─ Strategy.Core: oauth2.CoreStrategy                                       │
│  │  (JWTResponseAccessTokens ? 传入 JWT Strategy : nil)                       │
│  └─ Strategy.OpenID: openid.DefaultStrategy (使用 JWT Strategy)               │
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
│  │  GetKeyID(IDTokenKid, IDTokenAlg)                │ 遍历 i.jwks.Keys     │
│  │    ↓                        │                      │ 对每个 jwk 调用 Public()│
│  │  kid 注入 session.Headers   │                      │    ↓                │
│  └──────────────────────────────┘                      │ 返回仅含公钥的 JWKS   │
│                                                          └──────────────────────┘
│  ┌─ 设备授权流程 (device auth) ──┐
│  │  session 创建点             │
│  │    ↓                        │
│  │  GetKeyID(IDTokenKid, IDTokenAlg)
│  │    ↓                        │
│  │  kid 注入 session.Headers   │
│  └──────────────────────────────┘
│
│  Token 端点 (所有流程汇聚点)
│    │
│    ├─ ID Token 签名 (Strategy.OpenID)
│    │  ├─ 从 session.Headers 读取 kid
│    │  └─ jwt.DefaultStrategy → 通过 kid 查找 JWKS 私钥签名
│    │
│    └─ Access Token 签名 (Strategy.Core)
│       ├─ 检查全局 JWTResponseAccessTokens 开关
│       ├─ 检查客户端 GetEnableJWTProfileOAuthAccessTokens()
│       ├─ 开关关闭 → 生成 Opaque Token (HMAC-SHA256, GlobalSecret)
│       └─ 开关开启 → 生成 JWT Token
│          └─ 使用 AccessTokenKid → jwt.DefaultStrategy → 查找 JWKS 私钥
│
│  ┌─ 刷新令牌流程 (refresh) ─────┐
│  │  从存储读取 session           │
│  │  不调用 GetKeyID              │
│  │  ID Token: 复用已有 kid       │
│  │  Access Token: 重新检查开关   │
│  └──────────────────────────────┘
│
│  ┌─ 客户端凭证流程 (client_creds) ─┐
│  │  HydrateClientCredentialsFlow  │
│  │  不调用 GetKeyID               │
│  │  不签发 ID Token               │
│  │  Access Token: 检查开关        │
│  └──────────────────────────────┘
│
│  返回签名后的令牌 (ID Token + Access Token)
└──────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                         客户端验证闭环                                        │
├──────────────────────────────────────────────────────────────────────────────┤
│  1. 从 /.well-known/openid-configuration 获取 jwks_uri                        │
│  2. 从 jwks_uri 下载公钥集合 (JWKS)                                           │
│  3. 接收令牌:                                                                 │
│     ├─ ID Token: 始终 JWT → 从 Header 提取 kid → 匹配 JWKS 公钥验签            │
│     ├─ JWT Access Token: 从 Header 提取 kid → 匹配 JWKS 公钥验签              │
│     └─ Opaque Access Token: 发送到 introspection 端点验证 (服务端查存储)       │
│  4. 验证通过 → 信任令牌                                                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

## 七、关键设计要点

### 7.1 密钥隔离机制

| 层级 | 密钥类型 | 访问范围 | 用途 |
|------|---------|---------|------|
| 配置文件 | 私钥 (Base64 PEM 字符串) | 管理员 | 配置签名密钥 |
| 内存 `Issuer.jwks` | 私钥 + 公钥 (Go crypto 类型: `*rsa.PrivateKey` / `*ecdsa.PrivateKey` 等) | Authelia 服务内部 | 签发 JWT 令牌时签名 |
| 内存 `GlobalSecret` | HMAC 密钥 (SHA-256 哈希) | Authelia 服务内部 | 签发 Opaque Access Token 时签名 |
| JWKS 端点响应 | 仅公钥 (JWK 格式 JSON) | 外部公开 | 客户端验证 JWT 签名 |

### 7.2 两层开关控制 Access Token 类型

| 层级 | 配置项 | 说明 |
|------|--------|------|
| 全局 | `discovery.jwt_response_access_tokens` | 控制 CoreStrategy 是否传入 JWT Strategy，决定系统是否支持 JWT Access Token |
| 客户端 | `access_token_signed_response_alg` + `access_token_signed_response_key_id` | 控制单个客户端是否使用 JWT Access Token |

**开关组合结果**:

| 全局开关 | 客户端配置 | Access Token 类型 | 签名密钥 |
|---------|-----------|------------------|---------|
| `false` | 任意 | Opaque | GlobalSecret (HMAC-SHA256) |
| `true` | alg=none 或 kid 为空 | Opaque | GlobalSecret (HMAC-SHA256) |
| `true` | alg=RS256 且 kid 已配置 | JWT | JWKS 中的对应私钥 |

### 7.3 GetKeyID 的适用范围

`GetKeyID` 仅在**创建 session 时**为 **ID Token** 选择密钥：

| 授权流程 | 是否调用 GetKeyID | kid 用途 |
|---------|------------------|---------|
| 授权码流程 | ✅ 是 | 选择 ID Token 的签名密钥 |
| 设备授权流程 | ✅ 是 | 选择 ID Token 的签名密钥 |
| 刷新令牌流程 | ❌ 否 | 复用 session 中已有的 kid |
| 客户端凭证流程 | ❌ 否 | 不签发 ID Token |

> Access Token 的密钥选择由 oauth2 库内部根据客户端配置直接处理，不经过 `GetKeyID`。

### 7.4 密钥选择优先级（ID Token）

1. **客户端指定 kid 优先**: 如果客户端配置了 `id_token_signed_response_key_id`，且能在密钥集合中找到匹配项，则使用该密钥
2. **客户端指定 alg 匹配**: 如果只配置了 `id_token_signed_response_alg`，则选择第一个匹配该算法的签名密钥
3. **默认回退**: 都不匹配时使用第一个 `use=sig` 且 `algorithm=RS256` 的密钥

### 7.5 多密钥与密钥轮换

- 支持同时配置多个签名密钥
- 每个密钥有唯一的 `kid`（自动生成或手动配置）
- 签发时使用哪个密钥取决于客户端配置和默认规则
- 所有公钥都在 JWKS 端点暴露，客户端通过 JWT Header 中的 kid 自动匹配
- 密钥轮换：添加新密钥→逐步切换签发用的密钥→旧密钥保留在 JWKS 中直到所有旧令牌过期→最后移除旧密钥

### 7.6 密钥用途区分

- `use=sig`: 用于签名（ID Token、JWT Access Token、Userinfo Response、Discovery Response 等）
- `use=enc`: 用于加密（JWE 场景，如加密的 ID Token、Userinfo Response）
- 验证时严格检查 `use` 字段，防止用签名密钥解密或用加密密钥验签
- Opaque Access Token 不使用 JWKS，使用 HMAC 密钥单独签名

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
| 客户端凭证流程 session 初始化 | `internal/oidc/util.go` | 284-309 |
| kid 注入 JWT Header | `internal/oidc/session.go` | 153-166 |
| 发现文档 jwks_uri 构造 | `internal/oidc/provider.go` | 43, 60 |
| CoreStrategy 构造（JWT/Opaque 开关） | `internal/oidc/config.go` | 61-70 |
| 客户端 JWT Access Token 开关 | `internal/oidc/client.go` | 508-510 |
| 客户端 Access Token kid/alg 获取 | `internal/oidc/client.go` | 306-323 |
| JWK Schema | `internal/configuration/schema/shared.go` | 33-39 |
| Opaque token 前缀常量 | `internal/oidc/const.go` | 26-31 |
