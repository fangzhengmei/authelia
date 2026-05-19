# JWKS 端点与令牌签发衔接分析

## 一、架构核心角色与代码证据

### 1.1 三层 Strategy 构造

**文件**: `internal/oidc/config.go:61-75`

```go
c.Strategy.JWT = &jwt.DefaultStrategy{
    Config: c,
    Issuer: issuer,
}

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

**证据要点：
- `Strategy.JWT`: `jwt.DefaultStrategy，关联 Issuer（含私钥的 JWKS）
- `Strategy.Core`: `oauth2.CoreStrategy，根据全局开关决定是否传入 JWT Strategy
- `Strategy.OpenID`: `openid.DefaultStrategy，始终使用 JWT Strategy

### 1.2 全局开关

| 配置项 | 值 | CoreStrategy 构造参数 |
|--------|-----|----------------------|
| `config.Discovery.JWTResponseAccessTokens | `true` | 传入 `c.Strategy.JWT` |
| `config.Discovery.JWTResponseAccessTokens | `false` | 传入 `nil` |

### 1.3 客户端开关

**文件**: `internal/oidc/client.go:506-510`

```go
func (c *RegisteredClient) GetEnableJWTProfileOAuthAccessTokens() (enable bool) {
    return c.GetAccessTokenSignedResponseAlg() != SigningAlgNone && 
           len(c.GetAccessTokenSignedResponseKeyID()) > 0
}
```

**启用条件**（必须同时满足）:
1. `access_token_signed_response_alg` 不为 `none`
2. `access_token_signed_response_key_id` 非空

### 1.4 各 Grant Handler 使用的 Strategy

**文件**: `internal/oidc/config.go:255-380`

所有授权流程的 `AccessTokenStrategy` 统一使用 `c.Strategy.Core`:

| Grant Handler | AccessTokenStrategy |
|---------------|---------------------|
| AuthorizeExplicitGrantHandler | `c.Strategy.Core` |
| AuthorizeImplicitGrantTypeHandler | `c.Strategy.Core` |
| ClientCredentialsGrantHandler | `c.Strategy.Core` |
| RefreshTokenGrantHandler | `c.Strategy.Core` |
| DeviceAuthorizeHandler | `c.Strategy.Core` |

## 二、密钥配置与初始化

### 2.1 配置定义

**文件**: `internal/configuration/schema/shared.go:33-39`

```go
type JWK struct {
    KeyID            string               // 密钥 ID
    Use              string               // 用途: "sig" / "enc"
    Algorithm        string               // 算法: RS256, ES256 等
    Key              CryptographicKey     // 私钥材料
    CertificateChain X509CertificateChain // 可选证书链
}
```

### 2.2 配置来源与互斥校验

**文件**: `internal/configuration/validator/identity_providers.go:315-329`

```go
func validateOIDCIssuer(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
    switch {
    case len(config.JSONWebKeys) != 0 && (config.IssuerPrivateKey != nil || config.IssuerCertificateChain.HasCertificates()):
        validator.Push(fmt.Errorf("identity_providers: oidc: option `jwks` must not be configured at the same time as 'issuer_private_key' or 'issuer_certificate_chain'"))
    case config.IssuerPrivateKey != nil:
        validateOIDCIssuerPrivateKey(config)
        fallthrough
    case len(config.JSONWebKeys) != 0:
        validateOIDCIssuerJSONWebKeys(config, validator)
        validateOIDDIssuerSigningAlgsDiscovery(config, validator)
    default:
        validator.Push(errors.New(errFmtOIDCProviderNoPrivateKey))
    }
}
```

### 2.3 旧配置兼容

**文件**: `internal/configuration/validator/identity_providers.go:353-360`

```go
func validateOIDCIssuerPrivateKey(config *schema.IdentityProvidersOpenIDConnect) {
    config.JSONWebKeys = append([]schema.JWK{{
        Algorithm:        oidc.SigningAlgRSAUsingSHA256,
        Use:              oidc.KeyUseSignature,
        Key:              config.IssuerPrivateKey,
        CertificateChain: config.IssuerCertificateChain,
    }}, config.JSONWebKeys...)
}
```

### 2.4 JWK 列表验证

**文件**: `internal/configuration/validator/identity_providers.go:363-434`

验证内容包括：
- 密钥非空检查
- 自动计算缺失的 Key ID（基于密钥指纹）
- 按 use 分类收集（sig / enc）
- kid 格式唯一性验证
- 算法与密钥类型匹配验证
- 公私钥对匹配验证
- 强制要求至少有一个 RS256 签名密钥

### 2.5 Issuer 初始化

**文件**: `internal/oidc/issuer.go:15-17`

```go
func NewIssuer(keys []schema.JWK) (issuer *Issuer) {
    return &Issuer{
        jwks: NewJSONWebKeySet(keys),
        kid:  NewIssuerDefaultKeyID(keys),
    }
}
```

**默认密钥选择** (`internal/oidc/issuer.go:19-29`):

```go
func NewIssuerDefaultKeyID(keys []schema.JWK) (kid string) {
    for _, key := range keys {
        if key.Use != KeyUseSignature || key.Algorithm != SigningAlgRSAUsingSHA256 {
            continue
        }
        return key.KeyID
    }
    return ""
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
        keys[j] = jwk.Public()
    }
    return &jose.JSONWebKeySet{Keys: keys}
}
```

## 四、令牌签发：各流程的密钥使用

### 4.1 授权码流程

**文件**: `internal/handlers/handler_oauth2_authorization.go:147`

```go
session := oidc.NewSessionWithRequester(
    ctx, issuer,
    ctx.Providers.OpenIDConnect.Issuer.GetKeyID(
        ctx,
        client.GetIDTokenSignedResponseKeyID(),
        client.GetIDTokenSignedResponseAlg(),
    ),
    details.Username,
    // ...
)
```

**GetKeyID 逻辑** (`internal/oidc/issuer.go:81-87`):

```go
func (i *Issuer) GetKeyID(ctx context.Context, kid, alg string) string {
    if jwk, err := i.GetIssuerStrictJWK(ctx, kid, alg, KeyUseSignature); err == nil {
        return jwk.KeyID
    }
    return i.kid
}
```

### 4.2 设备授权流程

**文件**: `internal/handlers/handler_oauth2_device_authorization.go:214`

```go
session := oidc.NewSessionWithRequester(
    ctx, issuer,
    ctx.Providers.OpenIDConnect.Issuer.GetKeyID(
        ctx,
        client.GetIDTokenSignedResponseKeyID(),
        client.GetIDTokenSignedResponseAlg(),
    ),
    details.Username,
    // ...
)
```

### 4.3 kid 注入 JWT Header

**文件**: `internal/oidc/session.go:153-166`

```go
func (s *Session) SetValuesGeneral(ctx Context, issuer *url.URL, kid string, ...) {
    // ...
    if len(kid) != 0 {
        s.Headers.Extra[JWTHeaderKeyIdentifier] = kid
    }
    // ...
}
```

### 4.4 Token 端点：统一签发入口

**文件**: `internal/handlers/handler_oauth2_token.go:15-88`

```go
func OAuth2TokenPOST(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
    session := oidc.NewSessionWithRequestedAt(ctx.GetClock().Now())

    if requester, err = ctx.Providers.OpenIDConnect.NewAccessRequest(ctx, req, session); err != nil {
        // ...
    }

    // Token 端点本身不调用 GetKeyID
    // 实际签名由 oauth2 库内部根据 Strategy 完成
    if responder, err = ctx.Providers.OpenIDConnect.NewAccessResponse(ctx, requester); err != nil {
        // ...
    }

    ctx.Providers.OpenIDConnect.WriteAccessResponse(ctx, rw, requester, responder)
}
```

### 4.5 Token 端点 Hydration 逻辑

**文件**: `internal/handlers/handler_oauth2_token.go:90-171`

```go
func handleOAuth2TokenHydration(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, requester oauthelia2.AccessRequester, client oidc.Client, session *oidc.Session) (handled bool) {
    // 客户端凭证流程
    if requester.GetGrantTypes().ExactOne(oidc.GrantTypeClientCredentials) {
        if err = oidc.HydrateClientCredentialsFlowSessionWithAccessRequest(ctx, client, session); err != nil {
            // ...
        }
        // ...
        return false
    }

    // JWT Access Token 声明填充
    if client.GetEnableJWTProfileOAuthAccessTokens() {
        // 填充 AccessToken claims 到 session.AccessToken.Claims
        // ...
    }

    return false
}
```

### 4.6 客户端凭证流程 Session 初始化

**文件**: `internal/oidc/util.go:284-309`

```go
func HydrateClientCredentialsFlowSessionWithAccessRequest(ctx Context, client oauthelia2.Client, session *Session) (err error) {
    InitializeSessionDefaults(session)

    session.Subject = ""
    session.ClientID = client.GetID()
    session.Claims.Subject = client.GetID()
    session.Claims.Issuer = issuer.String()
    // 不注入 kid（无 ID Token）
    return nil
}
```

### 4.7 密钥搜索

**文件**: `internal/oidc/issuer.go:101-106`

```go
func (i *Issuer) GetIssuerJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
    return jwt.SearchJWKS(i.jwks, kid, alg, use, false)
}

func (i *Issuer) GetIssuerStrictJWK(ctx context.Context, kid, alg, use string) (jwk *jose.JSONWebKey, err error) {
    return jwt.SearchJWKS(i.jwks, kid, alg, use, true)
}
```

## 五、Access Token 生成与校验路径

### 5.1 Opaque Access Token 格式

**文件**: `internal/oidc/const.go:26-31`

```go
fmtAutheliaOpaqueOAuth2Token = "authelia_%s_"
fmtValueOAuth2AccessToken    = "at"
```

Opaque token 前缀: `authelia_at_`

### 5.2 Access Token 校验路径

**文件**: `internal/oidc/util.go:373-422`

```go
func IsAccessToken(ctx Context, value string) (is bool, err error) {
    // 检查 BearerAuthorization 开关
    if config.IdentityProviders.OIDC == nil || !config.IdentityProviders.OIDC.Discovery.BearerAuthorization {
        return false, nil
    }

    // 路径 1: Opaque Token 校验
    if strings.HasPrefix(value, "authelia_at_") && strings.Count(value, ".") == 1 {
        return true, nil
    }

    // 路径 2: JWT Token 校验
    if !IsMaybeSignedJWT(value) { // 检查是否有 2 个点
        return false, nil
    }

    // 解析 JWT（不验证签名）
    if token, _, err = jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(value, &jwt.RegisteredClaims{}); err != nil {
        return false, err
    }

    // 检查是否为 JWT Profile Access Token
    if !IsJWTProfileAccessToken(token.Header) {
        return false, fmt.Errorf("the token is not a JWT profile access token")
    }

    // 检查 issuer
    if iss, err = token.Claims.GetIssuer(); err != nil {
        return false, err
    }

    if strings.EqualFold(iss, issuer.String()) {
        return true, nil
    }

    return false, fmt.Errorf("the token issuer '%s' does not match the expected '%s'", iss, issuer)
}
```

**校验路径证据：

| Token 类型 | 判断条件 | 校验方式 |
|-----------|---------|----------|
| Opaque | 前缀 `authelia_at_` + 1 个点 | 格式检查（不验证签名，由存储校验） |
| JWT | 2 个点 + JWT Profile Header + issuer 匹配 | 解析验证（签名由调用方验证） |

### 5.3 发现文档与 jwks_uri

**文件**: `internal/oidc/provider.go:38-70`

```go
func (p *OpenIDConnectProvider) GetOAuth2WellKnownConfiguration(issuer string) OAuth2WellKnownConfiguration {
    options := p.discovery.OAuth2WellKnownConfiguration.Copy()
    options.Issuer = issuer
    options.JWKSURI = fmt.Sprintf("%s%s", issuer, EndpointPathJWKs)
    // ...
    return options
}

func (p *OpenIDConnectProvider) GetOpenIDConnectWellKnownConfiguration(issuer string) OpenIDConnectWellKnownConfiguration {
    options := p.discovery.Copy()
    options.Issuer = issuer
    options.JWKSURI = fmt.Sprintf("%s%s", issuer, EndpointPathJWKs)
    // ...
    return options
}
```

## 六、密钥流转关系（可证明部分）

```
配置文件
    │
    ▼
配置解析与验证
    ├─ PEM 字符串 → Go crypto 类型
    └─ validateOIDCIssuer()
    │
    ▼
NewIssuer(keys)
    ├─ jwks: 内存私钥集合
    └─ kid:  默认 RS256 签名密钥 ID
    │
    ▼
NewConfig(config, issuer, templates)
    ├─ Strategy.JWT: jwt.DefaultStrategy (关联 Issuer)
    ├─ Strategy.Core: oauth2.CoreStrategy
    │  (JWTResponseAccessTokens ? 传入 JWT Strategy : nil)
    └─ Strategy.OpenID: openid.DefaultStrategy (使用 JWT Strategy)
    │
    ▼
各授权流程
    ├─ 授权码流程: GetKeyID (ID Token)
    ├─ 设备授权流程: GetKeyID (ID Token)
    ├─ 刷新令牌流程: 从存储读取 session
    └─ 客户端凭证流程: HydrateClientCredentialsFlowSession
    │
    ▼
Token 端点 (统一签发)
    ├─ ID Token: Strategy.OpenID → jwt.DefaultStrategy
    └─ Access Token: Strategy.Core → oauth2.CoreStrategy
    │
    ▼
JWKS 端点
    └─ GetPublicJSONWebKeys() → 仅公钥
```

## 七、关键设计要点

### 7.1 密钥隔离机制

| 层级 | 密钥类型 | 访问范围 | 用途 |
|------|---------|---------|------|
| 配置文件 | 私钥 (Base64 PEM 字符串) | 管理员 | 配置签名密钥 |
| 内存 `Issuer.jwks` | 私钥 + 公钥 (Go crypto 类型) | Authelia 服务内部 | 签发 JWT 时签名 |
| 内存 `GlobalSecret` | HMAC 密钥 (SHA-256 哈希) | Authelia 服务内部 | 签发 Opaque Access Token 时签名 |
| JWKS 端点响应 | 仅公钥 (JWK 格式 JSON) | 外部公开 | 客户端验证 JWT 签名 |

### 7.2 两层开关配置

| 层级 | 配置项 | 代码证据 |
|------|--------|----------|
| 全局 | `discovery.jwt_response_access_tokens` | `config.go:66-70` 决定是否传入 JWT Strategy 给 CoreStrategy |
| 客户端 | `access_token_signed_response_alg` + `access_token_signed_response_key_id` | `client.go:508-510` 决定 `GetEnableJWTProfileOAuthAccessTokens()` |

### 7.3 GetKeyID 调用点

| 授权流程 | 是否调用 GetKeyID | 代码位置 |
|---------|------------------|----------|
| 授权码流程 | ✅ 是 | `handler_oauth2_authorization.go:147` |
| 设备授权流程 | ✅ 是 | `handler_oauth2_device_authorization.go:214` |
| 刷新令牌流程 | ❌ 否 | 无调用点 |
| 客户端凭证流程 | ❌ 否 | 无调用点 |

> GetKeyID 仅用于为 ID Token 选择签名密钥，注入 session.Headers。

### 7.4 密钥选择优先级（ID Token）

1. 客户端指定 kid 优先: `id_token_signed_response_key_id`
2. 客户端指定 alg 匹配: `id_token_signed_response_alg`
3. 默认回退: 第一个 `use=sig` 且 `algorithm=RS256` 的密钥

### 7.5 密钥用途区分

- `use=sig`: 用于签名（ID Token、JWT Access Token 等）
- `use=enc`: 用于加密（JWE 场景）
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
| Token 端点 Hydration | `internal/handlers/handler_oauth2_token.go` | 90-171 |
| 客户端凭证流程 session 初始化 | `internal/oidc/util.go` | 284-309 |
| kid 注入 JWT Header | `internal/oidc/session.go` | 153-166 |
| Access Token 校验 | `internal/oidc/util.go` | 373-422 |
| 发现文档 jwks_uri 构造 | `internal/oidc/provider.go` | 43, 60 |
| CoreStrategy 构造 | `internal/oidc/config.go` | 61-75 |
| 客户端 JWT Access Token 开关 | `internal/oidc/client.go` | 506-510 |
| JWK Schema | `internal/configuration/schema/shared.go` | 33-39 |
| Opaque token 前缀常量 | `internal/oidc/const.go` | 26-31 |
| 各 Grant Handler Strategy 配置 | `internal/oidc/config.go` | 255-380 |
