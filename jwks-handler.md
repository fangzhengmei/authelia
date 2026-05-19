# JWKS 端点与令牌签发衔接分析

## 一、核心架构概览

```
配置文件 (jwks 数组)
        │
        ▼
配置验证 (validateOIDCIssuerJSONWebKeys)
        │
        ▼
Issuer 结构体
├─ kid: 默认签名密钥 ID
└─ jwks: 完整 JWKS (含私钥)
        │
        ├─────────────────────────────────┐
        │                                 │
        ▼                                 ▼
令牌签发 (GetKeyID → GetIssuerJWK)    JWKS 端点 (GetPublicJSONWebKeys)
        │                                 │
        ▼                                 ▼
使用私钥签名令牌                      仅暴露公钥给外部
```

## 二、密钥配置与初始化

### 2.1 配置定义 (`schema.JWK`)

**文件**: `internal/configuration/schema/shared.go:33-39`

```go
type JWK struct {
    KeyID            string               // 密钥 ID
    Use              string               // 用途: "sig" (签名) / "enc" (加密)
    Algorithm        string               // 算法: RS256, ES256 等
    Key              CryptographicKey     // 私钥材料
    CertificateChain X509CertificateChain // 可选证书链
}
```

### 2.2 配置来源与验证

**文件**: `internal/configuration/validator/identity_providers.go:315-329`

```go
func validateOIDCIssuer(config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
    switch {
    case len(config.JSONWebKeys) != 0:
        validateOIDCIssuerJSONWebKeys(config, validator)  // 验证 JWK 列表
        validateOIDDIssuerSigningAlgsDiscovery(config, validator)
    case config.IssuerPrivateKey != nil:
        validateOIDCIssuerPrivateKey(config)  // 兼容旧配置，转换为 JWK
        fallthrough
    default:
        validator.Push(errors.New("no private key configured"))
    }
}
```

**关键验证逻辑** (`validateOIDCIssuerJSONWebKeys`):
- 检查密钥是否为空
- 自动计算缺失的 Key ID（基于密钥指纹）
- 验证 use 字段必须是 "sig" 或 "enc"
- 收集签名密钥 ID 到 `Discovery.ResponseObjectSigningKeyIDs`
- 收集加密密钥 ID 到 `Discovery.ResponseObjectEncryptionKeyIDs`

### 2.3 Issuer 初始化

**文件**: `internal/oidc/issuer.go:15-17`

```go
func NewIssuer(keys []schema.JWK) (issuer *Issuer) {
    return &Issuer{
        jwks: NewJSONWebKeySet(keys),     // 转换为 go-jose 的 JWKS (含私钥)
        kid:  NewIssuerDefaultKeyID(keys), // 默认密钥: 第一个 RS256 sig 密钥
    }
}
```

**默认密钥选择逻辑** (`NewIssuerDefaultKeyID`):
- 遍历所有密钥，找到第一个 `use=sig` 且 `algorithm=RS256` 的密钥
- 返回其 Key ID 作为默认签名密钥

## 三、JWKS 端点：公钥暴露

### 3.1 端点处理程序

**文件**: `internal/handlers/handler_oauth2_jwks.go:12-28`

```go
func OAuth2JSONWebKeySetGET(ctx *middlewares.AutheliaCtx) {
    // ...
    ctx.SetContentTypeApplicationJSON()
    if err = json.NewEncoder(ctx).Encode(
        ctx.Providers.OpenIDConnect.Issuer.GetPublicJSONWebKeys(ctx),
    ); err != nil {
        // ...
    }
}
```

### 3.2 公钥提取逻辑

**文件**: `internal/oidc/issuer.go:89-99`

```go
func (i *Issuer) GetPublicJSONWebKeys(ctx Context) (jwks *jose.JSONWebKeySet) {
    keys := make([]jose.JSONWebKey, len(i.jwks.Keys))
    for j, jwk := range i.jwks.Keys {
        keys[j] = jwk.Public()  // 关键：只提取公钥部分
    }
    return &jose.JSONWebKeySet{Keys: keys}
}
```

**安全要点**:
- 内部存储的 `i.jwks` 包含完整的私钥材料
- 通过 `jwk.Public()` 方法剥离私钥，仅返回公钥
- 外部无法获取私钥，只能获取用于验证签名的公钥

## 四、令牌签发：密钥使用

### 4.1 签发时的密钥选择

**文件**: `internal/handlers/handler_oauth2_authorization.go:147`

```go
session := oidc.NewSessionWithRequester(
    ctx, issuer,
    ctx.Providers.OpenIDConnect.Issuer.GetKeyID(
        ctx,
        client.GetIDTokenSignedResponseKeyID(),  // 客户端指定的 kid
        client.GetIDTokenSignedResponseAlg(),    // 客户端指定的 alg
    ),
    // ... 其他参数
)
```

### 4.2 GetKeyID 解析逻辑

**文件**: `internal/oidc/issuer.go:81-87`

```go
func (i *Issuer) GetKeyID(ctx context.Context, kid, alg string) string {
    // 优先尝试严格匹配客户端指定的 kid/alg
    if jwk, err := i.GetIssuerStrictJWK(ctx, kid, alg, KeyUseSignature); err == nil {
        return jwk.KeyID
    }
    // 匹配失败则返回默认密钥 ID
    return i.kid
}
```

### 4.3 密钥搜索 (内部使用私钥)

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
- `i.jwks` 包含完整的私钥材料
- `jwt.SearchJWKS` 从私钥集合中查找匹配的密钥
- 找到的密钥（含私钥）用于实际的 JWT 签名操作

## 五、密钥流转关系图

```
┌─────────────────────────────────────────────────────────────────┐
│                     配置加载阶段                                  │
├─────────────────────────────────────────────────────────────────┤
│  config.IdentityProviders.OIDC.JSONWebKeys                      │
│  (用户配置的私钥列表)                                            │
│                           ↓                                      │
│  validateOIDCIssuerJSONWebKeys()                                │
│  (验证密钥、自动生成 kid)                                        │
│                           ↓                                      │
│  NewIssuer(keys)                                                │
│  ├─ jwks: NewJSONWebKeySet(keys)  → 内存中的私钥集合            │
│  └─ kid:  默认签名密钥 ID                                       │
└─────────────────────────────────────────────────────────────────┘
                           │
         ┌─────────────────┴─────────────────┐
         ▼                                   ▼
┌──────────────────────┐          ┌──────────────────────┐
│   令牌签发路径        │          │    JWKS 端点路径      │
├──────────────────────┤          ├──────────────────────┤
│ 授权请求到达          │          │ GET /jwks.json       │
│    ↓                 │          │    ↓                 │
│ GetKeyID(kid, alg)   │          │ GetPublicJSONWebKeys │
│    ↓                 │          │    ↓                 │
│ GetIssuerJWK()       │          │ jwk.Public()         │
│  (获取私钥)           │          │  (剥离私钥)          │
│    ↓                 │          │    ↓                 │
│ JWT 签名 (用私钥)     │          │ 返回公钥给客户端      │
│    ↓                 │          └──────────────────────┘
│ 返回签名后的令牌      │
└──────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  客户端验证令牌                                      │
│  1. 从 JWKS 端点获取公钥                             │
│  2. 用公钥验证 JWT 签名                              │
│  3. 验证通过则信任令牌                               │
└──────────────────────────────────────────────────────┘
```

## 六、关键设计要点

### 6.1 密钥隔离机制

| 层级 | 密钥类型 | 访问范围 | 用途 |
|------|---------|---------|------|
| 内部内存 | 私钥 + 公钥 | Authelia 服务内部 | 签发令牌时签名 |
| JWKS 端点 | 仅公钥 | 外部公开 | 客户端验证签名 |

### 6.2 密钥选择优先级

1. **客户端指定优先**: 如果客户端配置了 `id_token_signed_response_key_id`，优先尝试匹配
2. **算法匹配**: 匹配 `id_token_signed_response_alg` 指定的算法
3. **默认回退**: 都不匹配时使用第一个 RS256 签名密钥

### 6.3 多密钥支持

- 支持同时配置多个签名密钥（用于密钥轮换）
- 每个密钥有唯一的 `kid`
- 客户端通过 `kid` 识别使用哪个公钥验证
- JWKS 端点返回所有公钥，客户端自行匹配

### 6.4 密钥用途区分

- `use=sig`: 用于签名（ID Token、Access Token 等）
- `use=enc`: 用于加密（JWE 场景）
- 验证时严格检查 `use` 字段，防止密钥误用

## 七、代码引用路径

| 功能 | 文件 | 行号 |
|------|------|------|
| JWKS 端点处理 | `internal/handlers/handler_oauth2_jwks.go` | 12-28 |
| Issuer 定义 | `internal/oidc/issuer.go` | 75-107 |
| 公钥提取 | `internal/oidc/issuer.go` | 89-99 |
| 密钥搜索 | `internal/oidc/issuer.go` | 101-106 |
| 配置验证 | `internal/configuration/validator/identity_providers.go` | 315-430 |
| 签发时密钥选择 | `internal/handlers/handler_oauth2_authorization.go` | 147 |
| JWK Schema | `internal/configuration/schema/shared.go` | 33-39 |
