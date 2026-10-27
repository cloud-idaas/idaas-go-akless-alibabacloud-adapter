# idaas-go-akless-alibabacloud-adapter

[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Development Status](https://img.shields.io/badge/status-Beta-orange)](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter)

[English](README.md) | 简体中文

IDaaS（身份即服务）Akless 阿里云适配器 Go SDK —— 通过 IDaaS PAM（特权访问管理）获取阿里云 STS 临时凭证，实现应用无 AK 接入阿里云服务。

## 工作原理

```
┌──────────┐    OIDC Token    ┌──────────────┐  阿里云 STS 凭证  ┌─────────────┐
│  IDaaS   │ ──────────────►  │  PAM          │ ─────────────────► │  阿里云    │
│  Core    │                  │  Developer    │   (AccessKeyId,    │  云服务    │
│  SDK     │                  │  API          │    AccessKeySecret,│ (OSS/SLS等)│
└──────────┘                  └──────────────┘    SecurityToken) └─────────────┘
```

1. IDaaS Core SDK 通过机器到机器认证获取 **OIDC Token**（AccessToken）
2. 本适配器用 OIDC Token 调用 **PAM Developer API** 获取阿里云 STS 临时凭证
3. 临时凭证用于访问**阿里云服务**（OSS V1/V2、SLS 及任何消费 `credentials-go` 的服务）
4. 凭证**自动缓存与刷新**——2/3 寿命点后台预取（不阻塞业务请求）、4/5 寿命点同步刷新，留 1/5 缓冲用于刷新失败降级

## 功能特性

- **无 AK 认证**：用 OIDC Token 经 IDaaS PAM 换取阿里云 STS 临时凭证
- **多 SDK 适配**：适配四套凭证接口 —— `credentials-go`（通用）、OSS V1 SDK、OSS V2 SDK、SLS SDK
- **自动刷新**：通过核心 SDK `CachedResultSupplier` 缓存凭证，含 singleflight；2/3 寿命点后台预取、4/5 寿命点同步刷新（留 1/5 降级缓冲），刷新失败降级返回旧值
- **结构化错误**：全部错误有类型（`ClientError`/`ServerError`/`CredentialError`/`ConfigError`）带错误码，支持 `errors.As`
- **4xx/5xx 严格分流**：4xx → `ClientError`（携带 PAM 返回的 `error`/`code` 错误码——标准 OAuth 与 IDaaS 自定义两种错误格式均兼容），5xx → `ServerError`
- **包级构造函数与选项**：Go 惯用包级 `Get*` 函数（单参 `roleArn`，其余从已初始化的核心 SDK 单例取）；高级/多实例用法用 functional-options 构造器
- **可定制超时**：连接超时与读取超时分别配置

## 环境要求

- Go >= 1.22
- 依赖：
  - github.com/cloud-idaas/idaas-go-core-sdk
  - github.com/aliyun/credentials-go（通用适配器）
  - github.com/aliyun/aliyun-oss-go-sdk（OSS V1 适配器）
  - github.com/aliyun/alibabacloud-oss-go-sdk-v2（OSS V2 适配器）
  - github.com/aliyun/aliyun-log-go-sdk（SLS 适配器）

> **依赖范围：** 四个云 SDK 依赖声明在同一个 Go module、所有适配器实现位于同一个 `package pam`
> （与 Java/Python 适配器一致）。因此 import `pam` 会传递引入全部云 SDK——这与 Java/Python
> 适配器将全部云 SDK 作为强制依赖的行为一致。

> **从核心 SDK `v0.1.0-alpha.3` 升级：** 如果宿主通过 `WithOidcTokenProvider` /
> `WithCredentialProvider` 注入**自实现**的 `provider.OidcTokenProvider` /
> `provider.IDaaSCredentialProvider`，升级时需额外实现 `GetOidcTokenWithContext(ctx)` /
> `GetCredentialWithContext(ctx)`——Go 没有默认方法，核心 SDK beta.1 的接口扩容对宿主自定义
> 实现是编译级破坏；一行委托旧方法（`return x.GetOidcToken()`）即为合法实现。

## 安装

```bash
go get github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter
```

## 前置准备

本 SDK 依赖 [idaas-go-core-sdk](https://github.com/cloud-idaas/idaas-go-core-sdk)。使用前需先完成 IDaaS Core SDK 初始化。

1. 添加并配置 `idaas-go-core-sdk`，详见 [idaas-go-core-sdk README](https://github.com/cloud-idaas/idaas-go-core-sdk/blob/main/README_zh.md)。

2. 配置文件中设置 PAM `scope`：

   ```json
   {
       "scope": "urn:cloud:idaas:pam|cloud_account_role:obtain_access_credential"
   }
   ```

3. 完成 IDaaS Core SDK 初始化：

   ```go
   import (
       idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
       "github.com/cloud-idaas/idaas-go-core-sdk/factory"
   )

   cfg, err := idaasconfig.NewConfigReader().LoadWithPriority("")
   if err != nil {
       log.Fatalf("加载 IDaaS 配置失败: %v", err)
   }
   if err := factory.InitWithConfig(cfg); err != nil {
       log.Fatalf("初始化 IDaaS 失败: %v", err)
   }
   ```

## 快速开始

### OSS V1 SDK

```go
package main

import (
    "log"

    "github.com/aliyun/aliyun-oss-go-sdk/oss"

    "github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
    idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
    "github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
    // 1. 初始化 IDaaS Core SDK
    idaasCfg, _ := idaasconfig.NewConfigReader().LoadWithPriority("")
    _ = factory.InitWithConfig(idaasCfg)

    // 2. 创建 OSS V1 凭证提供者
    credProvider, err := pam.GetOSSV1CredentialsProvider("acs:ram::<uid>:role/<name>")
    if err != nil {
        log.Fatalf("创建 provider 失败: %v", err)
    }

    // 3. 用 akless 凭证创建 OSS 客户端
    client, _ := oss.New("https://oss-cn-hangzhou.aliyuncs.com", "", "",
        oss.AuthVersion(oss.AuthV4), oss.Region("cn-hangzhou"), oss.SetCredentialsProvider(credProvider))
    bucketClient, _ := client.Bucket("your-bucket")
    result, _ := bucketClient.ListObjects(oss.MaxKeys(100))
    for _, obj := range result.Objects {
        log.Println(obj.Key)
    }
}
```

### 通用（`credentials-go`）

```go
// GetAlibabaCloudCredentialsProvider 实现 credentials.Credential，
// 可用于任何接受 credentials.Credential 的阿里云 SDK 客户端。
provider, err := pam.GetAlibabaCloudCredentialsProvider("acs:ram::<uid>:role/<name>")
model, _ := provider.GetCredential()
// *credentials.CredentialModel，含 AccessKeyId / AccessKeySecret / SecurityToken
```

## API 参考

### 构造函数

| 函数 | 返回类型 | 说明 |
|------|----------|------|
| `pam.GetAlibabaCloudCredentialsProvider(roleArn)` | `(*IDaaSPamAlibabaCloudCredentialsProvider, error)` | 通用 `credentials-go` Credential |
| `pam.GetOSSV1CredentialsProvider(roleArn)` | `(*IDaaSPamOSSV1CredentialsProvider, error)` | OSS V1 SDK CredentialsProvider |
| `pam.GetOSSV2CredentialsProvider(roleArn)` | `(*IDaaSPamOSSV2CredentialsProvider, error)` | OSS V2 SDK CredentialsProvider |
| `pam.GetSLSCredentialsProvider(roleArn)` | `(*IDaaSPamSLSCredentialsProvider, error)` | SLS SDK CredentialsProvider |

每个函数仅传 `roleArn`，其余参数（`developerApiEndpoint` / `idaasInstanceId` / `credentialProvider`）从已初始化的核心 SDK 单例自动获取。`roleArn` 留空时回退到环境变量 `ALIBABA_CLOUD_ROLE_ARN`（对齐 Java/Python 适配层）。需要显式全参构造（多实例、注入 `credentialProvider`、自定义超时）时用下方的 functional-options 构造器——与 Java `Builder` / Python 关键字参数构造器对齐。

### IDaaSPamAlibabaCloudCredentialsProvider

| 方法 | 返回类型 | 说明 |
|------|----------|------|
| `GetCredential()` | `(*credentials.CredentialModel, error)` | 实现 `credentials.Credential`，返回缓存 STS，过期自动刷新 |
| `GetStsCredential()` | `(*domain.AlibabaCloudStsCredential, error)` | 返回原始 STS 凭证 |
| `GetStsCredentialWithContext(ctx)` | `(*domain.AlibabaCloudStsCredential, error)` | 同上；调用方 ctx 可取消/限时对刷新的等待，取消时返回 `CacheError(ClientRequestCanceled)`，刷新在后台继续并写入缓存 |
| `GetRoleArn()` | `string` | 云账号角色外部标识 |
| `GetOIDCToken()` | `string` | 最近使用的 OIDC Token |
| `GetIdaasInstanceId()` | `string` | IDaaS 实例 ID |
| `GetDeveloperApiEndpoint()` | `string` | 规范化后的 PAM Developer API 端点 |
| `GetConnectTimeout()` | `int` | 连接超时（毫秒） |
| `GetReadTimeout()` | `int` | 读取超时（毫秒） |
| `Close()` | `error` | 释放资源（幂等；委托底层 supplier 关闭，当前效果等价 no-op；对齐 Java/Python `close()`） |

### 构造函数（高级用法）

```go
provider, err := pam.NewIDaaSPamAlibabaCloudCredentialsProvider(
    pam.WithCredentialProvider(credProvider),         // 核心 SDK IDaaSCredentialProvider
    pam.WithDeveloperApiEndpoint("pam.example.com"),  // scheme 保留（http/https 原样保留，无协议默认 https）
    pam.WithIdaasInstanceId("your-instance-id"),
    pam.WithRoleArn("acs:ram::<uid>:role/<name>"),
    pam.WithOidcTokenProvider(oidcProvider),  // 可选，直接注入 OIDC Token 来源（优先于 WithCredentialProvider）
    pam.WithConnectTimeout(5000),  // 可选，默认 5000ms
    pam.WithReadTimeout(10000),    // 可选，默认 10000ms
    pam.WithPreflight(),           // 可选，构造期立即换取一次 STS，fail-fast 验证整链路
    pam.WithLogger(l),             // 可选，注入 logger.Logger；未注入回退 logger.Default()
)
```

### 运维须知

- **多实例**：包级构造函数（`GetAlibabaCloudCredentialsProvider` 等）从核心 SDK 进程级单例（经 `factory.Init` / `factory.InitWithConfig` 初始化）读取，只持有一份 IDaaS 实例配置。单进程内要用多个 IDaaS 实例/角色时，用全参 `NewIDaaSPamAlibabaCloudCredentialsProvider(With*...)` 分别构造。
- **PAM 挂起阻塞上限**：缓存未命中（或进入 stale 窗口）的刷新会走完整链路——先取 OIDC Token，再调 PAM HTTP。该调用受 `WithConnectTimeout`/`WithReadTimeout`（默认 5s/10s）分段约束，整个刷新另受核心 SDK 异步刷新总超时（默认 2 分钟）封顶；singleflight 把并发刷新合并为一次 PAM 调用，`GetStsCredentialWithContext(ctx)` 可让调用方提前结束等待（刷新后台继续并写入缓存）。高 QPS 应用可用更短的超时约束单请求最坏阻塞。
- **时钟漂移**：1/5 降级缓冲兼吸收客户端与 PAM 间的适度时钟漂移；漂移过大会偏移刷新点，请保持 NTP 正常。
- **失败语义**：刷新失败但缓存凭证仍在 1/5 降级窗口内（StaleTime 至 ExpiresAt 之间）有效时，provider 返回缓存凭证并经注入的 `logger.Logger` 记 `logger.Warn`（`WithLogger` 注入；未注入时为核心 SDK 默认的一次性 stderr 提示，生产请 `logger.SetDefault` 或 `WithLogger` 注入真实实现）；缓存 STS 真正过期后（PAM 持续故障、缓冲耗尽），`GetCredential` 返回 `CredentialError`（fail-fast），不再返回过期凭证。

## 环境变量

| 变量 | 说明 |
|------|------|
| `CLOUD_IDAAS_CONFIG_PATH` | IDaaS 配置文件路径，默认为 `~/.cloud_idaas/client-config.json` |
| `CLOUD_IDAAS_CLIENT_SECRET` | 客户端密钥的默认环境变量名（核心 SDK 对 `client_secret*` 认证方式的缺省读取）。实际变量名由配置字段 `clientSecretEnvVarName` 决定——本仓库 `samples/cloud_idaas.json` 与集成测试流程使用的是 `IDAAS_CLIENT_SECRET` |
| `ALIBABA_CLOUD_ROLE_ARN` | 云账号角色 ARN（`acs:ram::<uid>:role/<name>`）。未向构造器传入 `roleArn` 时作为兜底——与 Java/Python 适配层的 roleArn 环境变量回退对齐 |

## 支持与反馈

- **Issues 与反馈**：[提交 Issue](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/issues)
- **安全漏洞披露**：见 [安全策略](SECURITY.md)，按负责任披露流程报告。

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 授权。
