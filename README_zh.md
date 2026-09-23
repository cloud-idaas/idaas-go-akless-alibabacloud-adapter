# idaas-go-akless-alibabacloud-adapter

[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Development Status](https://img.shields.io/badge/status-Beta-orange)](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter)

[English](README.md) | 简体中文

IDaaS（身份即服务）AKless 阿里云适配器 Go SDK —— 通过 IDaaS PAM（特权访问管理）获取阿里云 STS 临时凭证，实现应用无 AK 接入阿里云服务。

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
4. 凭证**自动缓存与刷新**，过期前在 2/3 寿命点同步刷新（留 1/3 缓冲用于刷新失败降级）

## 功能特性

- **无 AK 认证**：用 OIDC Token 经 IDaaS PAM 换取阿里云 STS 临时凭证
- **多 SDK 适配**：适配四套凭证接口 —— `credentials-go`（通用）、OSS V1 SDK、OSS V2 SDK、SLS SDK
- **自动刷新**：通过核心 SDK `CachedResultSupplier` 缓存凭证，含 singleflight；在 2/3 寿命点同步刷新（留 1/3 降级缓冲），刷新失败降级返回旧值
- **结构化错误**：全部错误有类型（`ClientError`/`ServerError`/`CredentialError`/`ConfigError`）带错误码，支持 `errors.As`
- **4xx/5xx 严格分流**：4xx → `ClientError`（携带 `error_code`），5xx → `ServerError`
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

   完整占位模板见 [samples/cloud_idaas.json](samples/cloud_idaas.json)。注意：配置文件中 `httpConfiguration` 的超时仅作用于核心 SDK 请求（OIDC Token 获取）；适配器调用 PAM Developer API 的超时由 `WithConnectTimeout`/`WithReadTimeout` 单独设置（包级便捷构造函数固定使用默认值 5000/10000 毫秒）。

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
   if err := factory.GetInstance().Initialize(cfg); err != nil {
       log.Fatalf("初始化 IDaaS 失败: %v", err)
   }
   ```

## 快速开始

四个适配器的完整可运行示例位于 [examples/](examples/)——每个示例带独立 build tag 编译，例如 `go run -tags=example_oss_v2 ./examples`（前置条件与所需环境变量见各文件头部说明）。下方片段为简洁起见省略了部分错误处理；生产代码请务必检查每个 `err`。

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
    _ = factory.GetInstance().Initialize(idaasCfg)

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

### OSS V2 SDK

```go
import (
    "context"
    "log"

    oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"

    "github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
)

// 先初始化 IDaaS Core SDK（见「前置准备」），然后：
credProvider, err := pam.GetOSSV2CredentialsProvider("acs:ram::<uid>:role/<name>")
if err != nil {
    log.Fatalf("创建 provider 失败: %v", err)
}

cfg := oss.NewConfig().
    WithRegion("cn-hangzhou").
    WithCredentialsProvider(credProvider)
client := oss.NewClient(cfg)

// 例如：列出 bucket 内对象
result, err := client.ListObjects(context.TODO(), &oss.ListObjectsRequest{Bucket: oss.Ptr("your-bucket")})
```

### SLS SDK

```go
import (
    "log"

    sls "github.com/aliyun/aliyun-log-go-sdk"

    "github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
)

// 先初始化 IDaaS Core SDK（见「前置准备」），然后：
credProvider, err := pam.GetSLSCredentialsProvider("acs:ram::<uid>:role/<name>")
if err != nil {
    log.Fatalf("创建 provider 失败: %v", err)
}

client := (&sls.Client{Endpoint: "cn-hangzhou.log.aliyuncs.com"}).WithCredentialsProvider(credProvider)

// 例如：列出 project
projects, err := client.ListProject()
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
| `GetCredential()` | `(*credentials.CredentialModel, error)` | 实现 `credentials.Credential`，返回缓存 STS，在 2/3 寿命点自动刷新 |
| `GetStsCredential()` | `(*domain.AlibabaCloudStsCredential, error)` | 返回原始 STS 凭证 |
| `GetRoleArn()` | `string` | 云账号角色外部标识 |
| `GetOIDCToken()` | `string` | 最近使用的 OIDC Token |
| `GetIdaasInstanceId()` | `string` | IDaaS 实例 ID |
| `GetDeveloperApiEndpoint()` | `string` | 规范化后的 PAM Developer API 端点 |
| `GetConnectTimeout()` | `int` | 连接超时（毫秒） |
| `GetReadTimeout()` | `int` | 读取超时（毫秒） |
| `Close()` | `error` | 释放资源（幂等；当前 no-op，对齐 Java/Python `close()`） |

### 构造函数（高级用法）

```go
provider, err := pam.NewIDaaSPamAlibabaCloudCredentialsProvider(
    pam.WithCredentialProvider(credProvider),         // 核心 SDK IDaaSCredentialProvider
    pam.WithDeveloperApiEndpoint("pam.example.com"),  // 缺省协议时自动补 https://
    pam.WithIdaasInstanceId("your-instance-id"),
    pam.WithRoleArn("acs:ram::<uid>:role/<name>"),
    pam.WithConnectTimeout(5000),     // 可选，默认 5000ms
    pam.WithReadTimeout(10000),       // 可选，默认 10000ms
    pam.WithPreflight(),              // 可选：构造期 STS 预检（fail-fast，见运维须知）
    // pam.WithOidcTokenProvider(p),  // 可选：直接注入 OIDC Token 提供者（高级用法，优先于 WithCredentialProvider）
)
```

### 运维须知

- **多实例**：包级构造函数（`GetAlibabaCloudCredentialsProvider` 等）从核心 SDK 进程级单例（`factory.GetInstance()`）读取，只持有一份 IDaaS 实例配置。单进程内要用多个 IDaaS 实例/角色时，用全参 `NewIDaaSPamAlibabaCloudCredentialsProvider(With*...)` 分别构造。
- **构造期预检**：`WithPreflight()` 使构造函数立即换取一次 STS 凭证，验证整条链路（核心 SDK → OIDC Token → PAM → STS），让配置类错误（client secret 不匹配、role 未授权、端点错误等）在初始化阶段即暴露，而非延迟到首次业务请求。推荐 OSS V1 场景启用——OSS V1 SDK 的 `GetCredentials()` 路径无法上报错误（会降级为空凭证 + 告警日志）。默认关闭（未启用时构造函数不做网络 IO）。
- **PAM 挂起阻塞上限**：缓存未命中时刷新，PAM 慢/不可达会阻塞最多 `readTimeout`（默认 10s）；singleflight 把并发刷新合并为一次 PAM 调用。高 QPS 应用可设更短的 `WithReadTimeout` 以约束单次刷新周期的最坏阻塞。
- **时钟漂移**：1/3 降级缓冲兼吸收客户端与 PAM 间的适度时钟漂移；漂移过大会偏移刷新点，请保持 NTP 正常。
- **失败语义**：刷新失败但缓存凭证仍在 1/3 缓冲内有效时，provider 返回缓存凭证并记 `slog.Warn`；缓存 STS 真正过期后（PAM 持续故障、缓冲耗尽），`GetCredential` 返回错误码为 `CredentialExpired` 的 `CredentialError`（fail-fast），不再返回过期凭证——与真实 PAM API 错误（`PamApiError`）可按码值区分归因（见下方错误码表）。

### 错误码

适配层错误码（`constants` 包），可按码值做告警分流与归因：

| 错误码 | 错误类型 | 触发场景 |
|------|----------|------|
| `InvalidParameter` | `ConfigError` | 必填参数缺失/非法（含 `roleArn` 与 `ALIBABA_CLOUD_ROLE_ARN` 均未设置） |
| `OidcTokenError` | `CredentialError` | 核心 SDK 获取 OIDC Token 失败或 Token 为空 |
| `HttpError` | `CredentialError` | 调用 PAM Developer API 时传输层错误 |
| `PamApiError` | `ServerError`/`ClientError` | PAM 返回非 2xx 且响应体不可按 JSON 解析（兜底码） |
| `ParseError` | `CredentialError` | PAM 响应非可解析 JSON 或缺失必需的 STS 字段 |
| `CredentialExpired` | `CredentialError` | 缓存 STS 真正过期且 PAM 刷新不可用（降级缓冲耗尽） |

非 2xx 且可解析的 PAM 响应携带 PAM 侧 `error_code`（如 `cloud_account_role_not_found`）而非 `PamApiError`；4xx 映射为 `ClientError`，5xx 映射为 `ServerError`。

## 环境变量

| 变量 | 说明 |
|------|------|
| `CLOUD_IDAAS_CONFIG_PATH` | IDaaS 配置文件路径，默认为 `~/.cloud_idaas/client-config.json` |
| `IDAAS_CLIENT_SECRET` | IDaaS 认证的客户端密钥，推荐用环境变量而非写入配置文件 |
| `ALIBABA_CLOUD_ROLE_ARN` | 云账号角色 ARN（`acs:ram::<uid>:role/<name>`）。未向构造器传入 `roleArn` 时作为兜底——与 Java/Python 适配层的 roleArn 环境变量回退对齐 |

## 测试

单元测试使用默认工具链运行：

```bash
go test ./... -race
```

集成测试（真实 IDaaS PAM → 阿里云 STS → OSS/SLS/ECS 端到端）受 build tag 与显式开关双重门控，默认跳过；所需配置与环境变量见 `pam/integration_test.go` 文件头说明：

```bash
IDAAS_INTEGRATION=on IDAAS_ROLE_ARN=... IDAAS_CLIENT_SECRET=... \
  go test -tags=integration ./pam/ -run TestIntegration -v -timeout 10m
```

## 支持与反馈

- **Issues**：[提交 Issue](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/issues)
- **邮箱**：cloudidaas@list.alibaba-inc.com

## 许可证

本项目基于 [Apache License 2.0](LICENSE) 授权。
