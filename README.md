# idaas-go-akless-alibabacloud-adapter

[![Go Version](https://img.shields.io/badge/go-1.22%2B-blue)](https://go.dev/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![Development Status](https://img.shields.io/badge/status-Beta-orange)](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter)

[简体中文](README_zh.md) | English

Go SDK for IDaaS (Identity as a Service) AKless Alibaba Cloud Adapter — Enables AK-free authentication for Alibaba Cloud services using IDaaS PAM (Privileged Access Management) to obtain Alibaba Cloud STS temporary credentials.

## How It Works

```
┌──────────┐    OIDC Token    ┌──────────────┐  Alibaba Cloud STS  ┌─────────────┐
│  IDaaS   │ ──────────────►  │  PAM          │ ─────────────────► │  Alibaba   │
│  Core    │                  │  Developer    │   (AccessKeyId,    │  Cloud     │
│  SDK     │                  │  API          │    AccessKeySecret,│  Service   │
└──────────┘                  └──────────────┘    SecurityToken)   └─────────────┘
```

1. The IDaaS Core SDK obtains an **OIDC Token** (AccessToken) via machine-to-machine authentication
2. This adapter sends the OIDC Token to the **PAM Developer API** to obtain Alibaba Cloud STS temporary credentials
3. The temporary credentials are used to authenticate with **Alibaba Cloud services** (OSS V1/V2, SLS, and any service consuming `credentials-go`)
4. Credentials are **automatically cached and refreshed** before expiration — a background prefetch fires at the 2/3-life point (non-blocking), a synchronous refresh at the 4/5 point, leaving a 1/5 stale-degradation buffer for refresh-failure fallback

## Features

- **AK-free Authentication**: Uses OIDC Token to obtain Alibaba Cloud STS temporary credentials via IDaaS PAM
- **Multi-SDK Compatible**: Adapts four credential-provider interfaces — `credentials-go` (generic), OSS V1 SDK, OSS V2 SDK, and SLS SDK
- **Automatic Credential Refresh**: Built-in credential caching via Core SDK `CachedResultSupplier` with singleflight; background prefetch at the 2/3-life point, synchronous refresh at the 4/5 point with a 1/5 stale-degrade buffer, stale-on-failure degradation
- **Structured Errors**: All errors are typed (`ClientError`/`ServerError`/`CredentialError`/`ConfigError`) with error codes, supporting `errors.As`
- **Strict 4xx/5xx Split**: 4xx → `ClientError` (carrying the PAM `error`/`code` field — both the standard OAuth and IDaaS error formats are accepted), 5xx → `ServerError`
- **Package-level Constructors & Options**: Idiomatic Go package-level `Get*` functions (single `roleArn` arg, the rest pulled from the initialized Core SDK singleton); functional-options constructor for advanced / multi-instance use
- **Customizable Timeouts**: Supports separate connect and read timeout configuration

## Requirements

- Go >= 1.22
- Dependencies:
  - github.com/cloud-idaas/idaas-go-core-sdk
  - github.com/aliyun/credentials-go (generic adapter)
  - github.com/aliyun/aliyun-oss-go-sdk (OSS V1 adapter)
  - github.com/aliyun/alibabacloud-oss-go-sdk-v2 (OSS V2 adapter)
  - github.com/aliyun/aliyun-log-go-sdk (SLS adapter)

> **Dependency scope:** All four cloud-SDK dependencies are declared in one Go module and all
> adapter implementations live in one `package pam` (mirroring the Java/Python adapters). Importing
> `pam` therefore transitively pulls in all of them — consistent with the Java/Python adapters,
> which likewise ship all cloud-SDK deps as mandatory.

> **Upgrading from Core SDK `v0.1.0-alpha.3`:** if you supply your own implementations of
> `provider.OidcTokenProvider` / `provider.IDaaSCredentialProvider` (via `WithOidcTokenProvider` /
> `WithCredentialProvider`), you must additionally implement `GetOidcTokenWithContext(ctx)` /
> `GetCredentialWithContext(ctx)` — Go has no default methods, so Core SDK beta.1's interface
> widening is compile-breaking for host-side implementations. A one-line delegation to the existing
> method (`return x.GetOidcToken()`) is a valid implementation.

## Installation

```bash
go get github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter
```

## Prerequisites

This SDK depends on [idaas-go-core-sdk](https://github.com/cloud-idaas/idaas-go-core-sdk). You need to complete the IDaaS Core SDK initialization before using this adapter.

1. Add and configure `idaas-go-core-sdk`, refer to [idaas-go-core-sdk README](https://github.com/cloud-idaas/idaas-go-core-sdk/blob/main/README.md) for details.

2. In the configuration file, set the `scope` to the IDaaS PAM scope:

   ```json
   {
       "scope": "urn:cloud:idaas:pam|cloud_account_role:obtain_access_credential"
   }
   ```

3. Complete the IDaaS Core SDK initialization:

   ```go
   import (
       idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
       "github.com/cloud-idaas/idaas-go-core-sdk/factory"
   )

   cfg, err := idaasconfig.NewConfigReader().LoadWithPriority("")
   if err != nil {
       log.Fatalf("Failed to load IDaaS config: %v", err)
   }
   if err := factory.InitWithConfig(cfg); err != nil {
       log.Fatalf("Failed to initialize IDaaS: %v", err)
   }
   ```

## Quick Start

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
    // 1. Initialize IDaaS Core SDK
    idaasCfg, _ := idaasconfig.NewConfigReader().LoadWithPriority("")
    _ = factory.InitWithConfig(idaasCfg)

    // 2. Create OSS V1 credentials provider
    credProvider, err := pam.GetOSSV1CredentialsProvider("acs:ram::<uid>:role/<name>")
    if err != nil {
        log.Fatalf("Failed to create provider: %v", err)
    }

    // 3. Create OSS client with akless credentials
    client, _ := oss.New("https://oss-cn-hangzhou.aliyuncs.com", "", "",
        oss.AuthVersion(oss.AuthV4), oss.Region("cn-hangzhou"), oss.SetCredentialsProvider(credProvider))
    bucketClient, _ := client.Bucket("your-bucket")
    result, _ := bucketClient.ListObjects(oss.MaxKeys(100))
    for _, obj := range result.Objects {
        log.Println(obj.Key)
    }
}
```

### Generic (`credentials-go`)

```go
// GetAlibabaCloudCredentialsProvider implements credentials.Credential,
// usable with any Alibaba Cloud SDK client that accepts credentials.Credential.
provider, err := pam.GetAlibabaCloudCredentialsProvider("acs:ram::<uid>:role/<name>")
model, _ := provider.GetCredential()
// *credentials.CredentialModel with AccessKeyId / AccessKeySecret / SecurityToken
```

## API Reference

### Constructors

| Function | Return Type | Description |
|----------|-------------|-------------|
| `pam.GetAlibabaCloudCredentialsProvider(roleArn)` | `(*IDaaSPamAlibabaCloudCredentialsProvider, error)` | Generic `credentials-go` Credential |
| `pam.GetOSSV1CredentialsProvider(roleArn)` | `(*IDaaSPamOSSV1CredentialsProvider, error)` | OSS V1 SDK CredentialsProvider |
| `pam.GetOSSV2CredentialsProvider(roleArn)` | `(*IDaaSPamOSSV2CredentialsProvider, error)` | OSS V2 SDK CredentialsProvider |
| `pam.GetSLSCredentialsProvider(roleArn)` | `(*IDaaSPamSLSCredentialsProvider, error)` | SLS SDK CredentialsProvider |

Each takes a single `roleArn` and pulls `developerApiEndpoint` / `idaasInstanceId` / `credentialProvider` from the initialized Core SDK singleton. An empty `roleArn` falls back to the `ALIBABA_CLOUD_ROLE_ARN` environment variable (aligned with the Java/Python adapters). For explicit full-parameter construction (multi-instance, injected `credentialProvider`, custom timeouts), use the functional-options constructor below — aligned with the Java `Builder` / Python keyword-argument constructors.

### IDaaSPamAlibabaCloudCredentialsProvider

| Method | Return Type | Description |
|--------|-------------|-------------|
| `GetCredential()` | `(*credentials.CredentialModel, error)` | Implements `credentials.Credential`. Returns cached STS, auto-refreshes if expired |
| `GetStsCredential()` | `(*domain.AlibabaCloudStsCredential, error)` | Returns the raw STS credential |
| `GetStsCredentialWithContext(ctx)` | `(*domain.AlibabaCloudStsCredential, error)` | Same, but the caller `ctx` can cancel/deadline the wait; cancellation returns `CacheError(ClientRequestCanceled)` while the refresh continues in the background |
| `GetRoleArn()` | `string` | Returns the cloud-account-role external id |
| `GetOIDCToken()` | `string` | Returns the last used OIDC token |
| `GetIdaasInstanceId()` | `string` | Returns the IDaaS instance ID |
| `GetDeveloperApiEndpoint()` | `string` | Returns the normalized PAM Developer API endpoint |
| `GetConnectTimeout()` | `int` | Returns the connect timeout (ms) |
| `GetReadTimeout()` | `int` | Returns the read timeout (ms) |
| `Close()` | `error` | Releases resources (idempotent; delegates to the underlying supplier close — a no-op effect today — aligned with Java/Python `close()`) |

### Constructor (Advanced)

```go
provider, err := pam.NewIDaaSPamAlibabaCloudCredentialsProvider(
    pam.WithCredentialProvider(credProvider),         // core SDK IDaaSCredentialProvider
    pam.WithDeveloperApiEndpoint("pam.example.com"),  // scheme preserved (http/https kept; no scheme defaults to https)
    pam.WithIdaasInstanceId("your-instance-id"),
    pam.WithRoleArn("acs:ram::<uid>:role/<name>"),
    pam.WithOidcTokenProvider(oidcProvider),  // optional, direct OIDC source (takes precedence over WithCredentialProvider)
    pam.WithConnectTimeout(5000),  // optional, default 5000ms
    pam.WithReadTimeout(10000),    // optional, default 10000ms
    pam.WithPreflight(),           // optional, construction-time STS exchange to fail-fast validate the chain
    pam.WithLogger(l),             // optional, logger.Logger injection; defaults to logger.Default()
)
```

### Operational Notes

- **Multi-instance**: The package-level constructors (`GetAlibabaCloudCredentialsProvider`, etc.) read from the Core SDK process-wide singleton (initialized via `factory.Init` / `factory.InitWithConfig`), which holds a single IDaaS instance config. To use multiple IDaaS instances/roles in one process, construct each provider with the full-arg `NewIDaaSPamAlibabaCloudCredentialsProvider(With*...)`.
- **PAM hang stall bound**: A cache-miss (or stale-window) refresh runs the full chain — OIDC token fetch plus the PAM HTTP call. The call is segmented by `WithConnectTimeout`/`WithReadTimeout` (defaults 5s/10s) and the whole refresh is capped by the Core SDK async-refresh timeout (2 minutes by default); singleflight merges concurrent refreshes into one PAM call, and `GetStsCredentialWithContext(ctx)` lets callers stop waiting early (the refresh keeps running in the background). For high-QPS apps, shorter timeouts bound the worst-case per-request stall.
- **Clock skew**: The 1/5 stale-degrade buffer also absorbs modest clock skew between the client and PAM. Large skew may shift the refresh point; keep NTP healthy.
- **Failure semantics**: If a refresh fails while a still-valid cached credential exists (within the 1/5 stale window, i.e. StaleTime→ExpiresAt), the provider serves the cached one and emits a `logger.Warn` via the injected `logger.Logger` (`WithLogger`; defaults to the Core SDK's one-shot stderr hint — set `logger.SetDefault` or pass `WithLogger` for persistent observability). Once the cached STS truly expires (buffer exhausted under prolonged PAM outage), `GetCredential` returns a `CredentialError` (fail-fast) instead of an expired credential.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CLOUD_IDAAS_CONFIG_PATH` | Path to the IDaaS configuration file. Defaults to `~/.cloud_idaas/client-config.json` |
| `CLOUD_IDAAS_CLIENT_SECRET` | Default client-secret env var (Core SDK default for `client_secret*` auth methods). The actual variable name is config-driven via `clientSecretEnvVarName` — this repo's `samples/cloud_idaas.json` and integration flow use `IDAAS_CLIENT_SECRET` |
| `ALIBABA_CLOUD_ROLE_ARN` | Cloud-account-role ARN (`acs:ram::<uid>:role/<name>`). Used as a fallback when `roleArn` is not passed to a constructor — aligned with the Java/Python adapters' `roleArn` env-var fallback |

## Support and Feedback

- **Issues & Feedback**: [Submit an Issue](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/issues)
- **Security Disclosures**: See [Security Policy](SECURITY.md) for responsible-reporting guidelines.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
