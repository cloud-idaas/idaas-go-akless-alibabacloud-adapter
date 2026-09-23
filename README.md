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
4. Credentials are **automatically cached and refreshed** before expiration (sync refresh at the 2/3-life point, leaving a 1/3 stale-degradation buffer)

## Features

- **AK-free Authentication**: Uses OIDC Token to obtain Alibaba Cloud STS temporary credentials via IDaaS PAM
- **Multi-SDK Compatible**: Adapts four credential-provider interfaces — `credentials-go` (generic), OSS V1 SDK, OSS V2 SDK, and SLS SDK
- **Automatic Credential Refresh**: Built-in credential caching via Core SDK `CachedResultSupplier` with singleflight; sync refresh at the 2/3-life point with a 1/3 stale-degrade buffer, stale-on-failure degradation
- **Structured Errors**: All errors are typed (`ClientError`/`ServerError`/`CredentialError`/`ConfigError`) with error codes, supporting `errors.As`
- **Strict 4xx/5xx Split**: 4xx → `ClientError` (carrying `error_code`), 5xx → `ServerError`
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

   See [samples/cloud_idaas.json](samples/cloud_idaas.json) for a full placeholder template. Note: the config file's `httpConfiguration` timeouts apply only to Core SDK requests (OIDC token acquisition); timeouts for the adapter's PAM Developer API calls are set separately via `WithConnectTimeout`/`WithReadTimeout` (package-level constructors use the defaults, 5000/10000 ms).

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
   if err := factory.GetInstance().Initialize(cfg); err != nil {
       log.Fatalf("Failed to initialize IDaaS: %v", err)
   }
   ```

## Quick Start

Complete runnable examples for all four adapters live in [examples/](examples/) — each example compiles under its own build tag, e.g. `go run -tags=example_oss_v2 ./examples` (see each file's header for prerequisites and required environment variables). Snippets below omit some error handling for brevity; always check every `err` in production code.

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
    _ = factory.GetInstance().Initialize(idaasCfg)

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

### OSS V2 SDK

```go
import (
    "context"
    "log"

    oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"

    "github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
)

// Initialize the IDaaS Core SDK first (see Prerequisites), then:
credProvider, err := pam.GetOSSV2CredentialsProvider("acs:ram::<uid>:role/<name>")
if err != nil {
    log.Fatalf("Failed to create provider: %v", err)
}

cfg := oss.NewConfig().
    WithRegion("cn-hangzhou").
    WithCredentialsProvider(credProvider)
client := oss.NewClient(cfg)

// e.g. list objects in a bucket
result, err := client.ListObjects(context.TODO(), &oss.ListObjectsRequest{Bucket: oss.Ptr("your-bucket")})
```

### SLS SDK

```go
import (
    "log"

    sls "github.com/aliyun/aliyun-log-go-sdk"

    "github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
)

// Initialize the IDaaS Core SDK first (see Prerequisites), then:
credProvider, err := pam.GetSLSCredentialsProvider("acs:ram::<uid>:role/<name>")
if err != nil {
    log.Fatalf("Failed to create provider: %v", err)
}

client := (&sls.Client{Endpoint: "cn-hangzhou.log.aliyuncs.com"}).WithCredentialsProvider(credProvider)

// e.g. list projects
projects, err := client.ListProject()
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
| `GetCredential()` | `(*credentials.CredentialModel, error)` | Implements `credentials.Credential`. Returns cached STS with auto-refresh at the 2/3-life point |
| `GetStsCredential()` | `(*domain.AlibabaCloudStsCredential, error)` | Returns the raw STS credential |
| `GetRoleArn()` | `string` | Returns the cloud-account-role external id |
| `GetOIDCToken()` | `string` | Returns the last used OIDC token |
| `GetIdaasInstanceId()` | `string` | Returns the IDaaS instance ID |
| `GetDeveloperApiEndpoint()` | `string` | Returns the normalized PAM Developer API endpoint |
| `GetConnectTimeout()` | `int` | Returns the connect timeout (ms) |
| `GetReadTimeout()` | `int` | Returns the read timeout (ms) |
| `Close()` | `error` | Releases resources (idempotent; currently no-op, aligned with Java/Python `close()`) |

### Constructor (Advanced)

```go
provider, err := pam.NewIDaaSPamAlibabaCloudCredentialsProvider(
    pam.WithCredentialProvider(credProvider),         // core SDK IDaaSCredentialProvider
    pam.WithDeveloperApiEndpoint("pam.example.com"),  // scheme auto-completed to https:// when missing
    pam.WithIdaasInstanceId("your-instance-id"),
    pam.WithRoleArn("acs:ram::<uid>:role/<name>"),
    pam.WithConnectTimeout(5000),     // optional, default 5000ms
    pam.WithReadTimeout(10000),       // optional, default 10000ms
    pam.WithPreflight(),              // optional: construction-time STS preflight (fail-fast; see Operational Notes)
    // pam.WithOidcTokenProvider(p),  // optional: direct OIDC token source (advanced; takes precedence over WithCredentialProvider)
)
```

### Operational Notes

- **Multi-instance**: The package-level constructors (`GetAlibabaCloudCredentialsProvider`, etc.) read from the Core SDK process-wide singleton (`factory.GetInstance()`), which holds a single IDaaS instance config. To use multiple IDaaS instances/roles in one process, construct each provider with the full-arg `NewIDaaSPamAlibabaCloudCredentialsProvider(With*...)`.
- **Preflight**: `WithPreflight()` makes the constructor immediately obtain one STS credential to validate the whole chain (Core SDK → OIDC token → PAM → STS), so misconfiguration (wrong client secret, unauthorized role, wrong endpoint) fails at initialization instead of at the first business request. Recommended for OSS V1, whose `GetCredentials()` path cannot surface errors (they degrade to empty credentials + a warning log). Off by default (the constructor performs no network I/O unless enabled).
- **PAM hang stall bound**: On a cache-miss refresh, a slow/unreachable PAM blocks up to `readTimeout` (default 10s); singleflight merges concurrent refreshes into one PAM call. For high-QPS apps, set a shorter `WithReadTimeout` to bound the worst-case stall per refresh cycle.
- **Clock skew**: The 1/3 stale-degrade buffer also absorbs modest clock skew between the client and PAM. Large skew may shift the refresh point; keep NTP healthy.
- **Failure semantics**: If a refresh fails while a still-valid cached credential exists (within the 1/3 buffer), the provider serves the cached one and logs `slog.Warn`. Once the cached STS truly expires (buffer exhausted under prolonged PAM outage), `GetCredential` returns a `CredentialError` with code `CredentialExpired` (fail-fast) instead of an expired credential — distinguishable from real PAM API errors (`PamApiError`) for alerting/attribution. See the error-code table below.

### Error Codes

Adapter-level error codes (`constants` package) for alerting/attribution by code value:

| Code | Error Type | Trigger |
|------|------------|---------|
| `InvalidParameter` | `ConfigError` | Required constructor parameter missing/invalid (and neither `roleArn` nor `ALIBABA_CLOUD_ROLE_ARN` set) |
| `OidcTokenError` | `CredentialError` | Core SDK failed to provide an OIDC token, or the token is empty |
| `HttpError` | `CredentialError` | Transport-level failure calling the PAM Developer API |
| `PamApiError` | `ServerError`/`ClientError` | PAM returned a non-2xx response that is not JSON-parseable (fallback code) |
| `ParseError` | `CredentialError` | PAM response is not parseable JSON or is missing required STS fields |
| `CredentialExpired` | `CredentialError` | Cached STS truly expired and PAM refresh is unavailable (degrade buffer exhausted) |

Non-2xx PAM responses that do parse carry the PAM-side `error_code` (e.g. `cloud_account_role_not_found`) instead of `PamApiError`; 4xx maps to `ClientError`, 5xx to `ServerError`.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CLOUD_IDAAS_CONFIG_PATH` | Path to the IDaaS configuration file. Defaults to `~/.cloud_idaas/client-config.json` |
| `IDAAS_CLIENT_SECRET` | Client secret for IDaaS authentication. Recommended over storing secrets in the config file |
| `ALIBABA_CLOUD_ROLE_ARN` | Cloud-account-role ARN (`acs:ram::<uid>:role/<name>`). Used as a fallback when `roleArn` is not passed to a constructor — aligned with the Java/Python adapters' `roleArn` env-var fallback |

## Testing

Unit tests run with the default toolchain:

```bash
go test ./... -race
```

Integration tests (real IDaaS PAM → Alibaba Cloud STS → OSS/SLS/ECS end-to-end) are gated behind a build tag plus an explicit switch and are skipped by default; see the header comment of `pam/integration_test.go` for required configuration and environment variables:

```bash
IDAAS_INTEGRATION=on IDAAS_ROLE_ARN=... IDAAS_CLIENT_SECRET=... \
  go test -tags=integration ./pam/ -run TestIntegration -v -timeout 10m
```

## Support and Feedback

- **Issues**: [Submit an Issue](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/issues)
- **Email**: cloudidaas@list.alibaba-inc.com

## License

This project is licensed under the [Apache License 2.0](LICENSE).
