# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.1] - 2026-09-23

### Added
- `roleArn` environment-variable fallback: when `roleArn` is not passed to a constructor,
  the provider reads `ALIBABA_CLOUD_ROLE_ARN` (constant `constants.RoleArnEnvVar`),
  aligning with the Java/Python adapters' `roleArn` env-var fallback so the same
  environment config is portable across the three language SDKs. Examples now use
  `ALIBABA_CLOUD_ROLE_ARN` instead of the Go-only `IDAAS_ROLE_ARN`.
- `Close()` lifecycle method on `IDaaSPamAlibabaCloudCredentialsProvider` (idempotent,
  currently no-op), aligning with the Java/Python adapters' `close()` API surface and
  reserving an explicit release hook for future HTTP-client resource cleanup.
- `WithPreflight()` functional option: opt-in construction-time STS preflight that
  fail-fast validates the full chain (Core SDK → OIDC token → PAM → STS). Restores the
  historical `NewOSSCredentialsProvider` fail-fast behavior as an explicit capability,
  recommended for OSS V1 (whose `GetCredentials()` path cannot surface errors).
- Compile-time interface assertions (`var _ <iface> = (*T)(nil)`) for all five
  credential-provider interfaces (credentials-go `Credential`, OSS V1
  `CredentialsProvider`/`CredentialsProviderE`, OSS V2 `CredentialsProvider`, SLS
  `CredentialsProvider`); upstream SDK signature changes now fail at build time.
- Examples are compiled in CI: each example carries an independent build tag
  (`example_generic`/`example_oss_v1`/`example_oss_v2`/`example_sls`) and CI builds them
  per-tag, so example API misuse can no longer go undetected.

### Changed
- Factory API simplified to idiomatic Go. Removed the `IDaaSPamAklessCredentialFactory`
  struct, `NewIDaaSPamAklessCredentialFactory()`, and all `Create*` / `Create*With`
  methods (a stateless empty struct with methods is a Java-`static` transplant, not a
  Go idiom; the Go AWS sibling never had one). The four package-level functions
  `GetAlibabaCloudCredentialsProvider` / `GetOSSV1CredentialsProvider` /
  `GetOSSV2CredentialsProvider` / `GetSLSCredentialsProvider` are now the sole
  convenience constructors; their parameter is renamed `roleExternalId` → `roleArn`,
  aligning with the Java/Python `roleArn` / `role_arn` parameters and resolving an
  internal inconsistency (the factory arg was `roleExternalId` while the option/field
  was `roleArn`). Full-parameter construction uses the existing functional-options
  constructor `NewIDaaSPamAlibabaCloudCredentialsProvider(With*...)`, mirroring the
  Java `Builder` / Python keyword-argument constructors. This aligns the factory
  method name and `roleArn` parameter across Go/Java/Python (NF-AKLESS-LANG-01).
- Core provider type renamed `IDaaSPamCredentialsProvider` →
  `IDaaSPamAlibabaCloudCredentialsProvider` (including its `New...` constructor and
  factory return types), aligning with the Java/Python adapters and the cross-cloud
  naming convention (AWS sibling is `IDaaSPamAwsCredentialsProvider`).
- `CredentialModel.Type` (and `GetType()`) now returns `"oidc_role_arn"` instead of
  `"sts"`, aligning with credentials-go's built-in OIDC provider and the Java/Python
  adapters. Functionally equivalent for darabonba signing (non-bearer types sign
  identically); affects only consumers that branch on the Type value for
  logging/telemetry.
- An empty OIDC token from the core SDK now fails fast with
  `CredentialError(OidcTokenError)` instead of proceeding to PAM with an empty
  Bearer token (which could only fail downstream with a confusing 401).
- `normalizeEndpoint` aligned with the Python adapter's `urlparse` semantics: an explicit
  `http://`/`https://` scheme is now preserved (no longer force-upgraded to `https://`);
  only a missing scheme defaults to `https://`. Path is stripped, host:port preserved.
- `idaasInstanceId` is now `url.PathEscape`-escaped when interpolated into the PAM request
  path, as defense-in-depth against malformed input.
- `GetStsCredential` fail-fast (cache truly expired) now returns a dedicated
  `CredentialExpired` error code instead of `PamApiError`, so cache-exhaustion is
  distinguishable from real PAM API errors in dashboards/alerts.
- `parseUTCDate` simplified: `time.RFC3339` already covers the `Z` and `+00:00` forms;
  dropped the redundant layout entries.

### Fixed
- Examples were previously excluded from CI (`//go:build ignore`) and the release build
  step swallowed failures (`|| true`); both are corrected — examples now build under
  per-tag CI verification and release example-build failures fail the release.
- Corrected misleading doc comments claiming "async prefetch": the supplier uses sync
  refresh at the 2/3-life point with a 1/3 stale-degrade buffer (prefetchThreshold=0),
  consistent with the AWS/Tencent sibling adapters.

### Security
- `refreshCredential` no longer embeds the raw PAM response body into error messages.
  Previously a 2xx response with a missing/empty STS field would put `accessKeyId` /
  `accessKeySecret` / `securityToken` into the error object (and from there into upstream
  logs/telemetry). Parse-failure messages now name only the missing field(s); the
  non-2xx fallback path truncates the body to a bounded length.

## [0.1.0-beta] - 2026-09-18

### Added
- First beta release of the IDaaS AKless Alibaba Cloud Adapter (Go).
- Four credential-provider adapters, all backed by IDaaS PAM Developer API:
  - `IDaaSPamAlibabaCloudCredentialsProvider` — generic `github.com/aliyun/credentials-go` `Credential` interface.
  - `IDaaSPamOSSV1CredentialsProvider` — Alibaba Cloud OSS V1 SDK `oss.CredentialsProvider` (with `CredentialsProviderE` error surfacing).
  - `IDaaSPamOSSV2CredentialsProvider` — Alibaba Cloud OSS V2 SDK `credentials.CredentialsProvider`.
  - `IDaaSPamSLSCredentialsProvider` — Alibaba Cloud SLS SDK `sls.CredentialsProvider`.
- `IDaaSPamAklessCredentialFactory` static factory with zero-arg (Core SDK Factory) and full-arg overloads for every adapter (F-AKLESS-FACTORY-01/02).
- Functional-options constructor (`WithCredentialProvider`, `WithOidcTokenProvider`, `WithDeveloperApiEndpoint`, `WithIdaasInstanceId`, `WithRoleArn`, `WithConnectTimeout`, `WithReadTimeout`).
- STS credential caching & auto-refresh via Core SDK `cache.CachedResultSupplier` (singleflight; sync refresh at the 2/3-life point with a 1/3 stale-degrade buffer, stale-on-failure degradation).
- Structured, typed errors (`ClientError`/`ServerError`/`CredentialError`/`ConfigError`) with error codes; strict 4xx→Client / 5xx→Server split.
- Core SDK HTTP client with split connect/read timeouts, TLS 1.2+, connection pooling; query params URL-escaped.
- `domain.AlibabaCloudStsCredential` and `constants/` packages for a stable, cross-language-aligned public surface.
- Bilingual README (English / 简体中文), Apache 2.0 LICENSE, sample config, cross-platform example build script.
- Unit tests (≥92% coverage) covering endpoint normalization, date parsing, PAM error mapping (4xx/5xx/non-JSON/missing fields), cache hit/refresh, and all four adapters.

### Changed
- Migrated module path to `github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter` (aligned with the open-source `cloud-idaas` org).
- Replaced raw `net/http` + hand-rolled `sync.Mutex` cache with Core SDK `http.HttpClient` + `cache.CachedResultSupplier`.
- Replaced `fmt.Errorf` in public error returns with structured Core SDK errors (`CredentialError`/`ClientError`/`ServerError`/`ConfigError`) carrying error codes (internal helpers' errors are wrapped into structured types by callers).
- Split `StsCredential` and path/field constants out of `pam` into `domain/` and `constants/`.
