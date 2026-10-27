# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.3] - 2026-10-27

### Added
- `WithLogger(logger.Logger)` option and a `logger` field on
  `IDaaSPamAlibabaCloudCredentialsProvider`, mirroring the Core SDK factory's
  `WithLogger` / `effectiveLogger()` pattern. Defaults to `logger.Default()` when
  not injected (the Core SDK's one-shot stderr hint). Production deployments
  should pass `WithLogger` or call `logger.SetDefault` at process start so
  refresh-degrade warnings are not collapsed into a single one-shot notice. Covered by unit tests (injected logger receives the refresh-failure warn; `nil` falls back to `logger.Default()`).

### Changed
- **Breaking change for host implementers (inherited from Core SDK beta.1):** hosts that supply their own
  `provider.OidcTokenProvider` / `provider.IDaaSCredentialProvider` implementations (via
  `WithOidcTokenProvider` / `WithCredentialProvider`) must additionally implement
  `GetOidcTokenWithContext(ctx)` / `GetCredentialWithContext(ctx)` when upgrading — Go has no default
  methods, so the Core SDK's interface widening is compile-breaking for custom implementations. A
  one-line delegation to the existing method (`return x.GetOidcToken()`) is a valid implementation; the
  adapter's own `oidcTokenAdapter` delegates exactly this way.

- **Go floor settled at 1.22** (unchanged vs the previous release; two lower floors were tried
  and rejected by real-toolchain evidence). Go 1.18 cannot compile the resolved dependency graph:
  `aliyun-log-go-sdk` — itself declaring `go 1.13` — transitively pins `klauspost/compress`
  v1.17.8, which declares `go 1.20` and uses the Go 1.19 `binary.*.Append*` APIs (CI failed on a
  1.18 runner with `binary.LittleEndian.AppendUint32 undefined`). Go 1.20 builds the graph
  (fmt/vet passed on a 1.20.14 runner), but the newest scanner that supports it, `govulncheck`
  v1.0.4, has a toolchain-bound bug there ("invalid finding: if Frame.Function is set,
  Frame.Package must also be") and v1.1.x requires Go >= 1.21. 1.22 is therefore the lowest
  consumer floor declared in `go.mod`; CI build/test runs on Go 1.25 (language version still
  gated by go.mod), and vulnerability scanning is a dedicated job on the latest stable
  toolchain with `govulncheck@latest` — stdlib advisories only ever disappear in supported
  toolchains, so pinning the scanner's Go version makes the gate red on its own schedule. With the floor at 1.22, `aliyun-log-go-sdk` moves back to
  v0.1.75 (its v0.1.74 downgrade was only needed for the rejected 1.18 floor). The adapter
  avoids `log/slog` by choice, mirroring the Core SDK `logger.Logger` abstraction.
- **Dependency upgrade: `idaas-go-core-sdk` v0.1.0-alpha.3 → v0.1.0-beta.1**, adapting to its
  breaking changes and adopting its context-aware API end to end:
  - `cache.NewCachedResultSupplier` dropped the positional `prefetchThreshold` argument and now
    takes a `func(context.Context) (*RefreshResult[T], error)` refresh function. The provider's
    `refreshCredential` is therefore context-aware and calls
    `OidcTokenProvider.GetOidcTokenWithContext` / `HttpClient.ExecuteContext`, so the whole
    refresh chain is bounded by the supplier's async-refresh timeout (and host cancellation)
    instead of relying only on the split connect/read timeouts.
  - `cache.RefreshResult` moved to the dual time-point model: the provider now fills
    `PrefetchTime` (2/3 of the STS lifetime), `StaleTime` (4/5) and `ExpiresAt` (the real STS
    expiration) rather than stuffing the prefetch point into `ExpiresAt`. Effective behaviour:
    crossing the 2/3 point triggers a **background** prefetch (no request blocked), the
    synchronous refresh happens in the 4/5→expiry stale window; stale-on-failure degradation
    (serving the cached credential within the 1/5 StaleTime→ExpiresAt window) and the
    expired-credential fail-fast remain in effect.
  - New public API `GetStsCredentialWithContext(ctx)`; `GetStsCredential()` now delegates to it
    with `context.Background()`. Caller cancellation/deadline returns immediately with
    `CacheError(ClientRequestCanceled)` instead of waiting for an in-flight refresh, which keeps
    running and populates the cache for later callers. The OSS V2 adapter forwards the `ctx` it
    receives from the OSS SDK.
  - The core SDK's degrade signal `cache.ErrStaleCredentialReturned` is no longer surfaced as a
    raw error: when the cached STS is genuinely expired it is converted to the adapter's own
    `CredentialError(CredentialExpired)`, with the signal retained in the error cause chain.
  - Expiration checks use the core SDK's injectable clock (`cache.GetClock()`), so the adapter
    and `CachedResultSupplier` share a single time source; with the default system clock,
    production behaviour is unchanged.
  - `Close()` now releases the underlying `CachedResultSupplier` (currently a no-op because no
    prefetch strategy is injected); it stays idempotent and non-destructive.
  - Test fixtures implement the new interface methods (`HttpClient.ExecuteContext`,
    `OidcTokenProvider.GetOidcTokenWithContext`,
    `IDaaSCredentialProvider.GetCredentialWithContext`, `IDaaSCredential.String` — the core SDK
    added a redacting `Stringer` to the credential interface), and the core-SDK factory fixture
    switched from `authnMethod=none` to `client_secret_post` + `clientSecretEnvVarName` because
    v0.1.0-beta.1 removed the public-client option and rejects it at initialization.
  - New tests lock in the upgraded behaviour: context-aware refresh calls, pre-cancelled and
    deadline-exceeded short circuits, stale-window silent degradation and expired-cache
    fail-fast driven by an injected clock (`cache.SetClock`).

- `parseUTCDate` now also accepts fractional seconds (`time.RFC3339Nano` plus space-separated layouts
  with optional fraction), covering common PAM/STS returns such as `2026-10-27T10:00:00.123Z`; the
  standard no-fraction form keeps the fast `time.RFC3339` path. Previously a fractional `expiration`
  failed every refresh, exhausting the cache into blanket `CredentialExpired`.

- `normalizeEndpoint` aligned with the Python adapter's `urlparse` semantics: an explicit
  `http://`/`https://` scheme is now preserved (no longer force-upgraded to `https://`);
  only a missing scheme defaults to `https://`. Path and host:port are preserved (trailing slashes trimmed), so a PAM deployed behind a reverse-proxy subpath (e.g. `https://gw.internal/pam-api`) keeps working — dropping the path made requests land on the gateway root and 404.
- `idaasInstanceId` is now `url.PathEscape`-escaped when interpolated into the PAM request
  path, as defense-in-depth against malformed input.
- `GetStsCredential` fail-fast (cache truly expired) now returns a dedicated
  `CredentialExpired` error code instead of `PamApiError`, so cache-exhaustion is
  distinguishable from real PAM API errors in dashboards/alerts.
- `parseUTCDate` now also accepts fractional seconds (`time.RFC3339Nano` plus space-separated layouts
  with optional fraction), covering common PAM/STS returns such as `2026-10-27T10:00:00.123Z`; the
  standard no-fraction form keeps the fast `time.RFC3339` path. Previously a fractional `expiration`
  failed every refresh, exhausting the cache into blanket `CredentialExpired`.

### Fixed
- `refreshCredential` now rejects a 2xx PAM response whose `expiration` has already passed (clock skew /
  PAM anomaly) with `CredentialError(CredentialExpired)` instead of committing the unusable value: the
  previous behaviour overwrote a still-valid cached credential with the expired one, forcing a
  synchronous re-refresh against PAM on every request (a "successful" refresh never arms the backoff)
  while all callers received `CredentialExpired`. The rejected refresh now arms the supplier's
  stale-retry backoff, and stale-cache degradation keeps serving the old valid credential.
- Integration tests used the builtin `min` (Go 1.21+) for `AccessKeyId` prefix
  truncation in log output. Replaced with a `redactAK` helper that masks the key as
  `prefix**(len=N, sha256=…)` — aligned with the Core SDK's redacting
  `IDaaSCredential.String` so no AK fragment leaks into test logs — and the
  `integration` build tag compiles on all supported floors (no Go 1.21 builtin `min`).
- Examples were previously excluded from CI (`//go:build ignore`) and the release build
  step swallowed failures (`|| true`); both are corrected — examples now build under
  per-tag CI verification and release example-build failures fail the release.
- Corrected documentation (README / README_zh / CHANGELOG) that misstated the refresh
  model as "synchronous refresh at the 2/3-life point with a 1/3 buffer": the actual
  dual time-point model fires a background prefetch at the 2/3 point and a synchronous
  refresh at the 4/5 point, leaving a 1/5 stale-degrade buffer. Also corrected the
  "protocol prefix auto-stripped" endpoint note — `normalizeEndpoint` preserves an
  explicit `http://`/`https://` scheme (only a missing scheme defaults to `https://`).
- CI coverage gate silently never fired: the extraction regex `[0-9.]+$` could not match
  the `'%'`-suffixed total line, so the threshold variable stayed empty and the 80% gate was
  permanently vacuous. The gate now parses the total via awk and enforces it for real
  (measured on this tree: 95%+).
- README / README_zh / code-comment accuracy sweep: the PAM 4xx error payload is documented
  as `error`/`code` (an `error_code` field never existed); the client-secret env var's Core SDK
  default is `CLOUD_IDAAS_CLIENT_SECRET` (`IDAAS_CLIENT_SECRET` is the name configured via
  `clientSecretEnvVarName` in this repo's samples); `Close()` and the refresh-stall bounds now
  describe the real implementation; API tables cover `GetStsCredentialWithContext`,
  `WithOidcTokenProvider`, `WithPreflight` and `WithLogger`; the `WithDeveloperApiEndpoint`
  doc records that URL path is preserved (reverse-proxy subpath deployments) while query is
  dropped.


## [0.1.0-beta.2] - 2026-09-23

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
