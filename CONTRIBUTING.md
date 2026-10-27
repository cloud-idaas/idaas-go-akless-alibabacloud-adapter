# Contributing to idaas-go-akless-alibabacloud-adapter

First of all — thank you for taking the time to contribute! 🎉

This project is the Go adapter in the IDaaS AKless family (sibling to the
Java/Python Alibaba Cloud adapters and the Go AWS adapter). It obtains Alibaba
Cloud STS temporary credentials via the IDaaS PAM Developer API so that
applications can call Alibaba Cloud services without long-lived access keys.

The following guidelines help keep the adapter consistent, secure, and
cross-language-aligned.

## Prerequisites

- **Go >= 1.18** (the `go` directive in `go.mod` is the enforced floor; CI
  builds and tests on 1.18 to verify the declared minimum).
- A working checkout of [`idaas-go-core-sdk`](https://github.com/cloud-idaas/idaas-go-core-sdk)
  (pinned via `go.mod`; `go mod tidy` will fetch it).
- Familiarity with the [Core SDK's](https://github.com/cloud-idaas/idaas-go-core-sdk)
  `logger` / `cache` / `errors` / `http` / `factory` packages — this adapter is a
  thin layer over them.

## Development workflow

```bash
# 1. Fork & clone, then from the repo root:
go mod tidy

# 2. Format + vet
gofmt -w .
go vet ./...

# 3. Run the unit tests with coverage (CI enforces >= 80%)
go test ./... -race -coverprofile=coverage.out -covermode=atomic
go tool cover -func=coverage.out | tail -1

# 4. Build every example (each has its own build tag)
for ex in generic oss_v1 oss_v2 sls; do
  go build -tags="example_${ex}" -o /tmp/example_build_${ex} ./examples
done

# 5. Vulnerability scan (CI runs this too)
go run golang.org/x/vuln/cmd/govulncheck@v1.0.4 ./...
govulncheck ./...
```

### Integration tests (opt-in)

Integration tests hit a real IDaaS PAM and live Alibaba Cloud endpoints. They
are skipped by default and only run when explicitly enabled:

```bash
IDAAS_INTEGRATION=on \
IDAAS_ROLE_ARN="acs:ram::<uid>:role/<name>" \
go test -tags=integration ./pam/ -run TestIntegration -v -timeout 10m
```

See [`pam/integration_test.go`](pam/integration_test.go) for the required config
files and environment variables. **Never commit real credentials** —
`cloud_idaas.json`, `*.local.json`, `client-config.json`, and `.env*` are
already git-ignored.

## Coding standards

- **Go floor.** Do not raise the `go` directive above 1.18 without a deliberate
  decision and a CHANGELOG entry. In particular, avoid `log/slog` (Go 1.21) and
  the builtin `min`/`max` (Go 1.21) — use the Core SDK `logger` abstraction and
  local helpers instead. CI on 1.18 will catch regressions.
- **Cross-language wire contract.** The PAM request path, query parameter names,
  response field keys, `oidc_role_arn` credential type, and error code values are
  shared with the Java/Python adapters. They are pinned in
  [`constants/constants_test.go`](constants/constants_test.go). Changing any value
  is a breaking wire-protocol change and must be coordinated across all three
  languages and confirmed against the PAM service.
- **Logger.** Use the injected `p.logger` (or `logger.Default()` fallback), never
  `log/slog` or `fmt.Println` in production code. See `WithLogger`.
- **No secrets in errors/logs.** Error messages must name *missing fields*, never
  embed the raw PAM response body or credential values. Non-2xx bodies are
  truncated (`truncateBody`, 512 bytes). Test logs redact access keys via
  `redactAK` (SHA-256 prefix), aligned with the Core SDK's `IDaaSCredential.String`.
- **Functional options.** New configuration goes through a `With*` option on
  `NewIDaaSPamAlibabaCloudCredentialsProvider`, mirroring the Java `Builder` /
  Python keyword-argument style.
- **Compile-time interface assertions.** Every credential-provider interface is
  asserted with `var _ <iface> = (*T)(nil)` so upstream signature changes fail at
  build time, not at the call site.

## Pull requests

1. Branch from `main` (`feature/<topic>` or `fix/<topic>`).
2. Keep changes focused; one concern per PR.
3. Update `CHANGELOG.md` under `## [Unreleased]` (Keep a Changelog format).
4. Ensure CI is green: fmt, vet, govulncheck, build, examples (per-tag),
   tests with >= 80% coverage.
5. If you touch the wire contract or the refresh time-point model, update
   `README.md`, `README_zh.md`, and the in-code doc comments together — they
   have diverged before.

## Security disclosures

**Do not open a public issue for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the responsible-reporting process.

## Code of conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
Please be kind.
