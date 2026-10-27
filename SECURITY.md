# Security Policy

This adapter obtains Alibaba Cloud STS temporary credentials via the IDaaS PAM
Developer API. Security is a top priority. This document describes how to
responsibly report vulnerabilities and what to expect.

## Supported versions

Only the latest minor release line receives security fixes. The project is
currently in **0.1.x beta**; breaking changes may occur before 1.0 GA.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ latest beta line |
| < 0.1.0 | ❌ not supported   |

## Reporting a vulnerability

**Do not open a public GitHub issue** for a suspected security vulnerability.

Please report privately via
[GitHub Security Advisory → "Report a vulnerability"](https://github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/security/advisories/new).

Include in your report:

- A description of the issue and its potential impact.
- The version / commit you tested against.
- A minimal reproduction. **Do not include real credentials** (AccessKeyId,
  AccessKeySecret, SecurityToken, OIDC tokens, or client secrets). Redact them
  or use synthetic values.
- Whether the issue affects the Java/Python sibling adapters (this helps us
  coordinate a cross-language fix).

## Response timeline

We will acknowledge receipt within **3 business days** and aim to provide an
initial assessment within **7 business days**. A fix or mitigation will be
released as soon as practicable, coordinated with public disclosure after the
fix is available.

## Scope

In scope:

- Leakage of credentials (AccessKeyId / AccessKeySecret / SecurityToken / OIDC
  token / client secret) through error messages, logs, or the credential
  `String()` representation.
- Authentication or authorization bypass in the PAM credential refresh chain.
- Token-lifetime / cache-staleness defects that could serve an expired or
  stale credential to downstream Alibaba Cloud SDKs.
- URL / header injection in the PAM request construction.
- Path-traversal or injection via `idaasInstanceId` interpolation.

Out of scope:

- Vulnerabilities in upstream dependencies — report them upstream
  (`idaas-go-core-sdk`, `aliyun-oss-go-sdk`, `aliyun-log-go-sdk`,
  `credentials-go`, `alibabacloud-oss-go-sdk-v2`). You may open an issue here so
  we can track and pin a fixed version.
- Findings from running the adapter against an IDaaS instance you do not own
  without authorization.

## Known dependency risks

### aliyun-log-go-sdk pinned to v0.1.74

`aliyun-log-go-sdk` is pinned to **v0.1.74**, one patch behind the latest
v0.1.75. The downgrade is deliberate: v0.1.75 declares `go 1.19` in its
`go.mod`, which would break this adapter's Go 1.18 compatibility floor (the
floor shared by the tencent and alibabacloud sibling adapters; only the aws
adapter requires Go 1.22 due to `aws-sdk-go-v2 v1.36.3`).

The SLS API surface consumed by `pam/integration_test.go` (`sls.Client{}`,
`.WithCredentialsProvider`, `.ListProject`) is unchanged between v0.1.74 and
v0.1.75 — only the module's declared Go floor moved.

**Residual risk:** the release notes for v0.1.75 are not retrievable in this
environment (GitHub releases / raw CHANGELOG return HTTP 403), so we cannot
definitively rule out a security fix landing in v0.1.75 that this pin skips.
If you operate this adapter in a hardened SLS-heavy workload and learn of a
v0.1.75 security advisory, treat the Go-floor conflict as a tracked debt and
re-evaluate: either raise the adapter's Go floor (coordinating with the
sibling adapters) or backport the specific fix. Until then the pin is on the
"sustained-Go-1.18-compatibility" side of the trade, and the known API
surface is verified by the integration test suite under `-tags=integration`.

## Safe disclosure

We are committed to acknowledging reporters. If you would like to be credited
in the release notes, include a name/handle in your report; we will credit you
unless you ask to remain anonymous.

Reporting in good faith is appreciated and will not result in legal action.
