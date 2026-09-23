package pam

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/domain"
	sdkdomain "github.com/cloud-idaas/idaas-go-core-sdk/domain"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// domainResponse 构造一个核心 SDK HttpResponse（测试辅助）。
func domainResponse(statusCode int, body []byte) *sdkdomain.HttpResponse {
	return &sdkdomain.HttpResponse{StatusCode: statusCode, Body: body}
}

// 覆盖 credentials.Credential 的 deprecated 方法与元数据方法。
func TestCredential_DeprecatedAndMetaMethods(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	if v, err := p.GetAccessKeyId(); err != nil || v == nil || *v != "AKID123" {
		t.Errorf("GetAccessKeyId=%v err=%v", v, err)
	}
	if v, err := p.GetAccessKeySecret(); err != nil || v == nil || *v != "SK123" {
		t.Errorf("GetAccessKeySecret=%v err=%v", v, err)
	}
	if v, err := p.GetSecurityToken(); err != nil || v == nil || *v != "ST123" {
		t.Errorf("GetSecurityToken=%v err=%v", v, err)
	}
	if bt := p.GetBearerToken(); bt == nil || *bt != "" {
		t.Errorf("GetBearerToken=%v", bt)
	}
	if tp := p.GetType(); tp == nil || *tp != constants.OIDCRoleArnCredentialType {
		t.Errorf("GetType=%v, want %q", tp, constants.OIDCRoleArnCredentialType)
	}
}

// 覆盖 deprecated 方法的错误分支：底层刷新失败时错误应原样冒泡（委托 GetCredential）。
func TestCredential_DeprecatedMethods_ErrorBranch(t *testing.T) {
	http := &fakeHttpClient{resp: domainResponse(500, []byte(`{"error":"internal","error_description":"boom"}`))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})
	if _, err := p.GetAccessKeyId(); err == nil {
		t.Error("GetAccessKeyId: expected error")
	}
	if _, err := p.GetAccessKeySecret(); err == nil {
		t.Error("GetAccessKeySecret: expected error")
	}
	if _, err := p.GetSecurityToken(); err == nil {
		t.Error("GetSecurityToken: expected error")
	}
}

// 覆盖 oidc_token_adapter.GetOidcToken：通过 WithCredentialProvider 路径。
func TestOidcTokenAdapter(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithCredentialProvider(&fakeIDaaSCredentialProvider{token: "adapted-token"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		withHttpClient(http),
	)
	if err != nil {
		t.Fatalf("constructor err: %v", err)
	}
	if _, err := p.GetStsCredential(); err != nil {
		t.Fatalf("GetStsCredential err: %v", err)
	}
	if p.GetOIDCToken() != "adapted-token" {
		t.Errorf("oidc token via adapter=%q, want adapted-token", p.GetOIDCToken())
	}
}

// 覆盖 oidcTokenAdapter.GetOidcToken 的错误分支：核心 SDK 取凭证失败时
// 应转为 CredentialError(OidcTokenError)，且不发起 PAM HTTP 调用。
func TestOidcTokenAdapter_ErrorBranch(t *testing.T) {
	http := &fakeHttpClient{resp: domainResponse(200, []byte(`{}`))}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithCredentialProvider(&fakeIDaaSCredentialProvider{err: errors.New("core sdk unavailable")}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		withHttpClient(http),
	)
	if err != nil {
		t.Fatalf("constructor err: %v", err)
	}
	_, err = p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error when core credential provider fails")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.OidcTokenError {
		t.Fatalf("expected CredentialError(%q), got %T: %v", constants.OidcTokenError, err, err)
	}
	if http.calls != 0 {
		t.Errorf("http calls=%d, want 0 (token acquisition fails before PAM call)", http.calls)
	}
}

// 覆盖 WithConnectTimeout / WithReadTimeout。
func TestWithOptions_Timeouts(t *testing.T) {
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(time.Now().Add(time.Hour).UTC().Format(time.RFC3339)))}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		WithConnectTimeout(2500),
		WithReadTimeout(8000),
		withHttpClient(http),
	)
	if err != nil {
		t.Fatalf("constructor err: %v", err)
	}
	if p.GetConnectTimeout() != 2500 || p.GetReadTimeout() != 8000 {
		t.Errorf("timeouts=%d/%d", p.GetConnectTimeout(), p.GetReadTimeout())
	}
}

// 覆盖 GetCredential 的错误分支。
func TestGetCredential_ErrorBranch(t *testing.T) {
	http := &fakeHttpClient{resp: domainResponse(500, []byte(`{"error":"internal","error_description":"boom"}`))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})
	if _, err := p.GetCredential(); err == nil {
		t.Fatal("expected error from GetCredential")
	}
}

// 覆盖 OSS V1 GetCredentials (非 E) 成功分支。
func TestOSSV1_GetCredentials_Success(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	core := newFakeBackedProvider(t, 200, pamSuccessBody(exp))
	v1 := NewIDaaSPamOSSV1CredentialsProvider(core)
	cred := v1.GetCredentials()
	if cred.GetAccessKeyID() != "AKID123" {
		t.Errorf("expected AKID123, got %q", cred.GetAccessKeyID())
	}
}

// 覆盖 GetOIDCToken 的 !ok 分支（注入非 string 值几乎不可达；这里仅确保空串路径已由其他用例覆盖）。
func TestGetOIDCToken_EmptyBeforeRefresh(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})
	if got := p.GetOIDCToken(); got != "" {
		t.Errorf("before refresh, want empty, got %q", got)
	}
}

// domain 包 getters。
func TestDomainCredentialGetters(t *testing.T) {
	exp := time.Now()
	c := &domain.AlibabaCloudStsCredential{
		AccessKeyId: "ak", AccessKeySecret: "sk", SecurityToken: "st", Expiration: exp,
	}
	if c.GetAccessKeyId() != "ak" || c.GetAccessKeySecret() != "sk" || c.GetSecurityToken() != "st" {
		t.Error("getter mismatch")
	}
	if !c.GetExpiration().Equal(exp) {
		t.Error("expiration mismatch")
	}
}

// 缓存的 STS 已真正过期（PAM 返回过期凭证 / PAM 持续故障缓冲耗尽）→ fail-fast 返回 error，
// 不返回过期凭证（避免下游云请求拿到 403/ExpiredToken 难以定位根因）。
// 同时覆盖 refreshCredential 的 expiresIn<=0 分支（预取点=now）。
// 使用独立错误码 CredentialExpired，区别于真实 PAM API 错误（PamApiError）。
func TestGetStsCredential_FailFastOnExpired(t *testing.T) {
	// PAM 返回一个已过期的 STS（expiration 在过去）。
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(past))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error for expired STS (fail-fast)")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CredentialError, got %T: %v", err, err)
	}
	if ce.Code != constants.CredentialExpired {
		t.Errorf("code=%q, want %q", ce.Code, constants.CredentialExpired)
	}
	if http.calls != 1 {
		t.Errorf("http calls=%d, want 1", http.calls)
	}
}

// --- WithPreflight ---

// WithPreflight 成功：构造期即换取一次 STS，返回的 provider 可直接用，PAM 被调用一次。
func TestNewProvider_Preflight_Success(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		withHttpClient(http),
		WithPreflight(),
	)
	if err != nil {
		t.Fatalf("preflight should succeed, got: %v", err)
	}
	if http.calls != 1 {
		t.Errorf("preflight should call PAM exactly once, got %d", http.calls)
	}
	if p == nil || p.GetRoleArn() != "acs:ram::123:role/demo" {
		t.Errorf("unexpected provider: %+v", p)
	}
}

// WithPreflight 失败：构造期 PAM 5xx → 原始 ServerError 透传，provider 不返回。
func TestNewProvider_Preflight_Failure(t *testing.T) {
	http := &fakeHttpClient{resp: domainResponse(500, []byte(`{"error":"internal","error_description":"boom"}`))}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		withHttpClient(http),
		WithPreflight(),
	)
	if err == nil {
		t.Fatal("preflight failure should propagate error")
	}
	if p != nil {
		t.Errorf("provider should be nil on preflight failure, got %+v", p)
	}
	var se *sdkerrors.ServerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *ServerError from preflight, got %T: %v", err, err)
	}
}

// --- 错误消息脱敏 ---

// 2xx 但缺 alibabaCloudStsToken：错误消息不得包含原始 body（防凭据泄漏）。
func TestRefreshCredential_RedactedMissingStsToken(t *testing.T) {
	http := &fakeHttpClient{resp: domainResponse(200, []byte(`{"cloudAccountRoleAccessCredential":{"alibabaCloudStsToken":{"accessKeyId":"LEAKED_AK","accessKeySecret":"","securityToken":""}}}`))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error for empty STS fields")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.ParseError {
		t.Fatalf("expected ParseError, got %v", err)
	}
	if strings.Contains(ce.Error(), "LEAKED_AK") {
		t.Errorf("error message leaks credential: %s", ce.Error())
	}
	if !strings.Contains(ce.Error(), constants.PAMAccessKeySecret) || !strings.Contains(ce.Error(), constants.PAMSecurityToken) {
		t.Errorf("error message should name missing fields, got: %s", ce.Error())
	}
}
