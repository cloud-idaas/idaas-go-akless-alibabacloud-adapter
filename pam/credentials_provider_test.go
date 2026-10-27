package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
	sdkconstants "github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	sdkhttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// --- fakes ---

type fakeOidcTokenProvider struct {
	token   string
	err     error
	lastCtx context.Context
}

func (f *fakeOidcTokenProvider) GetOidcToken() (string, error) {
	return f.GetOidcTokenWithContext(context.Background())
}

// GetOidcTokenWithContext 实现 provider.OidcTokenProvider（core SDK v0.1.0-beta.1 新增方法）。
func (f *fakeOidcTokenProvider) GetOidcTokenWithContext(ctx context.Context) (string, error) {
	f.lastCtx = ctx
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

var _ provider.OidcTokenProvider = (*fakeOidcTokenProvider)(nil)

// fakeHttpClient 记录调用次数、捕获最近一次请求与 ctx，并返回预设响应。
type fakeHttpClient struct {
	resp    *domain.HttpResponse
	err     error
	calls   int
	lastReq *domain.HttpRequest
	lastCtx context.Context
	// release 非空时 ExecuteContext 会阻塞直到该 channel 被关闭，用于模拟"PAM 刷新很慢"，
	// 从而验证调用方 ctx 取消/超时时能立即结束等待。
	release chan struct{}
}

func (f *fakeHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	return f.ExecuteContext(context.Background(), req)
}

// ExecuteContext 实现 sdkhttp.HttpClient（core SDK v0.1.0-beta.1 新增方法）。
func (f *fakeHttpClient) ExecuteContext(ctx context.Context, req *domain.HttpRequest) (*domain.HttpResponse, error) {
	f.calls++
	f.lastCtx = ctx
	f.lastReq = req
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeHttpClient) Get(_ string, _ map[string]string) (*domain.HttpResponse, error) {
	return f.Execute(nil)
}

func (f *fakeHttpClient) Post(_ string, _ map[string]string, _ interface{}) (*domain.HttpResponse, error) {
	return f.Execute(nil)
}

// 确保 fakeHttpClient 实现 sdkhttp.HttpClient 接口。
var _ sdkhttp.HttpClient = (*fakeHttpClient)(nil)

// newProviderWithFake 构造一个注入了 fake http + fake oidc 的 provider，用于测试。
func newProviderWithFake(t *testing.T, http *fakeHttpClient, oidc provider.OidcTokenProvider) *IDaaSPamAlibabaCloudCredentialsProvider {
	t.Helper()
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(oidc),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		withHttpClient(http),
	)
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	return p
}

func pamSuccessBody(expiration string) []byte {
	b, _ := json.Marshal(map[string]interface{}{
		"cloudAccountRoleAccessCredential": map[string]interface{}{
			"alibabaCloudStsToken": map[string]interface{}{
				"accessKeyId":     "AKID123",
				"accessKeySecret": "SK123",
				"securityToken":   "ST123",
				"expiration":      expiration,
			},
		},
	})
	return b
}

// --- normalizeEndpoint ---

func TestNormalizeEndpoint(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://api.x.com", "https://api.x.com"},
		{"http://api.x.com", "http://api.x.com"},    // 显式 http 保留（对齐 Python）
		{"api.x.com", "https://api.x.com"},          // 无 scheme 默认 https
		{"https://api.x.com/", "https://api.x.com"}, // 去尾部斜杠
		{"https://api.x.com//", "https://api.x.com"},
		{"  api.x.com  ", "https://api.x.com"},
		{"HTTPS://API.X.COM", "https://API.X.COM"},                      // scheme 小写、host 保留大小写
		{"http://api.x.com:8080", "http://api.x.com:8080"},              // 保留端口
		{"https://api.x.com/pam", "https://api.x.com/pam"},              // 保留 path（支持反代子路径部署）
		{"https://gw.internal/pam-api/", "https://gw.internal/pam-api"}, // 保留 path、strip 尾斜杠
		{"https://api.x.com", "https://api.x.com"},                      // 无 path 不追加
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeEndpoint(c.in); got != c.want {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// --- parseUTCDate ---

func TestParseUTCDate(t *testing.T) {
	if _, err := parseUTCDate(""); err == nil {
		t.Error("expected error for empty date")
	}
	if _, err := parseUTCDate("not-a-date"); err == nil {
		t.Error("expected error for garbage")
	}
	valid := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05+00:00",
		"2006-01-02 15:04:05",
	}
	for _, f := range valid {
		// 用该格式生成一个未来时间再解析
		ts := time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC).Format(f)
		if _, err := parseUTCDate(ts); err != nil {
			t.Errorf("parseUTCDate(%q from %q) err: %v", ts, f, err)
		}
	}

	// 带小数秒（毫秒/纳秒）的 ISO 8601 形态——STS/PAM 类服务常见返回。
	// time.RFC3339 不接受小数秒，须由 time.RFC3339Nano / 空格+小数秒格式承接。
	withFraction := []string{
		"2026-01-02T15:04:05.123Z",
		"2026-01-02T15:04:05.123456789Z",
		"2026-01-02T15:04:05.123+00:00",
		"2026-01-02 15:04:05.123",
	}
	for _, ts := range withFraction {
		if _, err := parseUTCDate(ts); err != nil {
			t.Errorf("parseUTCDate(%q) err: %v", ts, err)
		}
	}
}

// --- parsePamError ---

func TestParsePamError(t *testing.T) {
	// OAuth2 格式
	code, msg := parsePamError([]byte(`{"error":"invalid_request","error_description":"bad"}`), 400)
	if code != "invalid_request" || msg != "bad" {
		t.Errorf("oauth2 fmt: code=%q msg=%q", code, msg)
	}
	// IDaaS 自定义格式
	code, msg = parsePamError([]byte(`{"code":"NotFound","message":"no role"}`), 404)
	if code != "NotFound" || msg != "no role" {
		t.Errorf("idaas fmt: code=%q msg=%q", code, msg)
	}
	// 非 JSON → 回退 PamApiError
	code, msg = parsePamError([]byte(`plain text`), 500)
	if code != constants.PamApiError {
		t.Errorf("fallback code=%q, want %q", code, constants.PamApiError)
	}
	if msg == "" {
		t.Error("fallback msg should not be empty")
	}
}

// --- 构造校验 ---

func TestNewIDaaSPamAlibabaCloudCredentialsProvider_Validation(t *testing.T) {
	// 确定性：本机可能已设 ALIBABA_CLOUD_ROLE_ARN，清空以免 roleArn 走 env 兜底污染"缺参"用例。
	t.Setenv(constants.RoleArnEnvVar, "")
	oidc := &fakeOidcTokenProvider{token: "tok"}
	cases := []struct {
		name string
		opts []CredentialsProviderOption
	}{
		{"missing roleArn", []CredentialsProviderOption{
			WithOidcTokenProvider(oidc), WithDeveloperApiEndpoint("e"), WithIdaasInstanceId("i")}},
		{"missing instanceId", []CredentialsProviderOption{
			WithOidcTokenProvider(oidc), WithDeveloperApiEndpoint("e"), WithRoleArn("r")}},
		{"missing endpoint", []CredentialsProviderOption{
			WithOidcTokenProvider(oidc), WithIdaasInstanceId("i"), WithRoleArn("r")}},
		{"missing token source", []CredentialsProviderOption{
			WithDeveloperApiEndpoint("e"), WithIdaasInstanceId("i"), WithRoleArn("r")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewIDaaSPamAlibabaCloudCredentialsProvider(c.opts...)
			if err == nil {
				t.Fatalf("expected error")
			}
			var ce *sdkerrors.ConfigError
			if !errors.As(err, &ce) {
				t.Fatalf("expected *ConfigError, got %T: %v", err, err)
			}
			if ce.Code != constants.InvalidParameter {
				t.Errorf("code=%q, want %q", ce.Code, constants.InvalidParameter)
			}
		})
	}
}

// --- roleArn 环境变量兜底（对齐 Java/Python）---

// 未传 WithRoleArn 且环境变量已设 → 构造成功，roleArn 取自 env。
func TestNewProvider_RoleArnEnvFallback(t *testing.T) {
	t.Setenv(constants.RoleArnEnvVar, "acs:ram::env:role/fallback")
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody(exp)}}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		withHttpClient(http),
		// 故意不传 WithRoleArn
	)
	if err != nil {
		t.Fatalf("expected env fallback to satisfy roleArn, got: %v", err)
	}
	if p.GetRoleArn() != "acs:ram::env:role/fallback" {
		t.Errorf("roleArn=%q, want env fallback value", p.GetRoleArn())
	}
}

// 未传 WithRoleArn 且环境变量为空 → ConfigError(InvalidParameter)。
func TestNewProvider_RoleArnMissingWithoutEnv(t *testing.T) {
	t.Setenv(constants.RoleArnEnvVar, "")
	_, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
	)
	if err == nil {
		t.Fatal("expected error when roleArn and env var both empty")
	}
	var ce *sdkerrors.ConfigError
	if !errors.As(err, &ce) || ce.Code != constants.InvalidParameter {
		t.Fatalf("expected ConfigError(InvalidParameter), got %T: %v", err, err)
	}
}

// 显式 WithRoleArn 优先于环境变量。
func TestNewProvider_RoleArnExplicitOverridesEnv(t *testing.T) {
	t.Setenv(constants.RoleArnEnvVar, "env-role")
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody(exp)}}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("explicit-role"),
		withHttpClient(http),
	)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if p.GetRoleArn() != "explicit-role" {
		t.Errorf("roleArn=%q, want explicit value overriding env", p.GetRoleArn())
	}
}

// --- refreshCredential: 成功 + 缓存命中 ---

func TestGetStsCredential_SuccessAndCache(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody(exp)}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	cred, err := p.GetStsCredential()
	if err != nil {
		t.Fatalf("GetStsCredential err: %v", err)
	}
	if cred.AccessKeyId != "AKID123" || cred.AccessKeySecret != "SK123" || cred.SecurityToken != "ST123" {
		t.Errorf("unexpected cred: %+v", cred)
	}
	if !cred.Expiration.After(time.Now()) {
		t.Error("expiration should be in the future")
	}
	// 第二次应命中缓存，不再次调用 PAM。
	if _, err := p.GetStsCredential(); err != nil {
		t.Fatalf("second GetStsCredential err: %v", err)
	}
	if http.calls != 1 {
		t.Errorf("http calls=%d, want 1 (cache miss+hit)", http.calls)
	}
}

// --- 请求构造（F-AKLESS-CORE-01：GET / roleArn 经 Query（cloudAccountRoleExternalId）/ Bearer 来自 OIDC）---

func TestRefreshCredential_RequestConstruction(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody(exp)}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	if _, err := p.GetStsCredential(); err != nil {
		t.Fatalf("GetStsCredential err: %v", err)
	}
	req := http.lastReq
	if req == nil {
		t.Fatal("expected http request to be captured")
	}
	// Method 为 GET。
	if req.Method != enums.HttpMethodGet {
		t.Errorf("method=%v, want GET", req.Method)
	}
	// URL = normalizeEndpoint(endpoint) + path(url.PathEscape(instanceId))，无 query 串。
	wantURL := "https://pam.example.com/v2/inst-123/cloudAccountRoles/_/actions/obtainAccessCredential"
	if req.URL != wantURL {
		t.Errorf("url=%q, want %q", req.URL, wantURL)
	}
	// Bearer Token 来自 OIDC provider。
	if got := req.Headers[sdkconstants.HeaderAuthorization]; got != "Bearer tok" {
		t.Errorf("authorization=%q, want 'Bearer tok'", got)
	}
	if got := req.Headers[sdkconstants.HeaderAccept]; got != sdkconstants.ContentTypeJson {
		t.Errorf("accept=%q, want %q", got, sdkconstants.ContentTypeJson)
	}
	// roleArn 经 Query 参数（cloudAccountRoleExternalId）传递。
	if got := req.QueryParams.Get(constants.CloudAccountRoleExternalId); got != "acs:ram::123:role/demo" {
		t.Errorf("query cloudAccountRoleExternalId=%q, want role arn", got)
	}
}

// --- GetCredential 字段映射 ---

func TestGetCredential_Mapping(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody(exp)}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	model, err := p.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential err: %v", err)
	}
	if *model.AccessKeyId != "AKID123" || *model.AccessKeySecret != "SK123" || *model.SecurityToken != "ST123" {
		t.Errorf("unexpected model: %+v", model)
	}
	if *model.Type != constants.OIDCRoleArnCredentialType {
		t.Errorf("type=%q, want %q", *model.Type, constants.OIDCRoleArnCredentialType)
	}
}

// --- 4xx → ClientError ---

func TestRefreshCredential_4xx(t *testing.T) {
	http := &fakeHttpClient{resp: &domain.HttpResponse{
		StatusCode: 404,
		Body:       []byte(`{"code":"RoleNotFound","message":"role not found"}`),
	}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *sdkerrors.ClientError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ClientError, got %T: %v", err, err)
	}
	if ce.Code != "RoleNotFound" {
		t.Errorf("code=%q, want RoleNotFound", ce.Code)
	}
}

// --- 5xx → ServerError ---

func TestRefreshCredential_5xx(t *testing.T) {
	http := &fakeHttpClient{resp: &domain.HttpResponse{
		StatusCode: 500,
		Body:       []byte(`{"error":"internal","error_description":"boom"}`),
	}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error")
	}
	var se *sdkerrors.ServerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *ServerError, got %T: %v", err, err)
	}
	if se.Code != "internal" || se.StatusCode != 500 {
		t.Errorf("code=%q status=%d, want internal/500", se.Code, se.StatusCode)
	}
}

// --- OIDC token 获取失败 → CredentialError(OidcTokenError) ---

func TestRefreshCredential_OidcError(t *testing.T) {
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody("2099-01-01T00:00:00Z")}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{err: fmt.Errorf("network down")})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CredentialError, got %T: %v", err, err)
	}
	if ce.Code != constants.OidcTokenError {
		t.Errorf("code=%q, want %q", ce.Code, constants.OidcTokenError)
	}
	if http.calls != 0 {
		t.Errorf("http should not be called on oidc failure, calls=%d", http.calls)
	}
}

// --- 空 OIDC token → CredentialError(OidcTokenError) ---

func TestRefreshCredential_EmptyOidcToken(t *testing.T) {
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody("2099-01-01T00:00:00Z")}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: ""})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error for empty OIDC token")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CredentialError, got %T: %v", err, err)
	}
	if ce.Code != constants.OidcTokenError {
		t.Errorf("code=%q, want %q", ce.Code, constants.OidcTokenError)
	}
	if http.calls != 0 {
		t.Errorf("http should not be called on empty token, calls=%d", http.calls)
	}
}

// --- HTTP 传输错误 → CredentialError(HttpError) ---

func TestRefreshCredential_HttpError(t *testing.T) {
	http := &fakeHttpClient{err: fmt.Errorf("connection refused")}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *CredentialError, got %T: %v", err, err)
	}
	if ce.Code != constants.HttpError {
		t.Errorf("code=%q, want %q", ce.Code, constants.HttpError)
	}
}

// --- 非 JSON 响应 → ParseError ---

func TestRefreshCredential_NonJSON(t *testing.T) {
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: []byte(`not json`)}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.ParseError {
		t.Fatalf("expected ParseError, got %v", err)
	}
}

// --- 缺失 alibabaCloudStsToken → ParseError ---

func TestRefreshCredential_MissingStsToken(t *testing.T) {
	http := &fakeHttpClient{resp: &domain.HttpResponse{
		StatusCode: 200,
		Body:       []byte(`{"cloudAccountRoleAccessCredential":{}}`),
	}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.ParseError {
		t.Fatalf("expected ParseError, got %v", err)
	}
}

// --- 字段暴露 ---

func TestGetters(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody(exp)}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})
	// 触发一次刷新以填充 oidcToken。
	if _, err := p.GetStsCredential(); err != nil {
		t.Fatalf("GetStsCredential err: %v", err)
	}
	if p.GetRoleArn() != "acs:ram::123:role/demo" {
		t.Errorf("roleArn=%q", p.GetRoleArn())
	}
	if p.GetIdaasInstanceId() != "inst-123" {
		t.Errorf("instanceId=%q", p.GetIdaasInstanceId())
	}
	if p.GetDeveloperApiEndpoint() != "https://pam.example.com" {
		t.Errorf("endpoint=%q", p.GetDeveloperApiEndpoint())
	}
	if p.GetOIDCToken() != "tok" {
		t.Errorf("oidcToken=%q", p.GetOIDCToken())
	}
	if p.GetConnectTimeout() != defaultConnectTimeout || p.GetReadTimeout() != defaultReadTimeout {
		t.Errorf("timeouts=%d/%d", p.GetConnectTimeout(), p.GetReadTimeout())
	}
}

// --- Close ---

// Close 幂等、不 panic；调用后 provider 仍可正常工作（重新刷新）。
func TestClose_IdempotentAndUsable(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: pamSuccessBody(exp)}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	if err := p.Close(); err != nil {
		t.Errorf("first Close err: %v", err)
	}
	if err := p.Close(); err != nil { // 幂等
		t.Errorf("second Close err: %v", err)
	}
	// Close 后仍可使用（重新刷新，命中 fake）。
	if _, err := p.GetStsCredential(); err != nil {
		t.Errorf("GetStsCredential after Close err: %v", err)
	}
}
