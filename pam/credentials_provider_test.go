package pam

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	token string
	err   error
}

func (f *fakeOidcTokenProvider) GetOidcToken() (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.token, nil
}

// fakeHttpClient 记录调用次数、捕获最近一次请求，并返回预设响应。
// 并发用例（singleflight 合并）下被多 goroutine 调用，用互斥锁保护计数与捕获。
type fakeHttpClient struct {
	mu      sync.Mutex
	resp    *domain.HttpResponse
	err     error
	calls   int
	lastReq *domain.HttpRequest
}

func (f *fakeHttpClient) Execute(req *domain.HttpRequest) (*domain.HttpResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReq = req
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
		{"HTTPS://API.X.COM", "https://API.X.COM"},         // scheme 小写、host 保留大小写
		{"http://api.x.com:8080", "http://api.x.com:8080"}, // 保留端口
		{"https://api.x.com/pam", "https://api.x.com"},     // 丢弃 path（base endpoint）
		{"ftp://api.x.com", "https://api.x.com"},           // 非 http(s) scheme 归一为 https
		{"https:///path", "https://https:///path"},         // host 缺失（异常输入）→ 回退加 https:// 前缀
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

// parsePamError 对超大 body 的截断边界：512 字节以内不截断，超出保留前 512 字节 + 标记。
func TestParsePamError_TruncatesLargeBody(t *testing.T) {
	// 正好 512 字节：不截断（边界语义为 <=）。
	at512 := strings.Repeat("x", 512)
	if _, msg := parsePamError([]byte(at512), 502); strings.HasSuffix(msg, "...(truncated)") {
		t.Errorf("512-byte body should not be truncated, got tail %q", msg[len(msg)-20:])
	}
	// 超出 512 字节：保留前 512 字节 + 截断标记。
	code, msg := parsePamError([]byte(strings.Repeat("x", 600)), 502)
	if code != constants.PamApiError {
		t.Errorf("code=%q, want %q", code, constants.PamApiError)
	}
	if !strings.HasSuffix(msg, "...(truncated)") {
		t.Errorf("oversized body should be truncated, got %q", msg)
	}
	if !strings.Contains(msg, at512) {
		t.Error("truncated msg should keep the first 512 bytes")
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

// --- 并发与降级契约（README 公开承诺的行为，必须有测试守护）---

// 并发 singleflight 合并：N 个并发请求在缓存缺失时应合并为仅 1 次 PAM 调用，
// 且所有请求拿到同一份凭证（防止并发穿透把 PAM 打挂）。
func TestGetStsCredential_ConcurrentSingleflight(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	const n = 20
	errs := make([]error, n)
	tokens := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cred, err := p.GetStsCredential()
			if err != nil {
				errs[i] = err
				return
			}
			if cred != nil {
				tokens[i] = cred.SecurityToken
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if tokens[i] != "ST123" {
			t.Errorf("goroutine %d: unexpected credential token %q", i, tokens[i])
		}
	}
	if http.calls != 1 {
		t.Errorf("http calls=%d, want 1 (singleflight should coalesce concurrent refreshes)", http.calls)
	}
}

// 刷新失败降级契约：越过 2/3 刷新点后 PAM 故障 → 仍返回有效期内的旧缓存凭证（stale 降级），
// 错误不抛给调用方；与 FailFastOnExpired（真正过期才报 CredentialExpired）共同构成完整降级语义。
// 核心SDK supplier 的 Clock 为私有字段无注入通道，故用短 TTL（3s）+ RFC3339Nano 纳秒精度
// 锁定刷新点（+2.0s），睡眠 2.4s 落在 (刷新点, 真实过期点 +3.0s) 区间内，无需 fake clock。
func TestGetStsCredential_DegradeToStaleOnRefreshFailure(t *testing.T) {
	// TTL=3s：刷新点=now+2s（2/3 处），真实过期=now+3s。
	exp := time.Now().Add(3 * time.Second).UTC().Format(time.RFC3339Nano)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	if _, err := p.GetStsCredential(); err != nil {
		t.Fatalf("initial fetch: %v", err)
	}

	// 睡到越过刷新点（+2s）但仍在凭证有效期内（+3s）。
	time.Sleep(2400 * time.Millisecond)

	// PAM 故障：后续刷新全部失败。
	http.mu.Lock()
	http.err = fmt.Errorf("pam unavailable")
	http.mu.Unlock()

	cred, err := p.GetStsCredential()
	if err != nil {
		t.Fatalf("expected stale degrade (old credential, no error), got err: %v", err)
	}
	if cred == nil || cred.AccessKeyId != "AKID123" || cred.SecurityToken != "ST123" {
		t.Fatalf("expected old cached credential, got %+v", cred)
	}
	// 刷新确实被尝试过（1 次初始 + 1 次失败刷新）——证明这是降级路径而非普通缓存命中。
	if http.calls != 2 {
		t.Errorf("http calls=%d, want 2 (initial + failed refresh attempt)", http.calls)
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

// --- 缺失外层 cloudAccountRoleAccessCredential → ParseError ---

func TestRefreshCredential_MissingAccessCredential(t *testing.T) {
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: []byte(`{"foo":"bar"}`)}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error for response missing cloudAccountRoleAccessCredential")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.ParseError {
		t.Fatalf("expected ParseError, got %v", err)
	}
	if !strings.Contains(ce.Error(), constants.CloudAccountRoleAccessCredential) {
		t.Errorf("error should name missing field, got: %s", ce.Error())
	}
}

// --- STS 字段为空串（accessKeyId）→ ParseError ---

func TestRefreshCredential_EmptyStsFields(t *testing.T) {
	body := []byte(`{"cloudAccountRoleAccessCredential":{"alibabaCloudStsToken":{` +
		`"accessKeyId":"","accessKeySecret":"SK123","securityToken":"ST123",` +
		`"expiration":"2099-01-01T00:00:00Z"}}}`)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: body}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error for empty accessKeyId")
	}
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.ParseError {
		t.Fatalf("expected ParseError, got %v", err)
	}
	if !strings.Contains(ce.Error(), constants.PAMAccessKeyId) {
		t.Errorf("error should name missing field %q, got: %s", constants.PAMAccessKeyId, ce.Error())
	}
}

// --- 过期时间格式非法 → ParseError ---

func TestRefreshCredential_InvalidExpiration(t *testing.T) {
	body := []byte(`{"cloudAccountRoleAccessCredential":{"alibabaCloudStsToken":{` +
		`"accessKeyId":"AKID123","accessKeySecret":"SK123","securityToken":"ST123",` +
		`"expiration":"not-a-date"}}}`)
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: 200, Body: body}}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	if err == nil {
		t.Fatal("expected error for invalid expiration format")
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
