package pam

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// initCoreFactoryForTest 用最小合法配置初始化核心 SDK Factory 单例。
// 仅用于覆盖零参工厂路径的构造逻辑；不触发任何网络调用。
//
// authnMethod 用 client_secret_post + clientSecretEnvVarName：核心 SDK v0.1.0-beta.1 删除了
// TokenAuthnMethodNone（"none" 即 public client，任何能访问 token endpoint 的进程都能冒用
// clientId，故改为直接拒绝启动）。clientSecretEnvVarName 只是环境变量**名**，测试无需真设该
// 变量——只要不发起取令牌的网络调用即可。
func initCoreFactoryForTest(t *testing.T) {
	t.Helper()
	cfg := &config.IDaaSClientConfig{
		ClientId:             "client-test",
		InstanceId:           "inst-test",
		IssuerEndpoint:       "https://example.com/issuer",
		TokenEndpoint:        "https://example.com/token",
		DeveloperApiEndpoint: "pam.example.com",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			IdentityType:           enums.AuthenticationIdentityClient,
			AuthnMethod:            enums.TokenAuthnMethodClientSecretPost,
			ClientSecretEnvVarName: "IDAAS_TEST_CLIENT_SECRET",
		},
	}
	if err := factory.InitWithConfig(cfg); err != nil {
		t.Fatalf("initialize core factory: %v", err)
	}
}

// --- 包级便捷构造函数（依赖核心 SDK 单例）---

func TestFactory_PackageLevelGetters(t *testing.T) {
	initCoreFactoryForTest(t)
	roleArn := "acs:ram::123:role/demo"

	// 包级便捷函数（单参 roleArn，其余从核心 SDK Factory 单例取）。
	if p, err := GetAlibabaCloudCredentialsProvider(roleArn); err != nil {
		t.Errorf("GetAlibabaCloudCredentialsProvider: %v", err)
	} else if p == nil {
		t.Error("expected non-nil provider")
	}
	if p, err := GetOSSV1CredentialsProvider(roleArn); err != nil {
		t.Errorf("GetOSSV1CredentialsProvider: %v", err)
	} else if p == nil {
		t.Error("expected non-nil")
	}
	if p, err := GetOSSV2CredentialsProvider(roleArn); err != nil {
		t.Errorf("GetOSSV2CredentialsProvider: %v", err)
	} else if p == nil {
		t.Error("expected non-nil")
	}
	if p, err := GetSLSCredentialsProvider(roleArn); err != nil {
		t.Errorf("GetSLSCredentialsProvider: %v", err)
	} else if p == nil {
		t.Error("expected non-nil")
	}
}

// 全参/高级构造器（不依赖单例）：functional-options 构造各适配器成功。
func TestFactory_AdvancedConstructor(t *testing.T) {
	cp := &fakeIDaaSCredentialProvider{token: "tok"}
	roleArn := "acs:ram::123:role/demo"

	core, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithCredentialProvider(cp),
		WithDeveloperApiEndpoint("pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn(roleArn),
	)
	if err != nil {
		t.Fatalf("NewIDaaSPamAlibabaCloudCredentialsProvider: %v", err)
	}
	if core == nil || core.GetRoleArn() != roleArn {
		t.Errorf("unexpected core provider: %+v", core)
	}

	if p := NewIDaaSPamOSSV1CredentialsProvider(core); p == nil {
		t.Error("expected non-nil OSS V1")
	}
	if p := NewIDaaSPamOSSV2CredentialsProvider(core); p == nil {
		t.Error("expected non-nil OSS V2")
	}
	if p := NewIDaaSPamSLSCredentialsProvider(core); p == nil {
		t.Error("expected non-nil SLS")
	}
}

// 通用辅助：构造一个 fake-backed 通用 provider。
func newFakeBackedProvider(t *testing.T, statusCode int, body []byte) *IDaaSPamAlibabaCloudCredentialsProvider {
	t.Helper()
	http := &fakeHttpClient{resp: &domain.HttpResponse{StatusCode: statusCode, Body: body}}
	return newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})
}

// --- OSS V1 ---

func TestOSSV1_GetCredentialsE_Success(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	core := newFakeBackedProvider(t, 200, pamSuccessBody(exp))
	v1 := NewIDaaSPamOSSV1CredentialsProvider(core)

	cred, err := v1.GetCredentialsE()
	if err != nil {
		t.Fatalf("GetCredentialsE err: %v", err)
	}
	if cred.GetAccessKeyID() != "AKID123" || cred.GetAccessKeySecret() != "SK123" || cred.GetSecurityToken() != "ST123" {
		t.Errorf("unexpected oss v1 cred: %+v", cred)
	}
}

func TestOSSV1_GetCredentialsE_Error(t *testing.T) {
	core := newFakeBackedProvider(t, 500, []byte(`{"error":"internal","error_description":"boom"}`))
	v1 := NewIDaaSPamOSSV1CredentialsProvider(core)

	_, err := v1.GetCredentialsE()
	if err == nil {
		t.Fatal("expected error")
	}
	var se *sdkerrors.ServerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *ServerError, got %T: %v", err, err)
	}
}

func TestOSSV1_GetCredentials_BestEffort(t *testing.T) {
	core := newFakeBackedProvider(t, 500, []byte(`{"error":"internal","error_description":"boom"}`))
	v1 := NewIDaaSPamOSSV1CredentialsProvider(core)

	// GetCredentials (无 error 返回) 失败时返回空凭证，不应 panic。
	cred := v1.GetCredentials()
	if cred.GetAccessKeyID() != "" {
		t.Errorf("expected empty on error, got %q", cred.GetAccessKeyID())
	}
}

// --- OSS V2 ---

func TestOSSV2_GetCredentials_Success(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	core := newFakeBackedProvider(t, 200, pamSuccessBody(exp))
	v2 := NewIDaaSPamOSSV2CredentialsProvider(core)

	cred, err := v2.GetCredentials(context.Background())
	if err != nil {
		t.Fatalf("GetCredentials err: %v", err)
	}
	if cred.AccessKeyID != "AKID123" || cred.AccessKeySecret != "SK123" || cred.SecurityToken != "ST123" {
		t.Errorf("unexpected oss v2 cred: %+v", cred)
	}
	if cred.Expires == nil {
		t.Error("expected Expires set")
	}
}

func TestOSSV2_GetCredentials_Error(t *testing.T) {
	core := newFakeBackedProvider(t, 404, []byte(`{"code":"RoleNotFound","message":"no role"}`))
	v2 := NewIDaaSPamOSSV2CredentialsProvider(core)

	_, err := v2.GetCredentials(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	var ce *sdkerrors.ClientError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ClientError, got %T: %v", err, err)
	}
}

// --- SLS ---

func TestSLS_GetCredentials_Success(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	core := newFakeBackedProvider(t, 200, pamSuccessBody(exp))
	s := NewIDaaSPamSLSCredentialsProvider(core)

	cred, err := s.GetCredentials()
	if err != nil {
		t.Fatalf("GetCredentials err: %v", err)
	}
	if cred.AccessKeyID != "AKID123" || cred.AccessKeySecret != "SK123" || cred.SecurityToken != "ST123" {
		t.Errorf("unexpected sls cred: %+v", cred)
	}
}

func TestSLS_GetCredentials_Error(t *testing.T) {
	core := newFakeBackedProvider(t, 500, []byte(`{"error":"internal","error_description":"boom"}`))
	s := NewIDaaSPamSLSCredentialsProvider(core)

	_, err := s.GetCredentials()
	if err == nil {
		t.Fatal("expected error")
	}
	var se *sdkerrors.ServerError
	if !errors.As(err, &se) {
		t.Fatalf("expected *ServerError, got %T: %v", err, err)
	}
}

// --- 工厂 ---

// fakeIDaaSCredential 满足 credential.IDaaSCredential 接口。
type fakeIDaaSCredential struct{ token string }

func (f *fakeIDaaSCredential) GetAccessToken() string  { return f.token }
func (f *fakeIDaaSCredential) GetTokenType() string    { return "Bearer" }
func (f *fakeIDaaSCredential) GetExpiresIn() int64     { return 3600 }
func (f *fakeIDaaSCredential) GetScope() string        { return "urn:cloud:idaas:pam|.all" }
func (f *fakeIDaaSCredential) GetRefreshToken() string { return "" }

// String 实现 credential.IDaaSCredential（core SDK v0.1.0-beta.1 新增的 Stringer 兜底）：
// 返回脱敏摘要，明文 token 一律不外泄。
func (f *fakeIDaaSCredential) String() string {
	return "fakeIDaaSCredential{token: <redacted len=" + strconv.Itoa(len(f.token)) + ">}"
}

// fakeIDaaSCredentialProvider 满足 provider.IDaaSCredentialProvider 接口。
// err 非空时 GetCredential 返回错误（用于错误分支注入）。
type fakeIDaaSCredentialProvider struct {
	token string
	err   error
}

func (f *fakeIDaaSCredentialProvider) GetCredential() (credential.IDaaSCredential, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &fakeIDaaSCredential{token: f.token}, nil
}

// GetCredentialWithContext 实现 provider.IDaaSCredentialProvider
// （core SDK v0.1.0-beta.1 新增方法）。
func (f *fakeIDaaSCredentialProvider) GetCredentialWithContext(_ context.Context) (credential.IDaaSCredential, error) {
	return f.GetCredential()
}

var (
	_ provider.IDaaSCredentialProvider = (*fakeIDaaSCredentialProvider)(nil)
	_ credential.IDaaSCredential       = (*fakeIDaaSCredential)(nil)
)

// 全参构造器的参数校验：nil credentialProvider 应 fail-fast（不调 PAM、不依赖单例）。
func TestFactory_AdvancedConstructorValidation(t *testing.T) {
	if _, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithCredentialProvider(nil),
		WithDeveloperApiEndpoint("pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
	); err == nil {
		t.Fatal("expected error for nil credentialProvider")
	}
}

// 便捷函数 roleArn 环境变量兜底：传空 roleArn + env 已设 → 取 env；env 空 → 错误。
func TestFactory_RoleArnEnvFallback(t *testing.T) {
	initCoreFactoryForTest(t)

	// env 已设 + 传空 roleArn → 成功，roleArn 取自 env。
	t.Setenv(constants.RoleArnEnvVar, "acs:ram::env:role/fallback")
	p, err := GetAlibabaCloudCredentialsProvider("")
	if err != nil {
		t.Fatalf("env fallback should satisfy roleArn: %v", err)
	}
	if p.GetRoleArn() != "acs:ram::env:role/fallback" {
		t.Errorf("roleArn=%q, want env value", p.GetRoleArn())
	}

	// env 空 + 传空 roleArn → ConfigError。
	t.Setenv(constants.RoleArnEnvVar, "")
	if _, err := GetAlibabaCloudCredentialsProvider(""); err == nil {
		t.Error("expected error when roleArn and env both empty")
	}
}

func TestFactory_PackageFunctionsExist(t *testing.T) {
	// 编译期保证 4 个包级便捷函数存在且可调用。
	_ = GetAlibabaCloudCredentialsProvider
	_ = GetOSSV1CredentialsProvider
	_ = GetOSSV2CredentialsProvider
	_ = GetSLSCredentialsProvider
}
