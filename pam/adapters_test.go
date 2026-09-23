package pam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/config"
	sdkconstants "github.com/cloud-idaas/idaas-go-core-sdk/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/credential"
	"github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

// initCoreFactoryForTest 用最小合法配置初始化核心 SDK Factory 单例（public client，无需凭证）。
// 仅用于覆盖包级便捷构造函数（从单例取参）路径；不触发任何网络调用。
func initCoreFactoryForTest(t *testing.T) {
	t.Helper()
	cfg := &config.IDaaSClientConfig{
		ClientId:             "client-test",
		InstanceId:           "inst-test",
		IssuerEndpoint:       "https://example.com/issuer",
		TokenEndpoint:        "https://example.com/token",
		DeveloperApiEndpoint: "pam.example.com",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			IdentityType: enums.AuthenticationIdentityClient,
			AuthnMethod:  enums.TokenAuthnMethodNone,
		},
	}
	if err := factory.GetInstance().Initialize(cfg); err != nil {
		t.Fatalf("initialize core factory: %v", err)
	}
}

// --- 包级便捷构造函数（依赖核心 SDK 单例）---

// TestFactory_NotInitialized 验证核心 SDK Factory 未初始化时便捷构造函数的报错
// （用户忘了先调 factory.GetInstance().Initialize(cfg) 的场景）。
//
// 顺序敏感：单例一旦初始化无法复位（核心 SDK 无 Reset），故本用例必须是本包
// 首个执行的测试——adapters_test.go 是包内按文件名排序的首个测试文件，本函数
// 是其首个测试函数。IsInitialized 守卫保证未来顺序被打破时跳过而非误报。
func TestFactory_NotInitialized(t *testing.T) {
	if factory.GetInstance().IsInitialized() {
		t.Skip("core factory singleton already initialized by an earlier test; " +
			"cannot exercise the not-initialized branch (test-order dependency)")
	}
	_, err := GetAlibabaCloudCredentialsProvider("acs:ram::123:role/demo")
	if err == nil {
		t.Fatal("expected error when core factory is not initialized")
	}
	var ce *sdkerrors.ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ConfigError, got %T: %v", err, err)
	}
	if ce.Code != sdkconstants.IDaaSCredentialProviderFactoryNotInit {
		t.Errorf("code=%q, want %q", ce.Code, sdkconstants.IDaaSCredentialProviderFactoryNotInit)
	}
	// 其余三个便捷构造函数同样应透传未初始化错误。
	if _, err := GetOSSV1CredentialsProvider("acs:ram::123:role/demo"); err == nil {
		t.Error("expected error for GetOSSV1CredentialsProvider")
	}
	if _, err := GetOSSV2CredentialsProvider("acs:ram::123:role/demo"); err == nil {
		t.Error("expected error for GetOSSV2CredentialsProvider")
	}
	if _, err := GetSLSCredentialsProvider("acs:ram::123:role/demo"); err == nil {
		t.Error("expected error for GetSLSCredentialsProvider")
	}
}

// TestFactory_CreateCredentialProviderError 验证核心 Factory 已初始化但 IdentityType
// 非法时，便捷构造函数把 CreateCredentialProvider 的错误透传。
// Initialize 只校验字段格式（不校验 IdentityType 枚举），错误延迟到
// CreateCredentialProvider 的 switch default 分支才暴露。
func TestFactory_CreateCredentialProviderError(t *testing.T) {
	cfg := &config.IDaaSClientConfig{
		ClientId:             "client-test",
		InstanceId:           "inst-test",
		IssuerEndpoint:       "https://example.com/issuer",
		TokenEndpoint:        "https://example.com/token",
		DeveloperApiEndpoint: "pam.example.com",
		AuthnConfiguration: &config.IdentityAuthenticationConfiguration{
			IdentityType: enums.AuthenticationIdentityEnum("GHOST"),
			AuthnMethod:  enums.TokenAuthnMethodNone,
		},
	}
	if err := factory.GetInstance().Initialize(cfg); err != nil {
		t.Fatalf("initialize core factory: %v", err)
	}
	t.Cleanup(func() { initCoreFactoryForTest(t) }) // 还原为合法配置，避免影响后续用例

	_, err := GetAlibabaCloudCredentialsProvider("acs:ram::123:role/demo")
	if err == nil {
		t.Fatal("expected error for unsupported identity type")
	}
	var ce *sdkerrors.ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ConfigError, got %T: %v", err, err)
	}
	if ce.Code != "UnsupportedIdentityType" {
		t.Errorf("code=%q, want UnsupportedIdentityType", ce.Code)
	}
	// 其余三个便捷构造函数同样应透传该错误。
	if _, err := GetOSSV1CredentialsProvider("acs:ram::123:role/demo"); err == nil {
		t.Error("expected error for GetOSSV1CredentialsProvider")
	}
	if _, err := GetOSSV2CredentialsProvider("acs:ram::123:role/demo"); err == nil {
		t.Error("expected error for GetOSSV2CredentialsProvider")
	}
	if _, err := GetSLSCredentialsProvider("acs:ram::123:role/demo"); err == nil {
		t.Error("expected error for GetSLSCredentialsProvider")
	}
}

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
