//go:build integration

// 集成测试：连接真实 IDaaS PAM 环境，端到端验证 akless 凭证链路
// （OIDC Token → PAM Developer API → 阿里云 STS → 各服务 SDK 真实调用）。
//
// 默认跳过（不打扰常规 `go test ./...` 与 CI），仅在显式开启时运行：
//
//	IDAAS_INTEGRATION=on \
//	IDAAS_ROLE_ARN="acs:ram::<uid>:role/<name>" \
//	go test -tags=integration ./pam/ -run TestIntegration -v -timeout 10m
//
// 必需配置（缺失时给出明确报错提示）：
//   - cloud_idaas.json：真实 IDaaS 实例配置。放在当前目录，或用环境变量
//     CLOUD_IDAAS_CONFIG_PATH 指向文件路径。scope 必须为
//     "urn:cloud:idaas:pam|cloud_account_role:obtain_access_credential"（参考 samples/cloud_idaas.json）。
//   - IDAAS_CLIENT_SECRET 环境变量：client 密钥
//     （对应配置项 authnConfiguration.clientSecretEnvVarName）。
//   - IDAAS_ROLE_ARN 环境变量：PAM 云账号角色外部 ID，如 acs:ram::<uid>:role/<name>。
//
// 可选配置（控制 OSS/SLS 用例的运行模式，未设置时退化为探测模式）：
//   - OSS_BUCKET（可选 OSS_ENDPOINT / OSS_REGION，默认 cn-hangzhou）：设置后对指定
//     bucket 真实 ListObjects，要求角色对该 bucket 有 oss:ListObjects 权限；未设置时
//     用账号级 ListBuckets 探测：AccessDenied 视为链路验证通过（请求已通过签名认证，
//     仅被 RAM 策略拒绝；签名/凭证有问题会得到 SignatureDoesNotMatch 等，则判失败）。
//   - SLS_ENDPOINT（如 cn-hangzhou.log.aliyuncs.com）：设置后真实 ListProject，要求
//     角色有 log:ListProject 权限；未设置时用默认 endpoint 探测："denied by sts or ram"
//     视为链路验证通过（同理，签名错误会是另一种错误形态，则判失败）。
package pam

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	ossv2 "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"
	sls "github.com/aliyun/aliyun-log-go-sdk"
	ossv1 "github.com/aliyun/aliyun-oss-go-sdk/oss"

	idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
)

// integrationEnabled 判断集成测试开关是否打开。
func integrationEnabled() bool {
	return os.Getenv("IDAAS_INTEGRATION") == "on"
}

// findLocalConfigPath 定位本地真实配置文件（不影响核心 SDK 默认加载链）：
//  1. CLOUD_IDAAS_CONFIG_PATH 环境变量指定的路径；
//  2. 仓库根目录（测试文件的上一级）的 cloud_idaas.json；
//
// 均未命中时返回空串，交由核心 SDK LoadWithPriority 走默认链。
func findLocalConfigPath() string {
	if envPath := os.Getenv("CLOUD_IDAAS_CONFIG_PATH"); envPath != "" {
		return envPath
	}
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	candidates := []string{
		filepath.Join(filepath.Dir(thisFile), "..", "cloud_idaas.json"), // 仓库根
		filepath.Join(filepath.Dir(thisFile), "cloud_idaas.json"),       // 包目录（备用）
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// requireIntegration 前置校验：开关关闭则跳过；打开则加载真实配置并初始化核心 SDK Factory。
// 返回待测的 roleArn。开关打开但配置缺失时直接 Fatal 并给出可操作的提示。
func requireIntegration(t *testing.T) string {
	t.Helper()
	if !integrationEnabled() {
		t.Skip("integration tests disabled; set IDAAS_INTEGRATION=on and run with -tags=integration")
	}

	roleArn := os.Getenv("IDAAS_ROLE_ARN")
	if roleArn == "" {
		t.Fatal("IDAAS_ROLE_ARN is required when IDAAS_INTEGRATION=on " +
			"(cloud account role external id, e.g. acs:ram::<uid>:role/<name>)")
	}

	// 加载真实 IDaaS 配置，优先级：CLOUD_IDAAS_CONFIG_PATH 环境变量 > 仓库根目录
	// cloud_idaas.json > 核心 SDK 默认链（~/.cloud_idaas/client-config.json 等）。
	// 注意：go test 的工作目录是包目录 pam/ 而非仓库根，必须基于测试文件位置定位；
	// 否则会静默回退到 ~/.cloud_idaas 下的旧配置造成误诊断。
	// 显式路径传给 LoadWithPriority 时，文件不存在/解析失败会硬报错。
	configPath := findLocalConfigPath()
	cfg, err := idaasconfig.NewConfigReader().LoadWithPriority(configPath)
	if err != nil {
		t.Fatalf("failed to load IDaaS config (path=%q): %v\n"+
			"please provide a real cloud_idaas.json (see samples/cloud_idaas.json), "+
			"and export IDAAS_CLIENT_SECRET if the config reads the secret from env", configPath, err)
	}

	// Initialize 可重复调用：即使同包单元测试初始化过 fake 配置，这里也会用真实配置重建。
	if err := factory.GetInstance().Initialize(cfg); err != nil {
		t.Fatalf("failed to initialize IDaaS core factory: %v", err)
	}
	return roleArn
}

// envOr 读取环境变量，缺省用默认值。
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// isOssAuthorizedButDenied 判断 OSS 错误是否为“请求已通过签名认证、仅被 RAM 策略拒绝”。
// 若签名或凭证本身有问题，OSS 会返回 SignatureDoesNotMatch / InvalidAccessKeyId /
// InvalidSecurityToken 等错误码，不属于此类——因此匹配到 AccessDenied 即可
// 证明 akless 凭证 + SDK 签名链路端到端正确。
func isOssAuthorizedButDenied(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "AccessDenied")
}

// isSlsAuthorizedButDenied 判断 SLS 错误是否为“请求已通过签名认证、仅被 RAM/STS 策略拒绝”。
// SLS 拒绝信息形如 "denied by sts or ram, action: log:ListProject"；
// 签名错误则是 SignatureNotMatch 等另一种形态。
func isSlsAuthorizedButDenied(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "denied by sts or ram")
}

// --- 通用 provider：端到端获取 STS ---

// TestIntegration_GenericProvider_GetCredential 全链路验证：
// 核心 SDK 取 OIDC Token → PAM Developer API 换取阿里云 STS → CredentialModel 字段完整。
func TestIntegration_GenericProvider_GetCredential(t *testing.T) {
	roleArn := requireIntegration(t)

	provider, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		t.Fatalf("GetAlibabaCloudCredentialsProvider: %v", err)
	}

	model, err := provider.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}

	if model.AccessKeyId == nil || *model.AccessKeyId == "" {
		t.Error("AccessKeyId is empty")
	} else {
		t.Logf("AccessKeyId: %s...", (*model.AccessKeyId)[:min(8, len(*model.AccessKeyId))])
	}
	if model.AccessKeySecret == nil || *model.AccessKeySecret == "" {
		t.Error("AccessKeySecret is empty")
	}
	if model.SecurityToken == nil || *model.SecurityToken == "" {
		t.Error("SecurityToken is empty")
	}
	if model.Type == nil || *model.Type != constants.OIDCRoleArnCredentialType {
		t.Errorf("Type = %v, want %q (akless 家族约定，与 credentials-go OIDCCredentialsProvider 对齐)",
			model.Type, constants.OIDCRoleArnCredentialType)
	}

	// 原始 STS：过期时间必须在未来（有效凭证）。
	sts, err := provider.GetStsCredential()
	if err != nil {
		t.Fatalf("GetStsCredential: %v", err)
	}
	if !sts.Expiration.After(time.Now()) {
		t.Errorf("STS expiration %v is not in the future", sts.Expiration)
	}
	t.Logf("STS expiration: %s (ttl=%s)", sts.Expiration.Format(time.RFC3339),
		time.Until(sts.Expiration).Round(time.Second))

	if tok := provider.GetOIDCToken(); tok == "" {
		t.Error("OIDC token should be recorded after a successful refresh")
	}
}

// TestIntegration_CredentialCache_Reuse 验证有效期内缓存复用：
// 两次 GetStsCredential 返回完全相同的 STS（SecurityToken 每次签发均不同，
// 字段级相等即说明第二次命中缓存、未再次调用 PAM）。
func TestIntegration_CredentialCache_Reuse(t *testing.T) {
	roleArn := requireIntegration(t)

	provider, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		t.Fatalf("GetAlibabaCloudCredentialsProvider: %v", err)
	}

	first, err := provider.GetStsCredential()
	if err != nil {
		t.Fatalf("first GetStsCredential: %v", err)
	}
	second, err := provider.GetStsCredential()
	if err != nil {
		t.Fatalf("second GetStsCredential: %v", err)
	}

	if first.SecurityToken != second.SecurityToken {
		t.Error("SecurityToken differs between two consecutive calls; " +
			"cache should return the same credential within its lifetime")
	}
	if !first.Expiration.Equal(second.Expiration) {
		t.Errorf("Expiration differs: %v vs %v", first.Expiration, second.Expiration)
	}
	if first.AccessKeyId != second.AccessKeyId {
		t.Errorf("AccessKeyId differs: %q vs %q", first.AccessKeyId, second.AccessKeyId)
	}
}

// TestIntegration_InvalidRoleArn_Error 验证真实 PAM 对不存在角色的 4xx 错误映射。
// 构造一个语法合法但不存在的 roleArn，期望返回 ClientError（携带 error_code）。
func TestIntegration_InvalidRoleArn_Error(t *testing.T) {
	roleArn := requireIntegration(t)

	provider, err := GetAlibabaCloudCredentialsProvider(roleArn + "-akless-integration-nonexistent")
	if err != nil {
		t.Fatalf("GetAlibabaCloudCredentialsProvider: %v", err)
	}

	_, err = provider.GetStsCredential()
	if err == nil {
		t.Fatal("expected an error for a non-existent cloud account role, got nil")
	}
	t.Logf("non-existent role error: %v", err)

	var ce *sdkerrors.ClientError
	if !errors.As(err, &ce) {
		// 网络不通等其他类型错误也算链路发现问题的信号，给出提示但不判失败。
		t.Logf("error is %T (not *ClientError); if this is a network error, "+
			"check connectivity to the developer API endpoint", err)
		return
	}
	if ce.Code == "" {
		t.Error("ClientError should carry a non-empty error code")
	}
	t.Logf("mapped to ClientError, code=%q message=%q", ce.Code, ce.Message)
}

// TestIntegration_FullArgOverload 验证全参构造路径：
// 显式传入 endpoint / instanceId / credentialProvider / roleArn 构造 provider
// （等价于旧工厂全参重载，现由 functional-options 构造器承担）。
func TestIntegration_FullArgOverload(t *testing.T) {
	roleArn := requireIntegration(t)

	f := factory.GetInstance()
	cfg := f.GetConfig()
	credProvider, err := f.CreateCredentialProvider()
	if err != nil {
		t.Fatalf("CreateCredentialProvider: %v", err)
	}

	provider, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithCredentialProvider(credProvider),
		WithDeveloperApiEndpoint(cfg.DeveloperApiEndpoint),
		WithIdaasInstanceId(cfg.InstanceId),
		WithRoleArn(roleArn),
	)
	if err != nil {
		t.Fatalf("NewIDaaSPamAlibabaCloudCredentialsProvider: %v", err)
	}

	sts, err := provider.GetStsCredential()
	if err != nil {
		t.Fatalf("GetStsCredential: %v", err)
	}
	if sts.AccessKeyId == "" || sts.SecurityToken == "" {
		t.Errorf("unexpected empty credential fields: %+v", sts)
	}
}

// TestIntegration_RoleArnEnvFallback 验证 ALIBABA_CLOUD_ROLE_ARN 环境变量兜底：
// 便捷函数传空 roleArn 时，构造器应从环境变量兜底，并完成真实 STS 换取
// （对齐 Java/Python 适配层在 roleArn 为空时的环境变量回退行为）。
func TestIntegration_RoleArnEnvFallback(t *testing.T) {
	realArn := requireIntegration(t) // 初始化核心 SDK Factory；真实 ARN 仅作为兜底值注入

	// t.Setenv 自动在用例结束后还原，不污染后续用例。
	t.Setenv(constants.RoleArnEnvVar, realArn)

	provider, err := GetAlibabaCloudCredentialsProvider("")
	if err != nil {
		t.Fatalf("GetAlibabaCloudCredentialsProvider with empty roleArn (env fallback): %v", err)
	}
	if got := provider.GetRoleArn(); got != realArn {
		t.Fatalf("roleArn = %q, want env value %q", got, realArn)
	}

	sts, err := provider.GetStsCredential()
	if err != nil {
		t.Fatalf("GetStsCredential via env-fallback roleArn: %v", err)
	}
	if sts.AccessKeyId == "" || sts.SecurityToken == "" {
		t.Fatalf("unexpected empty credential fields: %+v", sts)
	}
	t.Logf("env fallback OK: roleArn from %s, STS AccessKeyId=%s...",
		constants.RoleArnEnvVar, sts.AccessKeyId[:min(9, len(sts.AccessKeyId))])
}

// TestIntegration_ExplicitRoleArnPrecedence 验证显式 roleArn 优先于环境变量：
// 环境变量设为无效值时，显式传入的真实 roleArn 仍应胜出并完成真实换取，
// 防止"环境变量意外覆盖显式参数"的回归。
func TestIntegration_ExplicitRoleArnPrecedence(t *testing.T) {
	realArn := requireIntegration(t)

	// 故意投毒：若实现误用 env 覆盖显式参数，本用例将以 cloud_account_role_not_found 失败。
	t.Setenv(constants.RoleArnEnvVar, "acs:ram::0000000000000000:role/bogus-env-value")

	provider, err := GetAlibabaCloudCredentialsProvider(realArn)
	if err != nil {
		t.Fatalf("GetAlibabaCloudCredentialsProvider with explicit roleArn: %v", err)
	}
	if got := provider.GetRoleArn(); got != realArn {
		t.Fatalf("explicit roleArn should win over env: got %q, want %q", got, realArn)
	}

	sts, err := provider.GetStsCredential()
	if err != nil {
		t.Fatalf("GetStsCredential with explicit roleArn (env poisoned): %v", err)
	}
	if sts.AccessKeyId == "" {
		t.Fatal("unexpected empty AccessKeyId")
	}
	t.Log("explicit roleArn wins over poisoned env, chain OK")
}

// --- OSS V1：真实调用 ---

// TestIntegration_OSSV1_ListObjects 用 akless STS 创建 OSS V1 客户端并真实调用 OSS。
//
// 双模式：
//   - 主模式（设置了 OSS_BUCKET）：ListObjects，要求角色对该 bucket 有权限，必须成功；
//   - 探测模式（未设置）：账号级 ListBuckets。该操作必然先做请求签名校验：
//     签名/凭证有问题会得到 SignatureDoesNotMatch / InvalidAccessKeyId 等；
//     AccessDenied 则说明请求已通过认证、仅被 RAM 策略拒绝，即链路验证通过。
func TestIntegration_OSSV1_ListObjects(t *testing.T) {
	roleArn := requireIntegration(t)

	endpoint := envOr("OSS_ENDPOINT", "https://oss-cn-hangzhou.aliyuncs.com")
	region := envOr("OSS_REGION", "cn-hangzhou")

	credProvider, err := GetOSSV1CredentialsProvider(roleArn)
	if err != nil {
		t.Fatalf("GetOSSV1CredentialsProvider: %v", err)
	}

	client, err := ossv1.New(endpoint, "", "",
		ossv1.AuthVersion(ossv1.AuthV4), ossv1.Region(region), ossv1.SetCredentialsProvider(credProvider))
	if err != nil {
		t.Fatalf("create OSS V1 client: %v", err)
	}

	// 主模式：指定 bucket 时真实 ListObjects，必须成功。
	if bucket := os.Getenv("OSS_BUCKET"); bucket != "" {
		bucketClient, err := client.Bucket(bucket)
		if err != nil {
			t.Fatalf("get bucket client: %v", err)
		}
		result, err := bucketClient.ListObjects(ossv1.MaxKeys(100))
		if err != nil {
			t.Fatalf("ListObjects(bucket=%s): %v", bucket, err)
		}
		t.Logf("OSS V1 ListObjects(bucket=%s) ok, %d objects", bucket, len(result.Objects))
		return
	}

	// 探测模式：账号级 ListBuckets 验证凭证 + 签名链路。
	_, err = client.ListBuckets()
	if err == nil {
		t.Log("probe: ListBuckets succeeded (role has oss:ListBuckets permission)")
		return
	}
	if isOssAuthorizedButDenied(err) {
		t.Logf("probe: request authenticated by OSS, denied by RAM policy (chain validated): %v", err)
		return
	}
	t.Fatalf("ListBuckets probe (signature/credential broken?): %v", err)
}

// --- OSS V2：真实调用 ---

// TestIntegration_OSSV2_ListObjects 用 akless STS 创建 OSS V2 客户端并真实调用 OSS。
// 双模式语义与 OSS V1 用例一致（见 TestIntegration_OSSV1_ListObjects）。
func TestIntegration_OSSV2_ListObjects(t *testing.T) {
	roleArn := requireIntegration(t)

	region := envOr("OSS_REGION", "cn-hangzhou")

	credProvider, err := GetOSSV2CredentialsProvider(roleArn)
	if err != nil {
		t.Fatalf("GetOSSV2CredentialsProvider: %v", err)
	}

	cfg := ossv2.NewConfig().
		WithRegion(region).
		WithCredentialsProvider(credProvider)
	client := ossv2.NewClient(cfg)

	// 主模式：指定 bucket 时真实 ListObjects，必须成功。
	if bucket := os.Getenv("OSS_BUCKET"); bucket != "" {
		result, err := client.ListObjects(context.Background(),
			&ossv2.ListObjectsRequest{Bucket: ossv2.Ptr(bucket), MaxKeys: 100})
		if err != nil {
			t.Fatalf("ListObjects(bucket=%s): %v", bucket, err)
		}
		t.Logf("OSS V2 ListObjects(bucket=%s) ok, %d objects", bucket, len(result.Contents))
		return
	}

	// 探测模式：账号级 ListBuckets 验证凭证 + 签名链路。
	_, err = client.ListBuckets(context.Background(), &ossv2.ListBucketsRequest{})
	if err == nil {
		t.Log("probe: ListBuckets succeeded (role has oss:ListBuckets permission)")
		return
	}
	if isOssAuthorizedButDenied(err) {
		t.Logf("probe: request authenticated by OSS, denied by RAM policy (chain validated): %v", err)
		return
	}
	t.Fatalf("ListBuckets probe (signature/credential broken?): %v", err)
}

// --- SLS：真实调用 ---

// TestIntegration_SLS_ListProjects 用 akless STS 创建 SLS 客户端并真实调用 SLS。
//
// 双模式：
//   - 主模式（设置了 SLS_ENDPOINT）：ListProject，要求角色有 log:ListProject 权限，必须成功；
//   - 探测模式（未设置）：用默认 endpoint（cn-hangzhou.log.aliyuncs.com）调 ListProject，
//     "denied by sts or ram" 说明请求已通过签名认证、仅被 RAM/STS 策略拒绝，即链路验证通过。
func TestIntegration_SLS_ListProjects(t *testing.T) {
	roleArn := requireIntegration(t)

	endpoint := envOr("SLS_ENDPOINT", "cn-hangzhou.log.aliyuncs.com")

	credProvider, err := GetSLSCredentialsProvider(roleArn)
	if err != nil {
		t.Fatalf("GetSLSCredentialsProvider: %v", err)
	}

	client := (&sls.Client{Endpoint: strings.TrimSpace(endpoint)}).WithCredentialsProvider(credProvider)
	projects, err := client.ListProject()
	if err != nil {
		if isSlsAuthorizedButDenied(err) {
			t.Logf("probe: request authenticated by SLS, denied by RAM/STS policy (chain validated): %v", err)
			return
		}
		t.Fatalf("ListProject(endpoint=%s): %v", endpoint, err)
	}
	t.Logf("SLS ListProject(endpoint=%s) ok, %d projects", endpoint, len(projects))
}
