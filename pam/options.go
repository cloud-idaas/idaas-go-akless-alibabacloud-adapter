package pam

import (
	"github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// 默认超时（毫秒），与 idaas-go-akless-aws-adapter 保持一致。
const (
	defaultConnectTimeout = 5000
	defaultReadTimeout    = 10000
)

// CredentialsProviderOption 配置 IDaaSPamAlibabaCloudCredentialsProvider 的函数式选项。
type CredentialsProviderOption func(*credentialsProviderConfig)

// credentialsProviderConfig 是 functional option（CredentialsProviderOption）的内部配置载体。
type credentialsProviderConfig struct {
	developerApiEndpoint string
	idaasInstanceId      string
	credentialProvider   provider.IDaaSCredentialProvider // spec F-AKLESS-CORE-02 的主参数
	oidcTokenProvider    provider.OidcTokenProvider       // 高级/测试注入；设置后优先于 credentialProvider
	roleArn              string
	connectTimeout       int
	readTimeout          int
	httpClient           http.HttpClient // 未导出，仅用于测试注入 fake client
	preflight            bool            // 构造期预检：立即换取一次 STS 验证链路，失败 fail-fast
}

// WithCredentialProvider 设置核心 SDK 凭证提供者（IDaaSCredentialProvider）。
// 适配层内部通过 oidcTokenAdapter 从中提取 AccessToken 作为 PAM 的 Bearer Token。
func WithCredentialProvider(p provider.IDaaSCredentialProvider) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.credentialProvider = p
	}
}

// WithOidcTokenProvider 直接设置 OIDC Token 提供者（高级用法，常用于测试注入）。
// 设置后优先于 WithCredentialProvider。
func WithOidcTokenProvider(p provider.OidcTokenProvider) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.oidcTokenProvider = p
	}
}

// WithDeveloperApiEndpoint 设置 PAM Developer API 端点。
//
// 端点会被 normalizeEndpoint 规范化（与 Python 适配层 urlparse 语义对齐）：
// 去除前后空白与尾部斜杠；已带 http:// 或 https:// 则保留该 scheme（不强制升级），
// 无协议前缀时默认补 https://。显式声明 http:// 的内网/开发环境不会被改写；
// 是否让 Bearer Token 走明文由调用方自负。
func WithDeveloperApiEndpoint(endpoint string) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.developerApiEndpoint = endpoint
	}
}

// WithIdaasInstanceId 设置 IDaaS 实例 ID。
func WithIdaasInstanceId(instanceId string) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.idaasInstanceId = instanceId
	}
}

// WithRoleArn 设置云账号角色外部标识（roleArn）。
// 留空时构造器从环境变量 ALIBABA_CLOUD_ROLE_ARN 兜底（对齐 Java/Python）。
func WithRoleArn(roleArn string) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.roleArn = roleArn
	}
}

// WithConnectTimeout 设置连接超时（毫秒）。
func WithConnectTimeout(timeout int) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.connectTimeout = timeout
	}
}

// WithReadTimeout 设置读取超时（毫秒）。
func WithReadTimeout(timeout int) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.readTimeout = timeout
	}
}

// withHttpClient 注入自定义 HTTP 客户端（未导出，仅用于测试）。
func withHttpClient(h http.HttpClient) CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.httpClient = h
	}
}

// WithPreflight 启用构造期预检：NewIDaaSPamAlibabaCloudCredentialsProvider 在返回前会立即向 PAM
// 换取一次 STS 凭证，验证整条链路（核心 SDK → OIDC Token → PAM → STS）是否可用，
// 任何环节失败均以原始错误 fail-fast 返回，避免配置类错误（client_secret 不匹配、
// role 未授权、端点错误等）延迟到首次业务请求才暴露。
//
// 注意：启用后构造函数会执行一次网络调用，默认不启用（遵循"构造期不做网络 IO"原则）。
// 推荐在 OSS V1 场景下启用——OSS V1 SDK 的部分调用点（conn.go:499）走无 error 返回的
// GetCredentials()，错误会被降级为空凭证 + 告警日志，预检可把这些错误前移到初始化阶段。
func WithPreflight() CredentialsProviderOption {
	return func(c *credentialsProviderConfig) {
		c.preflight = true
	}
}
