package pam

import (
	"log/slog"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
)

// IDaaSPamOSSV1CredentialsProvider 适配阿里云 OSS V1 SDK 的 CredentialsProvider 接口。
//
// OSS V1 的 oss.CredentialsProvider.GetCredentials() 不返回 error；OSS V1 SDK 在
// conn.go 中会优先类型断言到 oss.CredentialsProviderE 并调用 GetCredentialsE()，
// 因此本实现同时实现两个接口，使错误能通过 GetCredentialsE 冒泡。
// 凭证刷新/缓存由底层 *IDaaSPamAlibabaCloudCredentialsProvider 的 CachedResultSupplier 负责。
type IDaaSPamOSSV1CredentialsProvider struct {
	provider *IDaaSPamAlibabaCloudCredentialsProvider
}

// 编译期断言：同时实现 oss.CredentialsProvider 与 oss.CredentialsProviderE，
// 使错误能通过 GetCredentialsE 冒泡（OSS V1 SDK conn.go 优先走 CredentialsProviderE）。
var _ oss.CredentialsProviderE = (*IDaaSPamOSSV1CredentialsProvider)(nil)
var _ oss.Credentials = (*ossV1Credentials)(nil)

// NewIDaaSPamOSSV1CredentialsProvider 用通用 provider 构造 OSS V1 凭证适配器。
func NewIDaaSPamOSSV1CredentialsProvider(p *IDaaSPamAlibabaCloudCredentialsProvider) *IDaaSPamOSSV1CredentialsProvider {
	return &IDaaSPamOSSV1CredentialsProvider{provider: p}
}

// GetCredentials 实现 oss.CredentialsProvider（best-effort：失败时返回空凭证）。
// 优先实现 GetCredentialsE 以返回错误。
//
// 注意：OSS V1 SDK 的部分调用点直接调用 GetCredentials() 而非 GetCredentialsE()，
// 该接口无 error 返回。失败时此处返回空凭证并记录告警日志，避免错误被静默吞掉后、
// 下游 OSS 请求用空凭证签名失败却难以排查根因。
func (p *IDaaSPamOSSV1CredentialsProvider) GetCredentials() oss.Credentials {
	cred, err := p.GetCredentialsE()
	if err != nil {
		slog.Warn("IDaaSPamOSSV1CredentialsProvider: get credentials failed; "+
			"returning empty credentials (OSS V1 GetCredentials has no error return)",
			"error", err)
		return &ossV1Credentials{}
	}
	return cred
}

// GetCredentialsE 实现 oss.CredentialsProviderE，返回错误。
func (p *IDaaSPamOSSV1CredentialsProvider) GetCredentialsE() (oss.Credentials, error) {
	cred, err := p.provider.GetStsCredential()
	if err != nil {
		return nil, err
	}
	return &ossV1Credentials{
		accessKeyId:     cred.AccessKeyId,
		accessKeySecret: cred.AccessKeySecret,
		securityToken:   cred.SecurityToken,
	}, nil
}

// ossV1Credentials 实现 oss.Credentials 接口。
type ossV1Credentials struct {
	accessKeyId     string
	accessKeySecret string
	securityToken   string
}

func (c *ossV1Credentials) GetAccessKeyID() string     { return c.accessKeyId }
func (c *ossV1Credentials) GetAccessKeySecret() string { return c.accessKeySecret }
func (c *ossV1Credentials) GetSecurityToken() string   { return c.securityToken }
