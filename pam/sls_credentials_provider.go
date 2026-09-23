package pam

import (
	sls "github.com/aliyun/aliyun-log-go-sdk"
)

// IDaaSPamSLSCredentialsProvider 适配阿里云 SLS（日志服务）SDK 的
// sls.CredentialsProvider 接口。
//
// SLS 的 GetCredentials() 返回 (Credentials, error)，错误可直接冒泡。
// 凭证刷新/缓存由底层 *IDaaSPamAlibabaCloudCredentialsProvider 的 CachedResultSupplier 负责。
type IDaaSPamSLSCredentialsProvider struct {
	provider *IDaaSPamAlibabaCloudCredentialsProvider
}

// 编译期断言：实现 SLS SDK 的 sls.CredentialsProvider 接口。
var _ sls.CredentialsProvider = (*IDaaSPamSLSCredentialsProvider)(nil)

// NewIDaaSPamSLSCredentialsProvider 用通用 provider 构造 SLS 凭证适配器。
func NewIDaaSPamSLSCredentialsProvider(p *IDaaSPamAlibabaCloudCredentialsProvider) *IDaaSPamSLSCredentialsProvider {
	return &IDaaSPamSLSCredentialsProvider{provider: p}
}

// GetCredentials 实现 sls.CredentialsProvider。
func (p *IDaaSPamSLSCredentialsProvider) GetCredentials() (sls.Credentials, error) {
	cred, err := p.provider.GetStsCredential()
	if err != nil {
		return sls.Credentials{}, err
	}
	return sls.Credentials{
		AccessKeyID:     cred.AccessKeyId,
		AccessKeySecret: cred.AccessKeySecret,
		SecurityToken:   cred.SecurityToken,
	}, nil
}
