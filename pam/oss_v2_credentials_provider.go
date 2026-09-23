package pam

import (
	"context"

	"github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss/credentials"
)

// IDaaSPamOSSV2CredentialsProvider 适配阿里云 OSS V2 SDK 的
// credentials.CredentialsProvider 接口。
//
// OSS V2 的 GetCredentials(ctx) 返回 (Credentials, error)，错误可直接冒泡。
// 凭证刷新/缓存由底层 *IDaaSPamAlibabaCloudCredentialsProvider 的 CachedResultSupplier 负责。
type IDaaSPamOSSV2CredentialsProvider struct {
	provider *IDaaSPamAlibabaCloudCredentialsProvider
}

// 编译期断言：实现 OSS V2 SDK 的 credentials.CredentialsProvider 接口。
var _ credentials.CredentialsProvider = (*IDaaSPamOSSV2CredentialsProvider)(nil)

// NewIDaaSPamOSSV2CredentialsProvider 用通用 provider 构造 OSS V2 凭证适配器。
func NewIDaaSPamOSSV2CredentialsProvider(p *IDaaSPamAlibabaCloudCredentialsProvider) *IDaaSPamOSSV2CredentialsProvider {
	return &IDaaSPamOSSV2CredentialsProvider{provider: p}
}

// GetCredentials 实现 credentials.CredentialsProvider。
func (p *IDaaSPamOSSV2CredentialsProvider) GetCredentials(_ context.Context) (credentials.Credentials, error) {
	cred, err := p.provider.GetStsCredential()
	if err != nil {
		return credentials.Credentials{}, err
	}
	expiration := cred.Expiration
	return credentials.Credentials{
		AccessKeyID:     cred.AccessKeyId,
		AccessKeySecret: cred.AccessKeySecret,
		SecurityToken:   cred.SecurityToken,
		Expires:         &expiration,
	}, nil
}
