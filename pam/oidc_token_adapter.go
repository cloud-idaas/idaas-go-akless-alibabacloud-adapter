package pam

import (
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// oidcTokenAdapter 将核心 SDK 的 IDaaSCredentialProvider 适配为 OidcTokenProvider。
//
// 核心 SDK 的 IDaaSCredentialProvider.GetCredential() 返回 IDaaSCredential，
// 其中的 AccessToken 即作为访问 PAM Developer API 的 Bearer Token。
// 这与 idaas-go-akless-aws-adapter/pam/factory.go 中的桥接逻辑一致。
type oidcTokenAdapter struct {
	credProvider provider.IDaaSCredentialProvider
}

// GetOidcToken 实现 provider.OidcTokenProvider。
func (a *oidcTokenAdapter) GetOidcToken() (string, error) {
	cred, err := a.credProvider.GetCredential()
	if err != nil {
		return "", err
	}
	return cred.GetAccessToken(), nil
}
