package pam

import (
	"context"

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

// GetOidcToken 实现 provider.OidcTokenProvider，等价于
// GetOidcTokenWithContext(context.Background())。
func (a *oidcTokenAdapter) GetOidcToken() (string, error) {
	return a.GetOidcTokenWithContext(context.Background())
}

// GetOidcTokenWithContext 实现 provider.OidcTokenProvider。
//
// 核心 SDK v0.1.0-beta.1 的 OidcTokenProvider 新增了本方法（Go 无默认方法，属破坏性
// 变更）。ctx 透传到 IDaaSCredentialProvider.GetCredentialWithContext，使核心 SDK 内的
// Token Endpoint / 元数据服务调用同样受刷新链路 ctx 的取消 / 超时约束，而不必等其各自
// 走到连接、读取超时上限。
func (a *oidcTokenAdapter) GetOidcTokenWithContext(ctx context.Context) (string, error) {
	cred, err := a.credProvider.GetCredentialWithContext(ctx)
	if err != nil {
		return "", err
	}
	return cred.GetAccessToken(), nil
}
