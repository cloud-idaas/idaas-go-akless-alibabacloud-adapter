package pam

import (
	sdkconstants "github.com/cloud-idaas/idaas-go-core-sdk/constants"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"
)

// 本文件提供各适配器的包级便捷构造函数（F-AKLESS-FACTORY-01）。
//
// 设计说明（Go 规范）：
// Go 的构造惯用法是包级 NewXxx/GetXxx 函数，不存在 Java 式的"静态工厂类"。因此本适配器
// 不提供 IDaaSPamAklessCredentialFactory 结构体（空结构体挂方法是 Java static 的翻译，在 Go
// 里无意义），而以包级函数表达工厂语义。这与 idaas-go-akless-aws-adapter 的
// GetAwsCredentialsProvider 包级函数一致，也与 Java IDaaSPamAklessCredentialFactory /
// Python IDaaSPamAklessCredentialFactory 的方法名、roleArn 参数语义对齐（NF-AKLESS-LANG-01
// "命名风格各语言适配"）。
//
// 每类适配器对外暴露两个入口（与 Java/Python 同构）：
//   - 便捷入口：单参 roleArn，从已初始化的核心 SDK Factory 单例取 developerApiEndpoint /
//     idaasInstanceId / credentialProvider（F-AKLESS-CORE-05）。
//   - 全参/高级入口：functional-options 构造器 NewIDaaSPamAlibabaCloudCredentialsProvider
//     （With*...），对应 Java Builder / Python 关键字参数构造器。

// fromCoreFactory 从已初始化的核心 SDK Factory 单例读取 endpoint/instanceId/credentialProvider。
func fromCoreFactory() (endpoint, instanceId string, credProvider provider.IDaaSCredentialProvider, err error) {
	f := factory.GetInstance()
	cfg := f.GetConfig()
	if cfg == nil {
		return "", "", nil, sdkerrors.NewConfigError(sdkconstants.IDaaSCredentialProviderFactoryNotInit,
			"core SDK factory is not initialized, call factory.GetInstance().Initialize(cfg) first", nil)
	}
	credProvider, err = f.CreateCredentialProvider()
	if err != nil {
		return "", "", nil, err
	}
	return cfg.DeveloperApiEndpoint, cfg.InstanceId, credProvider, nil
}

// GetAlibabaCloudCredentialsProvider 创建通用 credentials-go Credential 凭证提供者（便捷入口）。
//
// 仅需传入 roleArn，其余参数（developerApiEndpoint / idaasInstanceId / credentialProvider）
// 从已初始化的核心 SDK Factory 单例自动获取。roleArn 留空时回退到环境变量
// ALIBABA_CLOUD_ROLE_ARN（constants.RoleArnEnvVar，对齐 Java/Python）。多实例等高级
// 场景请用全参构造器 NewIDaaSPamAlibabaCloudCredentialsProvider(With*...)。
func GetAlibabaCloudCredentialsProvider(roleArn string) (*IDaaSPamAlibabaCloudCredentialsProvider, error) {
	endpoint, instanceId, credProvider, err := fromCoreFactory()
	if err != nil {
		return nil, err
	}
	return NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithCredentialProvider(credProvider),
		WithDeveloperApiEndpoint(endpoint),
		WithIdaasInstanceId(instanceId),
		WithRoleArn(roleArn),
	)
}

// GetOSSV1CredentialsProvider 创建 OSS V1 SDK CredentialsProvider（便捷入口）。
// roleArn 留空时回退到环境变量 ALIBABA_CLOUD_ROLE_ARN（见 GetAlibabaCloudCredentialsProvider）。
func GetOSSV1CredentialsProvider(roleArn string) (*IDaaSPamOSSV1CredentialsProvider, error) {
	core, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		return nil, err
	}
	return NewIDaaSPamOSSV1CredentialsProvider(core), nil
}

// GetOSSV2CredentialsProvider 创建 OSS V2 SDK CredentialsProvider（便捷入口）。
// roleArn 留空时回退到环境变量 ALIBABA_CLOUD_ROLE_ARN（见 GetAlibabaCloudCredentialsProvider）。
func GetOSSV2CredentialsProvider(roleArn string) (*IDaaSPamOSSV2CredentialsProvider, error) {
	core, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		return nil, err
	}
	return NewIDaaSPamOSSV2CredentialsProvider(core), nil
}

// GetSLSCredentialsProvider 创建 SLS SDK CredentialsProvider（便捷入口）。
// roleArn 留空时回退到环境变量 ALIBABA_CLOUD_ROLE_ARN（见 GetAlibabaCloudCredentialsProvider）。
func GetSLSCredentialsProvider(roleArn string) (*IDaaSPamSLSCredentialsProvider, error) {
	core, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		return nil, err
	}
	return NewIDaaSPamSLSCredentialsProvider(core), nil
}
