package pam

import (
	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
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
//   - 便捷入口：单参 roleArn，从已初始化的核心 SDK Factory 取 developerApiEndpoint /
//     idaasInstanceId / credentialProvider（F-AKLESS-CORE-05），经由包级稳定 API 读取，
//     不依赖已 Deprecated 的 GetInstance/CreateCredentialProvider。
//   - 全参/高级入口：functional-options 构造器 NewIDaaSPamAlibabaCloudCredentialsProvider
//     （With*...），对应 Java Builder / Python 关键字参数构造器。

// fromCoreFactory 从已初始化的核心 SDK Factory 读取 endpoint/instanceId/credentialProvider。
//
// 走核心 SDK 的包级稳定 API（factory.GetIDaaSCredentialProvider /
// factory.GetDeveloperApiEndpoint / factory.GetIDaaSInstanceId），不依赖已 Deprecated 的
// GetInstance / CreateCredentialProvider——二者保留为薄壳，后续小版本将移除，适配层须提前
// 脱钩以免核心 SDK 升级时编译失败。未初始化时 GetIDaaSCredentialProvider 已返回 NotInit
// 错误并透传；endpoint/instanceId 在核心 SDK 配置校验通过后必非空，此处仍兜底映射成
// InvalidParameter，避免空端点进入下游 URL 构造。
//
// 便捷路径不注入 logger：provider 回退 logger.Default()（一次性的 stderr 提示）。
// 需持续可观测的宿主应改用全参构造器 + WithLogger，或在进程启动时 logger.SetDefault(...)
// 注入真实实现——否则 PAM 刷新失败降级告警只会向 stderr 打一次后静默。
func fromCoreFactory() (endpoint, instanceId string, credProvider provider.IDaaSCredentialProvider, err error) {
	credProvider, err = factory.GetIDaaSCredentialProvider()
	if err != nil {
		return "", "", nil, err
	}
	endpoint = factory.GetDeveloperApiEndpoint()
	instanceId = factory.GetIDaaSInstanceId()
	if endpoint == "" || instanceId == "" {
		return "", "", nil, sdkerrors.NewConfigError(constants.InvalidParameter,
			"core SDK factory config missing developerApiEndpoint or idaasInstanceId, call factory.Init() first", nil)
	}
	return endpoint, instanceId, credProvider, nil
}

// GetAlibabaCloudCredentialsProvider 创建通用 credentials-go Credential 凭证提供者（便捷入口）。
//
// 仅需传入 roleArn，其余参数（developerApiEndpoint / idaasInstanceId / credentialProvider）
// 从已初始化的核心 SDK Factory 单例自动获取。多实例等高级场景请用全参构造器
// NewIDaaSPamAlibabaCloudCredentialsProvider(With*...)。
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
func GetOSSV1CredentialsProvider(roleArn string) (*IDaaSPamOSSV1CredentialsProvider, error) {
	core, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		return nil, err
	}
	return NewIDaaSPamOSSV1CredentialsProvider(core), nil
}

// GetOSSV2CredentialsProvider 创建 OSS V2 SDK CredentialsProvider（便捷入口）。
func GetOSSV2CredentialsProvider(roleArn string) (*IDaaSPamOSSV2CredentialsProvider, error) {
	core, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		return nil, err
	}
	return NewIDaaSPamOSSV2CredentialsProvider(core), nil
}

// GetSLSCredentialsProvider 创建 SLS SDK CredentialsProvider（便捷入口）。
func GetSLSCredentialsProvider(roleArn string) (*IDaaSPamSLSCredentialsProvider, error) {
	core, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		return nil, err
	}
	return NewIDaaSPamSLSCredentialsProvider(core), nil
}
