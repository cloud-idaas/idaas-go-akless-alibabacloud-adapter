package constants

// PAM Developer API 响应中阿里云 STS 凭证字段 key。
//
// 响应结构：
//
//	{
//	  "cloudAccountRoleAccessCredential": {
//	    "alibabaCloudStsToken": {
//	      "accessKeyId":     "...",
//	      "accessKeySecret": "...",
//	      "securityToken":   "...",
//	      "expiration":      "2026-01-02T15:04:05Z"
//	    }
//	  }
//	}
const (
	// CloudAccountRoleAccessCredential 外层包装 key（跨云一致）。
	CloudAccountRoleAccessCredential = "cloudAccountRoleAccessCredential"

	// AlibabaCloudStsToken 阿里云 STS Token 的内层 key。
	AlibabaCloudStsToken = "alibabaCloudStsToken"

	// PAMAccessKeyId STS AccessKey ID 字段。
	PAMAccessKeyId = "accessKeyId"

	// PAMAccessKeySecret STS AccessKey Secret 字段。
	PAMAccessKeySecret = "accessKeySecret"

	// PAMSecurityToken STS Security Token 字段。
	PAMSecurityToken = "securityToken"

	// PAMExpiration STS 过期时间字段（ISO 8601）。
	PAMExpiration = "expiration"
)

// OIDCRoleArnCredentialType akless 流程的凭证类型标识（authType）。
//
// 与 github.com/aliyun/credentials-go 自带 OIDC provider（Type="oidc_role_arn"）及
// Java 适配层 AuthConstant.OIDC_ROLE_ARN 对齐（NF-AKLESS-LANG-01 跨语言一致）。
//
// darabonba-openapi 客户端在签名阶段读取该类型：非 "bearer"/"Anonymous" 一律走
// 标准 AK/SK/SecurityToken 签名，故功能上与 "sts" 等价；但作为 Client.GetType() 的
// 返回值用于日志/遥测/调试标识凭证来源，akless 流程应标识为 "oidc_role_arn" 而非
// 静态 STS token 语义的 "sts"。
const OIDCRoleArnCredentialType = "oidc_role_arn"

// RoleArnEnvVar roleArn 的环境变量名。
//
// 当调用方未显式传入 roleArn 时，构造器从该环境变量兜底，对齐 Java/Python 适配层
// （二者在 roleArn 为空时读 ALIBABA_CLOUD_ROLE_ARN）。这样同一份环境配置可在三语言
// 间移植。
const RoleArnEnvVar = "ALIBABA_CLOUD_ROLE_ARN"
