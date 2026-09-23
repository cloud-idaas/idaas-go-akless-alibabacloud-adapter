package constants

// PAM Developer API 请求相关常量。
//
// 该契约跨云（AWS / 腾讯云 / 阿里云）一致：相同的 path、相同的 query 参数名、
// 相同的外层包装 key；仅内层 <cloud>StsToken 的 key 与字段名不同。
const (
	// ObtainAccessCredentialPath PAM Developer API 获取云账号角色访问凭证的路径模板。
	// %s 占位符为 IDaaS 实例 ID（idaasInstanceId）。
	ObtainAccessCredentialPath = "/v2/%s/cloudAccountRoles/_/actions/obtainAccessCredential"

	// CloudAccountRoleExternalId 查询参数名，值为云账号角色的外部标识（roleArn）。
	CloudAccountRoleExternalId = "cloudAccountRoleExternalId"
)
