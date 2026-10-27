package constants

// 适配层错误码（适配层本地定义）。码值与 idaas-go-akless-aws-adapter 的错误码字面量
// 一致，便于跨云适配层统一识别；本仓先行将其集中为导出常量并新增 CredentialExpired
// （凭证不可用：降级缓冲耗尽 / 刷新结果已过期），AWS 适配层待同步集中化。
const (
	// InvalidParameter 必填参数缺失或非法。
	InvalidParameter = "InvalidParameter"

	// OidcTokenError 从核心 SDK 获取 OIDC Token 失败。
	OidcTokenError = "OidcTokenError"

	// HttpError 调用 PAM Developer API 时发生传输层错误。
	HttpError = "HttpError"

	// PamApiError PAM Developer API 返回非 2xx 响应。
	PamApiError = "PamApiError"

	// ParseError PAM 响应解析失败或缺失字段。
	ParseError = "ParseError"

	// CredentialExpired 适配器判定凭证不可用且非 PAM 显式报错，两类触发：
	// ① 缓存的 STS 已真正过期且 PAM 刷新不可用（降级缓冲耗尽）；② PAM 返回 200
	// 但 expiration 已过期（时钟偏移 / PAM 异常），刷新按失败拒绝。与 PamApiError
	// 区分：后者表示 PAM 返回了非 2xx；调用方应将此类失败与真实 PAM API 错误分别归因。
	CredentialExpired = "CredentialExpired"
)
