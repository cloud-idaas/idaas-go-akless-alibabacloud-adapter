package constants

// 适配层错误码（适配层本地定义；与 idaas-go-akless-aws-adapter 使用的码值一致，
// 便于跨云适配层统一识别）。
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

	// CredentialExpired 缓存的 STS 凭证已真正过期且 PAM 刷新不可用（缓冲耗尽）。
	// 与 PamApiError 区分：后者表示 PAM 返回了非 2xx，本码表示降级兜底已耗尽、
	// 调用方应将此类失败与真实 PAM API 错误分别归因。
	CredentialExpired = "CredentialExpired"
)
