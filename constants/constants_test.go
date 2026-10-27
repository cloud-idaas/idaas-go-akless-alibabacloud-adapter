package constants

import "testing"

// TestWireContractConstants 把适配层与 IDaaS PAM Developer API 的线上契约钉死。
//
// 这些常量不是普通字符串：请求 path / query 参数名 / 响应字段 key 是与 PAM 服务端
// （及 Java/Python 适配层）共同约定的线上协议，错误码码值与 AWS 适配层一致以便跨云
// 统一识别。任何人改动值都会静默破坏请求构造或响应解析，此测试强制改动必须是有意识的
// （同时升级所有语言的适配层并确认服务端兼容）。
func TestWireContractConstants(t *testing.T) {
	cases := []struct{ name, got, want string }{
		// --- 请求契约 ---
		{"ObtainAccessCredentialPath", ObtainAccessCredentialPath,
			"/v2/%s/cloudAccountRoles/_/actions/obtainAccessCredential"},
		{"CloudAccountRoleExternalId", CloudAccountRoleExternalId, "cloudAccountRoleExternalId"},

		// --- 响应解析契约 ---
		{"CloudAccountRoleAccessCredential", CloudAccountRoleAccessCredential, "cloudAccountRoleAccessCredential"},
		{"AlibabaCloudStsToken", AlibabaCloudStsToken, "alibabaCloudStsToken"},
		{"PAMAccessKeyId", PAMAccessKeyId, "accessKeyId"},
		{"PAMAccessKeySecret", PAMAccessKeySecret, "accessKeySecret"},
		{"PAMSecurityToken", PAMSecurityToken, "securityToken"},
		{"PAMExpiration", PAMExpiration, "expiration"},

		// --- 错误码（码值与 idaas-go-akless-aws-adapter 一致，便于跨云统一识别）---
		{"InvalidParameter", InvalidParameter, "InvalidParameter"},
		{"OidcTokenError", OidcTokenError, "OidcTokenError"},
		{"HttpError", HttpError, "HttpError"},
		{"PamApiError", PamApiError, "PamApiError"},
		{"ParseError", ParseError, "ParseError"},
		{"CredentialExpired", CredentialExpired, "CredentialExpired"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q (wire contract with PAM API; changing it breaks request/response compatibility)",
				c.name, c.got, c.want)
		}
	}
}
