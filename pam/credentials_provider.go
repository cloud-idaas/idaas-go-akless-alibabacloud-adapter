// Package pam 实现 Alibaba Cloud akless 适配层的凭证提供者。
//
// 通过 IDaaS PAM Developer API 用 OIDC Token（来自核心 SDK）换取阿里云 STS 临时凭证，
// 并适配 github.com/aliyun/credentials-go 的 Credential 接口，供阿里云各服务 SDK 使用。
package pam

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/domain"

	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	sdkconstants "github.com/cloud-idaas/idaas-go-core-sdk/constants"
	sdkdomain "github.com/cloud-idaas/idaas-go-core-sdk/domain"
	"github.com/cloud-idaas/idaas-go-core-sdk/enums"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
	sdkhttp "github.com/cloud-idaas/idaas-go-core-sdk/http"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"

	"github.com/aliyun/credentials-go/credentials"
)

// IDaaSPamAlibabaCloudCredentialsProvider 通过 IDaaS PAM Developer API 获取阿里云 STS 凭证，
// 并实现 github.com/aliyun/credentials-go/credentials.Credential 接口。
//
// 缓存与刷新复用核心 SDK 的 cache.CachedResultSupplier（StaleValueBehaviorRefresh +
// singleflight）。刷新点设在 STS 寿命 2/3 处（ExpiresAt=prefetchPoint），首个越过该点
// 的请求同步刷新、其余并发请求由 singleflight 合并等待；若刷新失败则降级返回仍有效的
// 旧缓存（剩余 1/3 寿命缓冲），旧缓存亦真正过期时 fail-fast。
type IDaaSPamAlibabaCloudCredentialsProvider struct {
	roleArn              string
	oidcToken            atomic.Value // 最近一次使用的 OIDC Token，供 GetOIDCToken() 暴露
	oidcTokenProvider    provider.OidcTokenProvider
	connectTimeout       int
	readTimeout          int
	idaasInstanceId      string
	developerApiEndpoint string
	developerApiPath     string
	httpClient           sdkhttp.HttpClient
	supplier             *cache.CachedResultSupplier[*domain.AlibabaCloudStsCredential]
}

// 编译期断言：IDaaSPamAlibabaCloudCredentialsProvider 必须实现 credentials-go 的 Credential 接口。
// 上游 SDK 升级若变更接口签名，此处立即编译失败，避免把适配缺陷推迟到用户调用点。
var _ credentials.Credential = (*IDaaSPamAlibabaCloudCredentialsProvider)(nil)

// NewIDaaSPamAlibabaCloudCredentialsProvider 创建通用凭证提供者（functional options）。
//
// 必填参数（F-AKLESS-CORE-02 / F-AKLESS-CORE-03）：developerApiEndpoint、idaasInstanceId、
// credentialProvider（或 oidcTokenProvider）、roleArn。缺一抛 ConfigError(InvalidParameter)。
//
// roleArn 未显式传入时，从环境变量 ALIBABA_CLOUD_ROLE_ARN 兜底（constants.RoleArnEnvVar），
// 对齐 Java/Python 适配层在 roleArn 为空时的环境变量回退行为。
func NewIDaaSPamAlibabaCloudCredentialsProvider(opts ...CredentialsProviderOption) (*IDaaSPamAlibabaCloudCredentialsProvider, error) {
	cfg := &credentialsProviderConfig{
		connectTimeout: defaultConnectTimeout,
		readTimeout:    defaultReadTimeout,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.roleArn == "" {
		// 未显式传入 roleArn 时，从环境变量兜底（对齐 Java/Python 适配层）。
		cfg.roleArn = os.Getenv(constants.RoleArnEnvVar)
	}
	if cfg.roleArn == "" {
		return nil, sdkerrors.NewConfigError(constants.InvalidParameter,
			"roleArn cannot be empty (set roleArn or "+constants.RoleArnEnvVar+" env var)", nil)
	}
	if cfg.idaasInstanceId == "" {
		return nil, sdkerrors.NewConfigError(constants.InvalidParameter, "idaasInstanceId cannot be empty", nil)
	}
	if cfg.developerApiEndpoint == "" {
		return nil, sdkerrors.NewConfigError(constants.InvalidParameter, "developerApiEndpoint cannot be empty", nil)
	}

	// 确定 OIDC Token 来源：优先显式注入的 OidcTokenProvider，否则用 CredentialProvider 桥接。
	var oidcTokenProvider provider.OidcTokenProvider
	switch {
	case cfg.oidcTokenProvider != nil:
		oidcTokenProvider = cfg.oidcTokenProvider
	case cfg.credentialProvider != nil:
		oidcTokenProvider = &oidcTokenAdapter{credProvider: cfg.credentialProvider}
	default:
		return nil, sdkerrors.NewConfigError(constants.InvalidParameter,
			"credentialProvider or oidcTokenProvider must be set", nil)
	}

	p := &IDaaSPamAlibabaCloudCredentialsProvider{
		roleArn:              cfg.roleArn,
		oidcTokenProvider:    oidcTokenProvider,
		connectTimeout:       cfg.connectTimeout,
		readTimeout:          cfg.readTimeout,
		idaasInstanceId:      cfg.idaasInstanceId,
		developerApiEndpoint: normalizeEndpoint(cfg.developerApiEndpoint),
		// PathEscape 防御性转义 instanceId，避免异常输入破坏 URL path 结构。
		developerApiPath: fmt.Sprintf(constants.ObtainAccessCredentialPath, url.PathEscape(cfg.idaasInstanceId)),
		httpClient:       newHTTPClient(cfg),
	}

	p.supplier = cache.NewCachedResultSupplier[*domain.AlibabaCloudStsCredential](
		p.refreshCredential,
		enums.StaleValueBehaviorRefresh,
		0,
	)

	// 预检（可选）：立即换取一次 STS 验证链路，配置类错误 fail-fast。
	if cfg.preflight {
		if _, err := p.GetStsCredential(); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// GetCredential 实现 credentials.Credential 接口，返回阿里云通用凭证模型。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetCredential() (*credentials.CredentialModel, error) {
	cred, err := p.GetStsCredential()
	if err != nil {
		return nil, err
	}
	return &credentials.CredentialModel{
		AccessKeyId:     strPtr(cred.AccessKeyId),
		AccessKeySecret: strPtr(cred.AccessKeySecret),
		SecurityToken:   strPtr(cred.SecurityToken),
		Type:            strPtr(constants.OIDCRoleArnCredentialType),
	}, nil
}

// GetStsCredential 返回原始 STS 凭证（从缓存或刷新）。
//
// 降级兜底：CachedResultSupplier 在刷新失败时会返回旧的缓存凭证（1/3 寿命缓冲内仍有效）。
// 但当缓存的 STS 已真正过期（PAM 持续故障、缓冲耗尽），不再返回过期凭证（会导致下游云
// 请求拿到 403/ExpiredToken 难以定位根因），而是 fail-fast 返回 CredentialError(CredentialExpired)。
// 使用独立码 CredentialExpired 而非 PamApiError：此处并非 PAM 返回了非 2xx，而是降级缓冲
// 已耗尽，便于上游按码值将"缓存耗尽"与"真实 PAM API 错误"分别归因。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetStsCredential() (*domain.AlibabaCloudStsCredential, error) {
	result, err := p.supplier.Get()
	if err != nil {
		return nil, err
	}
	if result == nil || result.Value == nil || !result.Value.Expiration.After(time.Now()) {
		return nil, sdkerrors.NewCredentialError(constants.CredentialExpired,
			"cached STS credential has expired and PAM refresh is unavailable", nil)
	}
	return result.Value, nil
}

// GetAccessKeyId 实现 credentials.Credential（deprecated，委托 GetCredential）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetAccessKeyId() (*string, error) {
	c, err := p.GetCredential()
	if err != nil {
		return nil, err
	}
	return c.AccessKeyId, nil
}

// GetAccessKeySecret 实现 credentials.Credential（deprecated，委托 GetCredential）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetAccessKeySecret() (*string, error) {
	c, err := p.GetCredential()
	if err != nil {
		return nil, err
	}
	return c.AccessKeySecret, nil
}

// GetSecurityToken 实现 credentials.Credential（deprecated，委托 GetCredential）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetSecurityToken() (*string, error) {
	c, err := p.GetCredential()
	if err != nil {
		return nil, err
	}
	return c.SecurityToken, nil
}

// GetBearerToken 实现 credentials.Credential（akless 模式不使用 Bearer Token）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetBearerToken() *string {
	return strPtr("")
}

// GetType 实现 credentials.Credential，返回 akless 流程的凭证类型标识。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetType() *string {
	return strPtr(constants.OIDCRoleArnCredentialType)
}

// refreshCredential 调用 PAM Developer API 获取新的阿里云 STS 凭证（缓存刷新回调）。
//
// 刷新失败时，CachedResultSupplier 的 StaleValueBehaviorRefresh 会吞掉错误、降级返回旧缓存凭证，
// 导致 PAM 故障对调用方"无声"。此处用 defer 在返回错误前记录 slog.Warn，使 PAM 中断在
// provider 侧可观测（而非只能从下游业务 403 反推）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) refreshCredential() (result *cache.RefreshResult[*domain.AlibabaCloudStsCredential], err error) {
	defer func() {
		if err != nil {
			slog.Warn("IDaaSPamAlibabaCloudCredentialsProvider: STS credential refresh failed; "+
				"may degrade to cached credential if still valid",
				"error", err)
		}
	}()

	// 1. 从核心 SDK 获取 OIDC Token（AccessToken）作为 Bearer Token。
	token, err := p.oidcTokenProvider.GetOidcToken()
	if err != nil {
		return nil, sdkerrors.NewCredentialError(constants.OidcTokenError, "failed to get OIDC token", err)
	}
	if token == "" {
		return nil, sdkerrors.NewCredentialError(constants.OidcTokenError,
			"OIDC token is empty, check core SDK credential provider configuration", nil)
	}
	p.oidcToken.Store(token)

	// 2. 构建 PAM 请求：GET {endpoint}{path}?cloudAccountRoleExternalId={roleArn}
	queryParams := url.Values{}
	queryParams.Set(constants.CloudAccountRoleExternalId, p.roleArn)

	requestURL := p.developerApiEndpoint + p.developerApiPath
	headers := map[string]string{
		sdkconstants.HeaderAuthorization: "Bearer " + token,
		sdkconstants.HeaderAccept:        sdkconstants.ContentTypeJson,
	}
	httpRequest := &sdkdomain.HttpRequest{
		Method:      enums.HttpMethodGet,
		URL:         requestURL,
		Headers:     headers,
		QueryParams: queryParams,
	}

	// 3. 执行 HTTP 调用。
	httpResponse, err := p.httpClient.Execute(httpRequest)
	if err != nil {
		return nil, sdkerrors.NewCredentialError(constants.HttpError, "failed to call PAM API", err)
	}

	// 4. 非 2xx：按 4xx/5xx 分流抛错（F-EXC-02）。
	if !httpResponse.IsSuccess() {
		code, msg := parsePamError(httpResponse.Body, httpResponse.StatusCode)
		if httpResponse.StatusCode >= 500 {
			return nil, sdkerrors.NewServerError(code, msg, httpResponse.StatusCode, nil)
		}
		return nil, sdkerrors.NewClientError(code, msg, nil)
	}

	// 5. 解析响应：cloudAccountRoleAccessCredential.alibabaCloudStsToken。
	var responseMap map[string]interface{}
	if err := json.Unmarshal(httpResponse.Body, &responseMap); err != nil {
		return nil, sdkerrors.NewCredentialError(constants.ParseError, "failed to parse PAM response", err)
	}

	accessCredential, ok := responseMap[constants.CloudAccountRoleAccessCredential].(map[string]interface{})
	if !ok {
		return nil, sdkerrors.NewCredentialError(constants.ParseError,
			"PAM response missing 'cloudAccountRoleAccessCredential' field", nil)
	}

	stsToken, ok := accessCredential[constants.AlibabaCloudStsToken].(map[string]interface{})
	if !ok {
		return nil, sdkerrors.NewCredentialError(constants.ParseError,
			"PAM response missing 'alibabaCloudStsToken' field", nil)
	}

	accessKeyId, _ := stsToken[constants.PAMAccessKeyId].(string)
	accessKeySecret, _ := stsToken[constants.PAMAccessKeySecret].(string)
	securityToken, _ := stsToken[constants.PAMSecurityToken].(string)
	expirationStr, _ := stsToken[constants.PAMExpiration].(string)

	if accessKeyId == "" || accessKeySecret == "" || securityToken == "" {
		// 仅说明缺失字段名，不外吐原始 body——2xx 响应体可能包含已下发的 AK/SK/Token，
		// 把整包拼进 error message 会让凭据随错误对象外溢到上游日志/可观测链路。
		var missing []string
		if accessKeyId == "" {
			missing = append(missing, constants.PAMAccessKeyId)
		}
		if accessKeySecret == "" {
			missing = append(missing, constants.PAMAccessKeySecret)
		}
		if securityToken == "" {
			missing = append(missing, constants.PAMSecurityToken)
		}
		return nil, sdkerrors.NewCredentialError(constants.ParseError,
			fmt.Sprintf("PAM response has empty STS fields: %s", strings.Join(missing, ", ")), nil)
	}

	expiration, err := parseUTCDate(expirationStr)
	if err != nil {
		return nil, sdkerrors.NewCredentialError(constants.ParseError,
			fmt.Sprintf("failed to parse expiration date '%s'", expirationStr), err)
	}

	// 6. 计算预取点：在 STS 寿命 2/3 处刷新（ExpiresAt = expiration - 寿命/3），
	// 留 1/3 缓冲兼吸收时钟漂移。与 Go AWS 兄弟适配器一致；Java（固定 -15min）、
	// Python（到期点刷新）策略不同，但都满足 stale-before-expiry。
	now := time.Now()
	expiresIn := expiration.Sub(now)
	prefetchTime := now
	if expiresIn > 0 {
		prefetchTime = expiration.Add(-expiresIn / 3)
	}

	credential := &domain.AlibabaCloudStsCredential{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		SecurityToken:   securityToken,
		Expiration:      expiration,
	}

	return &cache.RefreshResult[*domain.AlibabaCloudStsCredential]{
		Value:     credential,
		ExpiresAt: prefetchTime,
	}, nil
}

// parsePamError 从 PAM 错误响应体解析 error_code 与 message（双格式）。
// 解析失败时回退到 PamApiError + 状态码描述；body 仅在非 2xx 错误响应下被引用，
// 不会含 STS 凭据，但仍截断以防异常响应体过大导致日志膨胀。
func parsePamError(body []byte, statusCode int) (code, msg string) {
	var errResp sdkdomain.ErrResponse
	if err := json.Unmarshal(body, &errResp); err == nil {
		if c := errResp.GetErrorCode(); c != "" {
			code = c
		}
		if m := errResp.GetErrorMessage(); m != "" {
			msg = m
		}
	}
	if code == "" {
		code = constants.PamApiError
	}
	if msg == "" {
		msg = fmt.Sprintf("PAM API returned status %d: %s", statusCode, truncateBody(body, 512))
	}
	return code, msg
}

// truncateBody 截断响应体用于错误消息，避免超大 body 膨胀日志。
func truncateBody(body []byte, max int) string {
	if len(body) <= max {
		return string(body)
	}
	return string(body[:max]) + "...(truncated)"
}

// parseUTCDate 解析 PAM 返回的 ISO 8601 过期时间（兼容多种格式）。
// time.RFC3339 已覆盖带 Z 与带时区偏移（如 +00:00）的标准形式；
// 额外保留空格分隔格式以兼容个别非标准返回。
func parseUTCDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, fmt.Errorf("empty expiration date")
	}
	formats := []string{
		time.RFC3339,          // 2006-01-02T15:04:05Z07:00（覆盖 Z 与 +00:00）
		"2006-01-02 15:04:05", // 兼容空格分隔的非标准形式
	}
	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse date string: %s", dateStr)
}

// normalizeEndpoint 规范化 PAM Developer API 端点（F-AKLESS-CORE-04）。
//
// 规则：
//   - 去除前后空白与尾部斜杠；
//   - 无 scheme 时默认补 https://；
//   - 已带 http:// 或 https:// 则保留该 scheme（不强制升级，显式 http:// 的内网/开发
//     环境不会被静默改写）；非 http/https 的 scheme 一律按 https 处理；
//   - 解析后仅保留 scheme://host[:port]，丢弃任何 path（端点应为 base URL，path 由
//     developerApiPath 拼接）；解析失败或无 host 时回退为 https + 原样。
//
// 与 Python 适配层（取 parsed.netloc + scheme，隐式丢弃 path）语义对齐。
// Bearer 是否走明文由调用方自负。
func normalizeEndpoint(endpoint string) string {
	s := strings.TrimSpace(endpoint)
	s = strings.TrimRight(s, "/")
	if s == "" {
		return s
	}
	// 无 scheme（如 "api.x.com" 或 "api.x.com:8080"）→ 默认 https。
	if !strings.Contains(s, "://") {
		return "https://" + s
	}
	// 已带 scheme：解析后保留（http/https），丢弃任何 path，仅保留 scheme://host[:port]。
	parsed, err := url.Parse(s)
	if err != nil || parsed.Host == "" {
		// 解析失败或无 host（异常输入）→ 回退为 https + 原样。
		return "https://" + s
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	return scheme + "://" + parsed.Host
}

func strPtr(s string) *string {
	return &s
}

// newHTTPClient 构造 HTTP 客户端：优先用注入的（测试），否则用核心 SDK 默认客户端。
func newHTTPClient(cfg *credentialsProviderConfig) sdkhttp.HttpClient {
	if cfg.httpClient != nil {
		return cfg.httpClient
	}
	return sdkhttp.NewDefaultHttpClient(cfg.connectTimeout, cfg.readTimeout)
}

// --- 字段暴露（与 idaas-go-akless-aws-adapter 对齐）---

// Close 释放 provider 持有的资源。
//
// 当前为 no-op：底层 HTTP 客户端由核心 SDK 管理，其连接池的空闲连接由
// transport 的 IdleConnTimeout 自动回收，无硬泄漏。提供本方法是为：
//   - 与 Java（close()）/ Python（close()）适配层对齐生命周期 API；
//   - 预留显式释放钩子，便于核心 SDK 后续暴露连接释放能力时无缝填充。
//
// 幂等，可安全多次调用。调用 Close 后 provider 仍可继续使用（会按需重新刷新）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) Close() error {
	// 预留：未来若 httpClient 暴露 CloseIdleConnections，在此调用。
	return nil
}

// GetRoleArn 返回云账号角色 ARN（roleArn，即 PAM 的 cloudAccountRoleExternalId）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetRoleArn() string { return p.roleArn }

// GetOIDCToken 返回最近一次使用的 OIDC Token（仅观测用）。
// 注意：返回值是有效的 bearer 凭证，切勿将其写入日志、metrics 或持久化存储。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetOIDCToken() string {
	if v := p.oidcToken.Load(); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// GetIdaasInstanceId 返回 IDaaS 实例 ID。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetIdaasInstanceId() string {
	return p.idaasInstanceId
}

// GetDeveloperApiEndpoint 返回规范化的 PAM Developer API 端点。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetDeveloperApiEndpoint() string {
	return p.developerApiEndpoint
}

// GetConnectTimeout 返回连接超时（毫秒）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetConnectTimeout() int { return p.connectTimeout }

// GetReadTimeout 返回读取超时（毫秒）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetReadTimeout() int { return p.readTimeout }
