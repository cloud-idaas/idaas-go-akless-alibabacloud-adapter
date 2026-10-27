// Package pam 实现 Alibaba Cloud akless 适配层的凭证提供者。
//
// 通过 IDaaS PAM Developer API 用 OIDC Token（来自核心 SDK）换取阿里云 STS 临时凭证，
// 并适配 github.com/aliyun/credentials-go 的 Credential 接口，供阿里云各服务 SDK 使用。
package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
	"github.com/cloud-idaas/idaas-go-core-sdk/provider"

	"github.com/aliyun/credentials-go/credentials"
)

// IDaaSPamAlibabaCloudCredentialsProvider 通过 IDaaS PAM Developer API 获取阿里云 STS 凭证，
// 并实现 github.com/aliyun/credentials-go/credentials.Credential 接口。
//
// 缓存与刷新复用核心 SDK 的 cache.CachedResultSupplier（StaleValueBehaviorRefresh +
// singleflight），并按核心 SDK 的双时间点模型回填三段寿命点（见 refreshCredential）：
// PrefetchTime=寿命 2/3 处（越过则后台预取，不阻塞业务请求）、StaleTime=4/5 处（越过则
// 同步刷新，首个请求执行、其余并发请求由 singleflight 合并等待）、ExpiresAt=STS 真实
// 过期时间。刷新失败时降级返回仍在 1/5 缓冲内（StaleTime→ExpiresAt）的旧缓存；旧缓存亦真正过期时 fail-fast。
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
	logger               logger.Logger
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

	// logger 注入与回退：与核心 SDK factory.effectiveLogger() 口径一致——
	// 未注入 WithLogger 时回退 logger.Default()（一次性的 stderr 提示）。生产应
	// 通过 WithLogger 或进程级 logger.SetDefault 注入真实实现，否则刷新失败降级
	// 告警（refreshCredential defer）只会向 stderr 打一次后静默。
	pLogger := cfg.logger
	if pLogger == nil {
		pLogger = logger.Default()
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
		logger:           pLogger,
	}

	// 核心 SDK v0.1.0-beta.1 起：refreshFunc 接收 context.Context（取消/deadline 透传），
	// 且 prefetchThreshold 位置参数被移除（预取时机由 StaleTime/PrefetchTime 内部推导）。
	p.supplier = cache.NewCachedResultSupplier[*domain.AlibabaCloudStsCredential](
		p.refreshCredential,
		enums.StaleValueBehaviorRefresh,
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
// 降级兜底：CachedResultSupplier 在刷新失败时会返回旧的缓存凭证（1/5 寿命缓冲内、即 StaleTime 至 ExpiresAt 之间仍有效）。
// 但当缓存的 STS 已真正过期（PAM 持续故障、缓冲耗尽），不再返回过期凭证（会导致下游云
// 请求拿到 403/ExpiredToken 难以定位根因），而是 fail-fast 返回 CredentialError(CredentialExpired)。
// 使用独立码 CredentialExpired 而非 PamApiError：此处并非 PAM 返回了非 2xx，而是降级缓冲
// 已耗尽，便于上游按码值将"缓存耗尽"与"真实 PAM API 错误"分别归因。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetStsCredential() (*domain.AlibabaCloudStsCredential, error) {
	return p.GetStsCredentialWithContext(context.Background())
}

// GetStsCredentialWithContext 返回原始 STS 凭证，并让调用方的 ctx 参与凭证请求的生命周期。
//
// ctx 约束的是**等待**：核心 SDK 把刷新与单个请求解耦（一次刷新由 leader 触发、并发请求经
// singleflight 合并），调用方 ctx 取消 / 超时时本方法立即返回 CacheError(ClientRequestCanceled)，
// 不再干等刷新完成；在飞的刷新继续执行并把结果写入缓存，供后续请求直接命中。缓存命中、
// singleflight、失败降级与过期 fail-fast 语义与 GetStsCredential 完全一致。
// ctx 为 nil 时按 context.Background() 处理（兼容上游 SDK 传入 nil ctx 的场景）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetStsCredentialWithContext(ctx context.Context) (*domain.AlibabaCloudStsCredential, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	result, err := p.supplier.GetWithContext(ctx)
	// ErrStaleCredentialReturned 是核心 SDK "刷新失败但把过期旧值交回调用方"的降级信号，
	// 不是硬错误：交给下方过期校验统一转成 CredentialExpired，保持适配器错误语义稳定。
	if err != nil && !errors.Is(err, cache.ErrStaleCredentialReturned) {
		return nil, err
	}
	// 取时点统一用核心 SDK 的可注入时钟（cache.GetClock()），与 CachedResultSupplier
	// 判定 stale/expired 所用的时钟源保持一致：否则两者在测试或宿主重配时钟时口径不一。
	// 默认时钟即系统时钟，生产行为不变。
	if result == nil || result.Value == nil || !result.Value.Expiration.After(cache.GetClock().Now()) {
		return nil, sdkerrors.NewCredentialError(constants.CredentialExpired,
			"cached STS credential has expired and PAM refresh is unavailable", err)
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
// ctx 由核心 SDK 的 CachedResultSupplier 注入：同步刷新与后台预取共用同一个"宿主 baseCtx
// + asyncRefreshTimeout"派生的刷新 ctx（不绑定任一调用方请求）。本方法把它继续透传给 OIDC
// 获取与 PAM HTTP 调用，使整条刷新链路受统一超时 / 宿主取消约束，而不只靠 connect/read 两
// 段分段超时兜底。
//
// 刷新失败时，CachedResultSupplier 的 StaleValueBehaviorRefresh 会吞掉错误、降级返回旧缓存凭证，
// 导致 PAM 故障对调用方"无声"。此处用 defer 在返回错误前记录 p.logger.Warn，使 PAM 中断在
// provider 侧可观测（而非只能从下游业务 403 反推）。logger 经 WithLogger 注入，未注入时
// 回退 logger.Default()（与核心 SDK factory.effectiveLogger() 口径一致）；走核心 SDK logger
// 包而非 log/slog，与核心 SDK 的 logger 抽象保持一致（并非受工具链下限约束）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) refreshCredential(
	ctx context.Context,
) (result *cache.RefreshResult[*domain.AlibabaCloudStsCredential], err error) {
	defer func() {
		if err != nil {
			p.logger.Warn(ctx,
				"IDaaSPamAlibabaCloudCredentialsProvider: STS credential refresh failed; "+
					"may degrade to cached credential if still valid",
				"error", err)
		}
	}()

	// nil ctx 兜底：refreshFunc 由核心 SDK 调用，正常不会传 nil；防御自定义调用方/测试直调。
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. 从核心 SDK 获取 OIDC Token（AccessToken）作为 Bearer Token。
	//    ctx 交给 provider，使其可取消/限时核心 SDK 内的 Token Endpoint / 元数据服务调用。
	token, err := p.oidcTokenProvider.GetOidcTokenWithContext(ctx)
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

	// 3. 执行 HTTP 调用（ExecuteContext 透传 ctx，支持请求级取消与 deadline）。
	httpResponse, err := p.httpClient.ExecuteContext(ctx, httpRequest)
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

	// 6. 计算三段寿命点（对齐核心 SDK 双时间点模型：预取 2/3、stale 4/5）。
	//    注：Java/Python 适配层当前未显式设置这两个点（Java 仅 staleTime、Python
	//    stale_time 直接取全 expiration），本仓是三语中唯一完整回填三段的实现。
	//    不用 cache.NewRefreshResult：它以 receivedAt+expires_in 推导绝对过期时间，而 PAM
	//    返回的是绝对 expiration；且其 expiresIn<=0 直接报 InvalidExpiresIn，会抢走下面
	//    fail-fast 的 CredentialExpired 语义。
	now := cache.GetClock().Now()
	expiresIn := expiration.Sub(now)
	if expiresIn <= 0 {
		// PAM 返回的过期时间已不晚于当前时间（时钟偏移 / PAM 异常）。若照常返回"成功"，
		// supplier 会提交一个永不通过取时校验的值且不记录刷新失败：仍有效的旧缓存被过期
		// 值顶掉，之后每个请求都同步重刷 PAM（刷新"成功"不走退避窗口），而每个调用方都
		// 只拿到 CredentialExpired。改为按刷新失败处理：进入 staleRetryBackoff 退避窗口，
		// 降级沿用仍有效的旧缓存，fail-fast 语义不变但异常窗口内的 PAM 调用有界。
		return nil, sdkerrors.NewCredentialError(constants.CredentialExpired,
			fmt.Sprintf("PAM returned an already-expired credential (expiration=%s, now=%s)",
				expirationStr, now.Format(time.RFC3339Nano)), nil)
	}
	prefetchTime := expiration.Add(-expiresIn / 3) // 2/3 寿命点：后台预取
	staleTime := expiration.Add(-expiresIn / 5)    // 4/5 寿命点：同步刷新

	credential := &domain.AlibabaCloudStsCredential{
		AccessKeyId:     accessKeyId,
		AccessKeySecret: accessKeySecret,
		SecurityToken:   securityToken,
		Expiration:      expiration,
	}

	// ExpiresAt 是 STS 真实过期时间（v0.1.0-alpha.3 时代此处塞的是预取点，语义已被
	// 核心 SDK 拆成三个时间点）；过期值是否可用由 GetStsCredentialWithContext 按凭证
	// 自身 Expiration 二次校验，保证永不把过期凭证交给下游。
	return &cache.RefreshResult[*domain.AlibabaCloudStsCredential]{
		Value:        credential,
		PrefetchTime: prefetchTime,
		StaleTime:    staleTime,
		ExpiresAt:    expiration,
	}, nil
}

// parsePamError 从 PAM 错误响应体解析错误码与 message（双格式：标准 OAuth
// error/error_description 与 IDaaS 自定义 code/message，由核心 SDK ErrResponse 兼容解析）。
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
//
// 覆盖以下形态：
//   - 标准无小数秒：2006-01-02T15:04:05Z / +00:00（time.RFC3339）
//   - 标准带小数秒（毫秒/纳秒）：2006-01-02T15:04:05.123Z（time.RFC3339Nano）
//   - 空格分隔的非标准形式（个别 PAM 返回），含/不含小数秒
//
// time.RFC3339 不接受小数秒，须显式列出 time.RFC3339Nano；其 .999 占位使小数秒
// 可选，故 RFC3339Nano 也能解析无小数秒输入，但保留 RFC3339 在前以保持标准形式的
// 最快解析路径。带小数秒的返回在 STS/PAM 类服务中常见，缺此格式会让刷新持续
// ParseError → 缓存耗尽 → 全量 CredentialExpired。
func parseUTCDate(dateStr string) (time.Time, error) {
	if dateStr == "" {
		return time.Time{}, fmt.Errorf("empty expiration date")
	}
	formats := []string{
		time.RFC3339,                    // 2006-01-02T15:04:05Z07:00（无小数秒，覆盖 Z 与 +00:00）
		time.RFC3339Nano,                // 2006-01-02T15:04:05.999999999Z07:00（带可选小数秒）
		"2006-01-02 15:04:05",           // 空格分隔，无小数秒
		"2006-01-02 15:04:05.999999999", // 空格分隔，带可选小数秒
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
// 与 Python 适配层（urlparse 语义）对齐：去除前后空白与尾部斜杠；若端点已带
// http:// 或 https:// 协议则保留该 scheme（不强制升级），无协议时默认补 https://。
// 这样显式声明 http:// 的内网/开发环境不会被静默改写；Bearer 是否走明文由调用方自负。
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
	// 已带 scheme：解析后保留（http/https）scheme、host[:port] 以及 path（仅 strip 尾部斜杠）。
	// 保留 path 是为了支持 PAM 部署在反向代理子路径下的场景（如 https://gw.internal/pam-api），
	// 丢弃 path 会让后续拼接 developerApiPath 后请求落到网关根路径而 404。
	parsed, err := url.Parse(s)
	if err != nil || parsed.Host == "" {
		// 解析失败或无 host（异常输入）→ 回退为 https + 原样。
		return "https://" + s
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		scheme = "https"
	}
	path := strings.TrimRight(parsed.Path, "/")
	return scheme + "://" + parsed.Host + path
}

func strPtr(s string) *string {
	return &s
}

// newHTTPClient 解析 HTTP 客户端：优先用注入的（测试），否则用核心 SDK 默认客户端。
func newHTTPClient(cfg *credentialsProviderConfig) sdkhttp.HttpClient {
	if cfg.httpClient != nil {
		return cfg.httpClient
	}
	return sdkhttp.NewDefaultHttpClient(cfg.connectTimeout, cfg.readTimeout)
}

// --- 字段暴露（与 idaas-go-akless-aws-adapter 对齐）---

// Close 释放 provider 持有的资源。
//
// 现委托底层 supplier.Close()：当前未注入预取策略，核心 SDK 的内置异步刷新不持有
// 后台资源，实际效果等价 no-op；底层 HTTP 客户端由核心 SDK 管理，其连接池的空闲
// 连接由 transport 的 IdleConnTimeout 自动回收，无硬泄漏。提供本方法是为：
//   - 与 Java（close()）/ Python（close()）适配层对齐生命周期 API；
//   - 预留显式释放钩子，便于核心 SDK 后续暴露连接释放能力时无缝填充。
//
// 幂等，可安全多次调用。调用 Close 后 provider 仍可继续使用（会按需重新刷新）。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) Close() error {
	// 核心 SDK v0.1.0-beta.1 起 CachedResultSupplier 暴露 Close()：释放可选的预取策略
	// （未注入策略时为 no-op）。本 provider 当前未注入策略，调用等价 no-op，但让
	// "supplier 不再使用时释放其后台资源"这条链路提前接通。
	// 预留：未来若 httpClient 暴露 CloseIdleConnections，在此调用。
	if p.supplier != nil {
		return p.supplier.Close()
	}
	return nil
}

// GetRoleArn 返回云账号角色外部标识。
func (p *IDaaSPamAlibabaCloudCredentialsProvider) GetRoleArn() string { return p.roleArn }

// GetOIDCToken 返回最近一次使用的 OIDC Token（仅观测用）。
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
