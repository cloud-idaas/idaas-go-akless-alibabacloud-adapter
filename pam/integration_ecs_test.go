//go:build integration

// ECS 端到端用例：验证通用 provider（credentials-go 路径）换取的 STS 凭证
// 可真实调用阿里云 ECS OpenAPI。
//
// 本仓不提供 ECS 专用适配器（ECS SDK 直接消费 credentials.Credential），
// 这里用阿里云 RPC V1（HMAC-SHA1）签名规范直调 DescribeInstances，
// 与任意官方 SDK 内部的签名行为一致——证明 STS 凭证对"任何阿里云服务"可用。
//
// 前置条件：
//   - 与 integration_test.go 相同的必需配置（cloud_idaas.json / IDAAS_CLIENT_SECRET /
//     IDAAS_ROLE_ARN）；
//   - 角色需具备 ECS 只读权限（如 AliyunECSReadOnlyAccess 或自定义 ecs:Describe* 授权）。
//
// 可选环境变量：ECS_REGION（默认 cn-hangzhou）。
package pam

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestIntegration_ECS_DescribeInstances 全链路验证：
// PAM 换取 STS → 用该 STS 对 ECS OpenAPI 做 RPC V1 签名 → 真实查询 ECS 实例列表。
func TestIntegration_ECS_DescribeInstances(t *testing.T) {
	roleArn := requireIntegration(t)
	region := envOr("ECS_REGION", "cn-hangzhou")

	// 1. 通用 provider 取 STS（真实 PAM 链路）。
	provider, err := GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		t.Fatalf("GetAlibabaCloudCredentialsProvider: %v", err)
	}
	model, err := provider.GetCredential()
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if model.AccessKeyId == nil || model.AccessKeySecret == nil || model.SecurityToken == nil {
		t.Fatalf("credential model has empty fields: %+v", model)
	}

	// 2. 用 STS 凭证签名直调 ECS DescribeInstances。
	body, err := ecsRpcV1Get(region, "DescribeInstances",
		map[string]string{
			"Version":  "2014-05-26",
			"RegionId": region,
		},
		*model.AccessKeyId, *model.AccessKeySecret, *model.SecurityToken)
	if err != nil {
		t.Fatalf("call ECS API: %v", err)
	}

	// 3. 解析响应：错误响应携带 Code/Message，成功响应携带 Instances/TotalCount。
	var resp map[string]interface{}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to parse ECS response: %v\nbody: %s", err, body)
	}
	if code, ok := resp["Code"].(string); ok {
		t.Fatalf("ECS API returned error code %q: %v", code, resp["Message"])
	}

	total, _ := resp["TotalCount"].(float64)
	t.Logf("ECS DescribeInstances(region=%s) ok, TotalCount=%d", region, int(total))

	if instances, ok := resp["Instances"].(map[string]interface{}); ok {
		if list, ok := instances["Instance"].([]interface{}); ok {
			for i, item := range list {
				if i >= 5 {
					t.Logf("  ... %d more instances omitted", len(list)-5)
					break
				}
				if inst, ok := item.(map[string]interface{}); ok {
					t.Logf("  instance: id=%v name=%v status=%v",
						inst["InstanceId"], inst["InstanceName"], inst["Status"])
				}
			}
		}
	}
}

// ecsRpcV1Get 用 STS 凭证对阿里云 RPC API 做 V1 签名并发起 GET 调用，返回响应体。
func ecsRpcV1Get(region, action string, apiParams map[string]string, ak, sk, securityToken string) ([]byte, error) {
	query := signRpcV1Query(ak, sk, securityToken, action, apiParams)
	endpoint := fmt.Sprintf("https://ecs.%s.aliyuncs.com/?%s", region, query)

	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response (status %d): %w", resp.StatusCode, err)
	}
	return body, nil
}

// signRpcV1Query 按阿里云 RPC API 签名版本 1.0 构造已签名的 query string：
//
//	StringToSign = HTTPMethod + "&" + percentEncode("/") + "&" + percentEncode(canonicalQuery)
//	Signature    = Base64( HMAC-SHA1( AccessKeySecret + "&", StringToSign ) )
//
// STS 临时凭证需额外携带 SecurityToken 参数（参与签名）。
func signRpcV1Query(ak, sk, securityToken, action string, apiParams map[string]string) string {
	params := map[string]string{
		"Action":           action,
		"AccessKeyId":      ak,
		"Format":           "JSON",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   randomNonce(),
		"SignatureVersion": "1.0",
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if securityToken != "" {
		params["SecurityToken"] = securityToken
	}
	for k, v := range apiParams {
		params[k] = v
	}

	// 按 key 排序构造规范化请求串。
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canonical bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncodeRfc3986(k))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncodeRfc3986(params[k]))
	}

	stringToSign := "GET&" + percentEncodeRfc3986("/") + "&" + percentEncodeRfc3986(canonical.String())
	mac := hmac.New(sha1.New, []byte(sk+"&"))
	mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return canonical.String() + "&Signature=" + percentEncodeRfc3986(signature)
}

// percentEncodeRfc3986 做 RFC 3986 百分号编码（阿里云 RPC 签名要求的编码方式）：
// 基于 url.QueryEscape 修正空格（+→%20）、星号（*→%2A）、波浪号（%7E→~）。
func percentEncodeRfc3986(s string) string {
	return strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~").Replace(url.QueryEscape(s))
}

// randomNonce 生成请求唯一标识（防重放）。
func randomNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}
