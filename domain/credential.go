// Package domain 定义 Alibaba Cloud akless 适配层的领域模型。
package domain

import "time"

// AlibabaCloudStsCredential 表示从 IDaaS PAM Developer API 获取的阿里云 STS 临时凭证。
//
// 字段命名与跨语言（Java/Python）数据模型保持一致：
// accessKeyId / accessKeySecret / securityToken / expiration(ISO 8601)。
type AlibabaCloudStsCredential struct {
	AccessKeyId     string
	AccessKeySecret string
	SecurityToken   string
	Expiration      time.Time
}

// GetAccessKeyId 返回 STS AccessKey ID。
func (c *AlibabaCloudStsCredential) GetAccessKeyId() string {
	return c.AccessKeyId
}

// GetAccessKeySecret 返回 STS AccessKey Secret。
func (c *AlibabaCloudStsCredential) GetAccessKeySecret() string {
	return c.AccessKeySecret
}

// GetSecurityToken 返回 STS Security Token。
func (c *AlibabaCloudStsCredential) GetSecurityToken() string {
	return c.SecurityToken
}

// GetExpiration 返回凭证过期时间。
func (c *AlibabaCloudStsCredential) GetExpiration() time.Time {
	return c.Expiration
}
