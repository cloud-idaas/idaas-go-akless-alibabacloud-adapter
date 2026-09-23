package domain

import (
	"testing"
	"time"
)

func TestAlibabaCloudStsCredential_Getters(t *testing.T) {
	exp := time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)
	c := &AlibabaCloudStsCredential{
		AccessKeyId:     "ak",
		AccessKeySecret: "sk",
		SecurityToken:   "st",
		Expiration:      exp,
	}
	if c.GetAccessKeyId() != "ak" {
		t.Errorf("AccessKeyId=%q", c.GetAccessKeyId())
	}
	if c.GetAccessKeySecret() != "sk" {
		t.Errorf("AccessKeySecret=%q", c.GetAccessKeySecret())
	}
	if c.GetSecurityToken() != "st" {
		t.Errorf("SecurityToken=%q", c.GetSecurityToken())
	}
	if !c.GetExpiration().Equal(exp) {
		t.Errorf("Expiration=%v want %v", c.GetExpiration(), exp)
	}
}
