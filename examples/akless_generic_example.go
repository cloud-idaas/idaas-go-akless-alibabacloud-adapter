//go:build example_generic

// Sample: Use IDaaS PAM AKless authentication with the generic Alibaba Cloud
// credentials provider (github.com/aliyun/credentials-go).
//
// The generic provider implements credentials.Credential, so it can be passed
// to any Alibaba Cloud SDK client that accepts a credentials.Credential.
//
// Prerequisites:
// 1. Configure idaas-go-core-sdk (config file with PAM scope).
// 2. Set env var: ALIBABA_CLOUD_ROLE_ARN.
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
	idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
	roleArn := envOr("ALIBABA_CLOUD_ROLE_ARN", "")
	if roleArn == "" {
		log.Fatal("ALIBABA_CLOUD_ROLE_ARN env var is required")
	}

	// 1. Initialize IDaaS Core SDK.
	idaasCfg, err := idaasconfig.NewConfigReader().LoadWithPriority("")
	if err != nil {
		log.Fatalf("Failed to load IDaaS config: %v", err)
	}
	if err := factory.GetInstance().Initialize(idaasCfg); err != nil {
		log.Fatalf("Failed to initialize IDaaS: %v", err)
	}

	// 2. Create generic credentials provider via the package-level constructor.
	credProvider, err := pam.GetAlibabaCloudCredentialsProvider(roleArn)
	if err != nil {
		log.Fatalf("Failed to create credentials provider: %v", err)
	}

	// 3. Obtain the STS credential (cached / auto-refreshed).
	model, err := credProvider.GetCredential()
	if err != nil {
		log.Fatalf("Failed to get credential: %v", err)
	}
	fmt.Println("=== Alibaba Cloud STS Credential ===")
	fmt.Printf("  AccessKeyId:     %s\n", *model.AccessKeyId)
	fmt.Printf("  AccessKeySecret: %s\n", *model.AccessKeySecret)
	fmt.Printf("  SecurityToken:   %s\n", *model.SecurityToken)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
