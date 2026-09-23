//go:build example_sls

// Sample: Use IDaaS PAM AKless authentication to access Alibaba Cloud SLS (Log Service).
//
// Prerequisites:
// 1. Configure idaas-go-core-sdk (config file with PAM scope).
// 2. Ensure the PAM cloud-account-role has SLS permissions.
// 3. Set env vars: ALIBABA_CLOUD_ROLE_ARN, SLS_ENDPOINT.
package main

import (
	"fmt"
	"log"
	"os"

	sls "github.com/aliyun/aliyun-log-go-sdk"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
	idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
	roleArn := envOr("ALIBABA_CLOUD_ROLE_ARN", "")
	endpoint := envOr("SLS_ENDPOINT", "")
	if roleArn == "" || endpoint == "" {
		log.Fatal("ALIBABA_CLOUD_ROLE_ARN and SLS_ENDPOINT env vars are required")
	}

	// 1. Initialize IDaaS Core SDK.
	idaasCfg, err := idaasconfig.NewConfigReader().LoadWithPriority("")
	if err != nil {
		log.Fatalf("Failed to load IDaaS config: %v", err)
	}
	if err := factory.GetInstance().Initialize(idaasCfg); err != nil {
		log.Fatalf("Failed to initialize IDaaS: %v", err)
	}

	// 2. Create SLS credentials provider via the package-level constructor.
	credProvider, err := pam.GetSLSCredentialsProvider(roleArn)
	if err != nil {
		log.Fatalf("Failed to create SLS credentials provider: %v", err)
	}

	// 3. Create SLS client with akless credentials.
	client := (&sls.Client{Endpoint: endpoint}).WithCredentialsProvider(credProvider)

	// 4. List SLS projects (ListProject returns project name strings).
	projects, err := client.ListProject()
	if err != nil {
		log.Fatalf("Failed to list projects: %v", err)
	}
	fmt.Println("=== SLS Projects ===")
	for _, name := range projects {
		fmt.Printf("  %s\n", name)
	}
	fmt.Printf("Total: %d projects\n", len(projects))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
