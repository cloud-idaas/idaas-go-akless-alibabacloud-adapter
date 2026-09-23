//go:build example_oss_v2

// Sample: Use IDaaS PAM AKless authentication to access Alibaba Cloud OSS (V2 SDK).
//
// Prerequisites:
// 1. Configure idaas-go-core-sdk (config file with PAM scope).
// 2. Ensure the PAM cloud-account-role has OSS permissions on the target bucket.
// 3. Set env vars: ALIBABA_CLOUD_ROLE_ARN, OSS_BUCKET, OSS_REGION.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	oss "github.com/aliyun/alibabacloud-oss-go-sdk-v2/oss"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
	idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
	roleArn := envOr("ALIBABA_CLOUD_ROLE_ARN", "")
	bucket := envOr("OSS_BUCKET", "")
	region := envOr("OSS_REGION", "cn-hangzhou")
	if roleArn == "" || bucket == "" {
		log.Fatal("ALIBABA_CLOUD_ROLE_ARN and OSS_BUCKET env vars are required")
	}

	// 1. Initialize IDaaS Core SDK.
	idaasCfg, err := idaasconfig.NewConfigReader().LoadWithPriority("")
	if err != nil {
		log.Fatalf("Failed to load IDaaS config: %v", err)
	}
	if err := factory.GetInstance().Initialize(idaasCfg); err != nil {
		log.Fatalf("Failed to initialize IDaaS: %v", err)
	}

	// 2. Create OSS V2 credentials provider via the package-level constructor.
	credProvider, err := pam.GetOSSV2CredentialsProvider(roleArn)
	if err != nil {
		log.Fatalf("Failed to create OSS V2 credentials provider: %v", err)
	}

	// 3. Create OSS V2 client with akless credentials.
	cfg := oss.NewConfig().
		WithRegion(region).
		WithCredentialsProvider(credProvider)
	client := oss.NewClient(cfg)

	// 4. List objects in the bucket.
	result, err := client.ListObjects(context.TODO(), &oss.ListObjectsRequest{Bucket: oss.Ptr(bucket)})
	if err != nil {
		log.Fatalf("Failed to list objects: %v", err)
	}
	fmt.Printf("=== Objects in bucket %s ===\n", bucket)
	for _, obj := range result.Contents {
		key := ""
		if obj.Key != nil {
			key = *obj.Key
		}
		fmt.Printf("  %s (size: %d)\n", key, obj.Size)
	}
	fmt.Printf("Total: %d objects\n", len(result.Contents))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
