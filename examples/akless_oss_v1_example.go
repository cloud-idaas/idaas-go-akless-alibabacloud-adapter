//go:build example_oss_v1

// Sample: Use IDaaS PAM AKless authentication to access Alibaba Cloud OSS (V1 SDK).
//
// Prerequisites:
//  1. Configure idaas-go-core-sdk (config file with PAM scope, e.g.
//     "urn:cloud:idaas:pam|cloud_account_role:obtain_access_credential").
//  2. Ensure the PAM cloud-account-role has OSS permissions on the target bucket.
//  3. Set env vars:
//     ALIBABA_CLOUD_ROLE_ARN       - cloud account role external id (e.g. acs:ram::<uid>:role/<name>)
//     OSS_BUCKET           - bucket name
//     OSS_ENDPOINT         - e.g. https://oss-cn-hangzhou.aliyuncs.com
//     OSS_REGION           - e.g. cn-hangzhou
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/pam"
	idaasconfig "github.com/cloud-idaas/idaas-go-core-sdk/config"
	"github.com/cloud-idaas/idaas-go-core-sdk/factory"
)

func main() {
	roleArn := envOr("ALIBABA_CLOUD_ROLE_ARN", "")
	bucket := envOr("OSS_BUCKET", "")
	endpoint := envOr("OSS_ENDPOINT", "https://oss-cn-hangzhou.aliyuncs.com")
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

	// 2. Create OSS V1 credentials provider via the package-level constructor.
	credProvider, err := pam.GetOSSV1CredentialsProvider(roleArn)
	if err != nil {
		log.Fatalf("Failed to create OSS V1 credentials provider: %v", err)
	}

	// 3. Create OSS V1 client with akless credentials.
	client, err := oss.New(endpoint, "", "",
		oss.AuthVersion(oss.AuthV4), oss.Region(region), oss.SetCredentialsProvider(credProvider))
	if err != nil {
		log.Fatalf("Failed to create OSS client: %v", err)
	}

	// 4. List objects in the bucket.
	bucketClient, err := client.Bucket(bucket)
	if err != nil {
		log.Fatalf("Failed to get bucket client: %v", err)
	}
	fmt.Printf("=== Objects in bucket %s ===\n", bucket)
	marker := ""
	total := 0
	for {
		result, err := bucketClient.ListObjects(oss.Marker(marker), oss.MaxKeys(100))
		if err != nil {
			log.Fatalf("Failed to list objects: %v", err)
		}
		for _, obj := range result.Objects {
			fmt.Printf("  %s (size: %d)\n", obj.Key, obj.Size)
			total++
		}
		if !result.IsTruncated {
			break
		}
		marker = result.NextMarker
	}
	fmt.Printf("Total: %d objects\n", total)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
