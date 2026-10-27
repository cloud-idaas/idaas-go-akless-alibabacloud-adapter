package pam

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/cloud-idaas/idaas-go-core-sdk/logger"
)

var errStubPamDown = errors.New("stub: pam unavailable")

// recordingLogger 记录 Warn/Error 消息，验证 WithLogger 注入生效。
type recordingLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *recordingLogger) Debug(context.Context, string, ...interface{}) {}
func (l *recordingLogger) Info(context.Context, string, ...interface{})  {}

func (l *recordingLogger) Warn(_ context.Context, msg string, _ ...interface{})  { l.record(msg) }
func (l *recordingLogger) Error(_ context.Context, msg string, _ ...interface{}) { l.record(msg) }

func (l *recordingLogger) record(msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, msg)
}

func (l *recordingLogger) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.messages...)
}

// WithLogger 注入的 logger 必须收到 refreshCredential 失败降级的 Warn
// （此前该路径只被 logger.Default() 的一次性提示覆盖，注入面完全没有测试固化）。
func TestWithLogger_InjectedLoggerReceivesRefreshFailureWarn(t *testing.T) {
	rec := &recordingLogger{}
	fake := &fakeHttpClient{err: errStubPamDown}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		withHttpClient(fake),
		WithLogger(rec),
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if _, err := p.GetStsCredential(); err == nil {
		t.Fatal("expected refresh error")
	}
	var found bool
	for _, m := range rec.all() {
		if strings.Contains(m, "refresh failed") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("injected logger should receive the refresh-failure Warn, got: %v", rec.all())
	}
}

// WithLogger(nil) 必须等价于不调用：构造器回退 logger.Default()（核心 SDK 的
// 一次性 stderr 提示），且后续刷新失败不 panic。
func TestWithLogger_NilFallsBackToDefault(t *testing.T) {
	fake := &fakeHttpClient{err: errStubPamDown}
	p, err := NewIDaaSPamAlibabaCloudCredentialsProvider(
		WithOidcTokenProvider(&fakeOidcTokenProvider{token: "tok"}),
		WithDeveloperApiEndpoint("https://pam.example.com"),
		WithIdaasInstanceId("inst-123"),
		WithRoleArn("acs:ram::123:role/demo"),
		withHttpClient(fake),
		WithLogger(nil),
	)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	if p.logger != logger.Default() {
		t.Errorf("WithLogger(nil) should fall back to logger.Default(), got %T", p.logger)
	}
	if _, err := p.GetStsCredential(); err == nil {
		t.Fatal("expected refresh error")
	}
}
