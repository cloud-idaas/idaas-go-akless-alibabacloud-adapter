package pam

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cloud-idaas/idaas-go-akless-alibabacloud-adapter/constants"
	"github.com/cloud-idaas/idaas-go-core-sdk/cache"
	sdkconstants "github.com/cloud-idaas/idaas-go-core-sdk/constants"
	sdkerrors "github.com/cloud-idaas/idaas-go-core-sdk/errors"
)

// 本文件覆盖升级到核心 SDK v0.1.0-beta.1 后引入的两类新行为：
//  1. context 生命周期（OidcTokenProvider.GetOidcTokenWithContext /
//     HttpClient.ExecuteContext / CachedResultSupplier.GetWithContext）；
//  2. 双时间点缓存模型（PrefetchTime / StaleTime / ExpiresAt）下的降级与 fail-fast。

// fakeClock 可推进的测试时钟，经 cache.SetClock 注入核心 SDK。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// useFakeClock 把核心 SDK 的包级时钟切到 fakeClock，并在测试结束时恢复系统时钟。
func useFakeClock(t *testing.T, start time.Time) *fakeClock {
	t.Helper()
	clock := &fakeClock{now: start}
	cache.SetClock(clock)
	t.Cleanup(func() { cache.SetClock(&cache.SystemClock{}) })
	return clock
}

// --- ctx 感知的刷新链路 ---

// refreshCredential 必须走 ctx 版 API：OIDC 获取与 PAM HTTP 调用都收到带 deadline 的
// 刷新 ctx（由 supplier 注入 = 宿主 baseCtx + asyncRefreshTimeout）。
func TestRefreshCredential_UsesContextAwareAPIs(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	oidc := &fakeOidcTokenProvider{token: "tok"}
	p := newProviderWithFake(t, http, oidc)

	if _, err := p.GetStsCredential(); err != nil {
		t.Fatalf("GetStsCredential: %v", err)
	}
	if http.lastCtx == nil || oidc.lastCtx == nil {
		t.Fatal("refresh chain must pass a context to ExecuteContext / GetOidcTokenWithContext")
	}
	deadline, ok := http.lastCtx.Deadline()
	if !ok {
		t.Error("refresh ctx should carry the supplier's async refresh deadline")
	} else if d := time.Until(deadline); d <= 0 || d > 5*time.Minute {
		t.Errorf("refresh deadline out of range: %v", d)
	}
}

// ctx 已取消 → 不发起刷新（不消耗 PAM 配额），立即返回 ClientRequestCanceled。
func TestGetStsCredentialWithContext_PreCanceledShortCircuits(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	oidc := &fakeOidcTokenProvider{token: "tok"}
	p := newProviderWithFake(t, http, oidc)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.GetStsCredentialWithContext(ctx)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false, want true: %v", err)
	}
	var ce *sdkerrors.CacheError
	if !errors.As(err, &ce) || ce.Code != sdkconstants.ClientRequestCanceled {
		t.Fatalf("expected CacheError[%s], got %T: %v", sdkconstants.ClientRequestCanceled, err, err)
	}
	if http.calls != 0 || oidc.lastCtx != nil {
		t.Errorf("canceled ctx must not start a refresh: httpCalls=%d oidcCalled=%v", http.calls, oidc.lastCtx != nil)
	}
}

// 刷新在飞、调用方 ctx 到期 → 立即返回错误而不是干等（在飞刷新继续，结果写入缓存）。
func TestGetStsCredentialWithContext_DeadlineStopsWaiting(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	release := make(chan struct{})
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp)), release: release}
	t.Cleanup(func() { close(release) }) // 让后台 worker 收尾，不泄漏到其它测试

	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := p.GetStsCredentialWithContext(ctx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected deadline error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded in chain, got: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("caller should return promptly on deadline, waited %v", elapsed)
	}
}

// nil ctx 兜底为 Background（上游 SDK 可能传入 nil ctx）。
func TestGetStsCredentialWithContext_NilContext(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	cred, err := p.GetStsCredentialWithContext(nil) //nolint:staticcheck // 故意传 nil 验证兜底
	if err != nil {
		t.Fatalf("nil ctx should be treated as Background: %v", err)
	}
	if cred.AccessKeyId != "AKID123" {
		t.Errorf("accessKeyId=%q", cred.AccessKeyId)
	}
}

// --- 双时间点模型下的降级 / fail-fast ---

// 越过 StaleTime 但未过 ExpiresAt：同步刷新失败 → 静默降级返回仍有效的旧缓存。
func TestGetStsCredential_DegradesToCachedInStaleWindow(t *testing.T) {
	base := time.Now().UTC()
	clock := useFakeClock(t, base)

	// STS 寿命 30min → StaleTime=24min、PrefetchTime=20min、ExpiresAt=30min。
	exp := base.Add(30 * time.Minute).Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	first, err := p.GetStsCredential()
	if err != nil {
		t.Fatalf("first GetStsCredential: %v", err)
	}
	if http.calls != 1 {
		t.Fatalf("http calls=%d, want 1", http.calls)
	}

	// PAM 故障 + 时钟推进到 stale 窗口（25min）。
	http.err = fmt.Errorf("pam unavailable")
	clock.advance(25 * time.Minute)

	second, err := p.GetStsCredential()
	if err != nil {
		t.Fatalf("stale-window refresh failure should degrade silently, got: %v", err)
	}
	if second.AccessKeyId != first.AccessKeyId {
		t.Errorf("degraded credential mismatch: %+v", second)
	}
	if http.calls != 2 {
		t.Errorf("http calls=%d, want 2 (stale window triggers a sync refresh)", http.calls)
	}
}

// 越过 ExpiresAt 且刷新失败：supplier 交回过期旧值（ErrStaleCredentialReturned 信号），
// 适配器必须 fail-fast 抛 CredentialExpired，并把降级信号保留在 cause 链里。
func TestGetStsCredential_ExpiredCacheFailFastKeepsStaleSignal(t *testing.T) {
	base := time.Now().UTC()
	clock := useFakeClock(t, base)

	exp := base.Add(10 * time.Minute).Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	if _, err := p.GetStsCredential(); err != nil {
		t.Fatalf("first GetStsCredential: %v", err)
	}

	http.err = fmt.Errorf("pam unavailable")
	clock.advance(11 * time.Minute) // 已过真实过期点

	_, err := p.GetStsCredential()
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.CredentialExpired {
		t.Fatalf("expected CredentialError[%s], got %T: %v", constants.CredentialExpired, err, err)
	}
	if !errors.Is(err, cache.ErrStaleCredentialReturned) {
		t.Errorf("error cause should retain the SDK degrade signal, got: %v", err)
	}
}

// --- oidcTokenAdapter 的无 ctx 入口（接口兼容用）---

func TestOidcTokenAdapter_NoContextEntryDelegates(t *testing.T) {
	a := &oidcTokenAdapter{credProvider: &fakeIDaaSCredentialProvider{token: "t1"}}
	tok, err := a.GetOidcToken()
	if err != nil || tok != "t1" {
		t.Fatalf("GetOidcToken=%q err=%v, want t1/nil", tok, err)
	}

	aErr := &oidcTokenAdapter{credProvider: &fakeIDaaSCredentialProvider{err: errors.New("core down")}}
	if _, err := aErr.GetOidcToken(); err == nil {
		t.Error("expected error from underlying provider")
	}
}

// --- OSS V2 适配器透传 ctx ---

func TestOSSV2Provider_PropagatesCallerContext(t *testing.T) {
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	core := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})
	ossV2 := NewIDaaSPamOSSV2CredentialsProvider(core)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ossV2.GetCredentials(ctx); err == nil {
		t.Fatal("canceled ctx should surface as an error")
	}
	if http.calls != 0 {
		t.Errorf("canceled ctx must not start a PAM refresh, calls=%d", http.calls)
	}
}

// --- 已过期刷新结果的拒绝与退避（M1）---

// PAM 返回 200 但 expiration 已过期（时钟偏移 / PAM 异常）：必须按"刷新失败"处理，
// 抛 CredentialError(CredentialExpired)，而不是把不可用值提交进缓存。
func TestRefreshCredential_RejectsAlreadyExpiredCredential(t *testing.T) {
	clock := useFakeClock(t, time.Now().UTC())
	past := clock.Now().Add(-time.Minute).Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(past))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	_, err := p.GetStsCredential()
	var ce *sdkerrors.CredentialError
	if !errors.As(err, &ce) || ce.Code != constants.CredentialExpired {
		t.Fatalf("expected CredentialError[%s], got %T: %v", constants.CredentialExpired, err, err)
	}
}

// 已有有效缓存、越过 StaleTime 后 PAM 返回"已过期"的成功响应：刷新按失败处理并进入
// 退避窗口——调用方继续拿到旧的有效凭证（不被过期值顶掉），且退避窗口内不再逐请求重刷 PAM。
func TestRefreshCredential_ExpiredPayloadKeepsValidCacheAndBacksOff(t *testing.T) {
	base := time.Now().UTC()
	clock := useFakeClock(t, base)

	// STS 寿命 30min → StaleTime=24min。
	exp := base.Add(30 * time.Minute).Format(time.RFC3339)
	http := &fakeHttpClient{resp: domainResponse(200, pamSuccessBody(exp))}
	p := newProviderWithFake(t, http, &fakeOidcTokenProvider{token: "tok"})

	first, err := p.GetStsCredential()
	if err != nil {
		t.Fatalf("first GetStsCredential: %v", err)
	}

	// 推进到 stale 窗口（25min），PAM 改为返回已过期 expiration 的 200 响应。
	clock.advance(25 * time.Minute)
	badExp := clock.Now().Add(-time.Minute).Format(time.RFC3339)
	http.resp = domainResponse(200, pamSuccessBody(badExp))

	second, err := p.GetStsCredential()
	if err != nil {
		t.Fatalf("bad refresh in stale window should degrade to old valid credential, got: %v", err)
	}
	if second.AccessKeyId != first.AccessKeyId {
		t.Errorf("degraded credential mismatch: %+v", second)
	}
	if http.calls != 2 {
		t.Fatalf("http calls=%d, want 2 (one stale-window refresh attempted)", http.calls)
	}

	// 退避窗口内再次获取：直接命中旧缓存，不再打 PAM（刷新失败已记录，退避生效）。
	third, err := p.GetStsCredential()
	if err != nil {
		t.Fatalf("backoff-window get should still serve cached credential: %v", err)
	}
	if third.AccessKeyId != first.AccessKeyId {
		t.Errorf("backoff-window credential mismatch: %+v", third)
	}
	if http.calls != 2 {
		t.Errorf("backoff window must not re-hit PAM, calls=%d, want 2", http.calls)
	}
}
