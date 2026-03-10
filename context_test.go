package castle

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(opts ...Option) *Client {
	defaults := []Option{WithAPISecret("test")}
	c, _ := NewClient(append(defaults, opts...)...)
	return c
}

// --- Client ID extraction ---

func TestContextFromRequest_ClientID_FromCookie(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "__cid", Value: "cookie-cid"})

	ctx := c.ContextFromRequest(r)
	if ctx.ClientID != "cookie-cid" {
		t.Errorf("expected 'cookie-cid', got %q", ctx.ClientID)
	}
}

func TestContextFromRequest_ClientID_FromHeader(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Castle-Client-Id", "header-cid")

	ctx := c.ContextFromRequest(r)
	if ctx.ClientID != "header-cid" {
		t.Errorf("expected 'header-cid', got %q", ctx.ClientID)
	}
}

func TestContextFromRequest_ClientID_HeaderOverCookie(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "__cid", Value: "cookie-cid"})
	r.Header.Set("X-Castle-Client-Id", "header-cid")

	ctx := c.ContextFromRequest(r)
	if ctx.ClientID != "header-cid" {
		t.Errorf("expected header to win, got %q", ctx.ClientID)
	}
}

func TestContextFromRequest_ClientID_Empty(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)

	ctx := c.ContextFromRequest(r)
	if ctx.ClientID != "" {
		t.Errorf("expected empty, got %q", ctx.ClientID)
	}
}

// --- Context metadata ---

func TestContextFromRequest_Active(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)

	ctx := c.ContextFromRequest(r)
	if !ctx.Active {
		t.Error("expected Active=true")
	}
}

func TestContextFromRequest_Library(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)

	ctx := c.ContextFromRequest(r)
	if ctx.Library == nil {
		t.Fatal("expected library info")
	}
	if ctx.Library.Name != "castle-go" {
		t.Errorf("expected name 'castle-go', got %q", ctx.Library.Name)
	}
	if ctx.Library.Version != Version {
		t.Errorf("expected version %q, got %q", Version, ctx.Library.Version)
	}
}

func TestContextFromRequest_UserAgent(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Test")

	ctx := c.ContextFromRequest(r)
	if ctx.UserAgent != "Mozilla/5.0 Test" {
		t.Errorf("expected user_agent from User-Agent header, got %q", ctx.UserAgent)
	}
}

func TestContextFromRequest_UserAgent_Empty(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)

	ctx := c.ContextFromRequest(r)
	if ctx.UserAgent != "" {
		t.Errorf("expected empty user_agent when no User-Agent header, got %q", ctx.UserAgent)
	}
}

func TestContextFromRequest_Locale(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")

	ctx := c.ContextFromRequest(r)
	if ctx.Locale != "en-US,en;q=0.9" {
		t.Errorf("expected locale from Accept-Language, got %q", ctx.Locale)
	}
}

func TestContextFromRequest_Locale_Empty(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)

	ctx := c.ContextFromRequest(r)
	if ctx.Locale != "" {
		t.Errorf("expected empty locale when no Accept-Language, got %q", ctx.Locale)
	}
}

// --- IP extraction ---

func TestContextFromRequest_IP_FromRemoteAddr(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:1234"

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_FromXRealIP(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Real-Ip", "5.5.5.5")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "5.5.5.5" {
		t.Errorf("expected '5.5.5.5', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_XFFOverXRealIP(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Real-Ip", "5.5.5.5")
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 7.7.7.7")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "7.7.7.7" {
		t.Errorf("expected '7.7.7.7', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_XFFStripsPrivate(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "8.8.8.8, 192.168.1.1")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "8.8.8.8" {
		t.Errorf("expected '8.8.8.8' (stripped private proxy), got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_XFFSinglePublic(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "9.9.9.9")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "9.9.9.9" {
		t.Errorf("expected '9.9.9.9', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_TrustProxyChain(t *testing.T) {
	c := newTestClient(WithTrustProxyChain(true))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "1.1.1.1" {
		t.Errorf("with trust_proxy_chain, expected leftmost '1.1.1.1', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_TrustedProxyDepth(t *testing.T) {
	c := newTestClient(WithTrustedProxyDepth(1))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "2.2.2.2" {
		t.Errorf("with depth=1, expected '2.2.2.2', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_TrustedProxyDepth2(t *testing.T) {
	c := newTestClient(WithTrustedProxyDepth(2))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "1.1.1.1" {
		t.Errorf("with depth=2, expected '1.1.1.1', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_CustomIPHeader(t *testing.T) {
	c := newTestClient(WithIPHeaders([]string{"CF-Connecting-IP"}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.1.1.1")
	r.Header.Set("CF-Connecting-IP", "4.4.4.4")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "4.4.4.4" {
		t.Errorf("custom IP header should take priority, expected '4.4.4.4', got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_ConfiguredTrustedProxy(t *testing.T) {
	c := newTestClient(WithTrustedProxies([]string{"3.3.3.3"}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "2.2.2.2" {
		t.Errorf("expected '2.2.2.2' (3.3.3.3 is trusted proxy), got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_TrustedProxyCIDR(t *testing.T) {
	c := newTestClient(WithTrustedProxies([]string{"3.3.3.0/24"}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.99")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "2.2.2.2" {
		t.Errorf("expected '2.2.2.2' (3.3.3.99 in CIDR proxy), got %q", ctx.IP)
	}
}

func TestContextFromRequest_IP_AllPrivate(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1, 172.16.0.1")

	ctx := c.ContextFromRequest(r)
	if ctx.IP != "10.0.0.1" {
		t.Errorf("when all private, expected first '10.0.0.1', got %q", ctx.IP)
	}
}

// --- Header extraction ---

func TestContextFromRequest_Headers_DefaultSendsAll(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "test-agent")
	r.Header.Set("Accept-Language", "en-US")
	r.Header.Set("X-Custom-Header", "custom-value")

	ctx := c.ContextFromRequest(r)
	if ctx.Headers["User-Agent"] != "test-agent" {
		t.Error("User-Agent should be included")
	}
	if ctx.Headers["Accept-Language"] != "en-US" {
		t.Error("Accept-Language should be included")
	}
	if ctx.Headers["X-Custom-Header"] != "custom-value" {
		t.Error("with no allowlist configured, all headers should be sent")
	}
}

func TestContextFromRequest_Headers_CookieScrubbedToTrue(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "session=abc123")

	ctx := c.ContextFromRequest(r)
	val, found := ctx.Headers["Cookie"]
	if !found {
		t.Fatal("Cookie header should be present (scrubbed to true)")
	}
	if val != true {
		t.Errorf("Cookie should be scrubbed to true, got %v", val)
	}
}

func TestContextFromRequest_Headers_AuthorizationScrubbedToTrue(t *testing.T) {
	c := newTestClient()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer token123")

	ctx := c.ContextFromRequest(r)
	val, found := ctx.Headers["Authorization"]
	if !found {
		t.Fatal("Authorization header should be present (scrubbed to true)")
	}
	if val != true {
		t.Errorf("Authorization should be scrubbed to true, got %v", val)
	}
}

func TestContextFromRequest_Headers_UserAgentNeverScrubbed(t *testing.T) {
	c := newTestClient(WithDenylistedHeaders([]string{"User-Agent"}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "test-agent")

	ctx := c.ContextFromRequest(r)
	if ctx.Headers["User-Agent"] != "test-agent" {
		t.Errorf("User-Agent should never be scrubbed (ALWAYS_ALLOWLISTED), got %v", ctx.Headers["User-Agent"])
	}
}

func TestContextFromRequest_Headers_CustomAllowlist(t *testing.T) {
	c := newTestClient(WithAllowlistedHeaders([]string{"X-Custom-Header"}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Custom-Header", "custom-value")
	r.Header.Set("Accept-Language", "en-US")
	r.Header.Set("User-Agent", "test-agent")

	ctx := c.ContextFromRequest(r)
	if ctx.Headers["X-Custom-Header"] != "custom-value" {
		t.Error("allowlisted header should have real value")
	}
	if ctx.Headers["Accept-Language"] != true {
		t.Errorf("non-allowlisted header should be scrubbed to true, got %v", ctx.Headers["Accept-Language"])
	}
	if ctx.Headers["User-Agent"] != "test-agent" {
		t.Error("User-Agent always allowed even when not in custom allowlist")
	}
}

func TestContextFromRequest_Headers_CustomDenylist(t *testing.T) {
	c := newTestClient(WithDenylistedHeaders([]string{"X-Secret"}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Secret", "should-be-scrubbed")
	r.Header.Set("Accept-Language", "en-US")

	ctx := c.ContextFromRequest(r)
	if ctx.Headers["X-Secret"] != true {
		t.Errorf("denylisted header should be scrubbed to true, got %v", ctx.Headers["X-Secret"])
	}
	if ctx.Headers["Accept-Language"] != "en-US" {
		t.Error("non-denied header should have real value")
	}
}

func TestContextFromRequest_Headers_DefaultAllowlistOptIn(t *testing.T) {
	c := newTestClient(WithAllowlistedHeaders(DefaultAllowlist))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "test-agent")
	r.Header.Set("X-Internal-Secret", "secret")

	ctx := c.ContextFromRequest(r)
	if ctx.Headers["User-Agent"] != "test-agent" {
		t.Error("User-Agent in DefaultAllowlist, should have real value")
	}
	if ctx.Headers["X-Internal-Secret"] != true {
		t.Errorf("non-allowlisted header should be scrubbed to true, got %v", ctx.Headers["X-Internal-Secret"])
	}
}
