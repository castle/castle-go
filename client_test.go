package castle

import (
	"testing"
	"time"
)

func TestNewClient_RequiresAPISecret(t *testing.T) {
	_, err := NewClient()
	if err != ErrMissingAPISecret {
		t.Fatalf("expected ErrMissingAPISecret, got %v", err)
	}
}

func TestNewClient_EmptySecretFails(t *testing.T) {
	_, err := NewClient(WithAPISecret(""))
	if err != ErrMissingAPISecret {
		t.Fatalf("expected ErrMissingAPISecret, got %v", err)
	}
}

func TestNewClient_ValidSecret(t *testing.T) {
	c, err := NewClient(WithAPISecret("test-secret"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.cfg.apiSecret != "test-secret" {
		t.Errorf("expected api secret 'test-secret', got %q", c.cfg.apiSecret)
	}
}

func TestNewClient_Defaults(t *testing.T) {
	c, err := NewClient(WithAPISecret("sk_test"))
	if err != nil {
		t.Fatal(err)
	}

	if c.cfg.baseURL != defaultBaseURL {
		t.Errorf("expected base URL %q, got %q", defaultBaseURL, c.cfg.baseURL)
	}
	if c.cfg.timeout != 1000*time.Millisecond {
		t.Errorf("expected timeout 1s, got %v", c.cfg.timeout)
	}
	if c.cfg.failoverStrategy != FailoverAllow {
		t.Errorf("expected failover strategy allow, got %v", c.cfg.failoverStrategy)
	}
	if c.cfg.doNotTrack {
		t.Error("expected doNotTrack=false")
	}
	if c.cfg.httpClient == nil {
		t.Error("expected default HTTP client")
	}
	if len(c.cfg.allowlisted) != 0 {
		t.Error("expected empty default allowlist (send all headers)")
	}
}

func TestNewClient_OptionOverrides(t *testing.T) {
	c, err := NewClient(
		WithAPISecret("sk_test"),
		WithBaseURL("https://custom.api.io/v1"),
		WithTimeout(2*time.Second),
		WithFailoverStrategy(FailoverDeny),
		WithDoNotTrack(true),
		WithAllowlistedHeaders([]string{"X-Custom"}),
		WithDenylistedHeaders([]string{"X-Secret"}),
		WithIPHeaders([]string{"CF-Connecting-IP"}),
		WithTrustedProxies([]string{"10.0.0.0/8"}),
		WithTrustedProxyDepth(2),
		WithTrustProxyChain(true),
	)
	if err != nil {
		t.Fatal(err)
	}

	if c.cfg.baseURL != "https://custom.api.io/v1" {
		t.Errorf("baseURL: got %q", c.cfg.baseURL)
	}
	if c.cfg.timeout != 2*time.Second {
		t.Errorf("timeout: got %v", c.cfg.timeout)
	}
	if c.cfg.failoverStrategy != FailoverDeny {
		t.Errorf("failover: got %v", c.cfg.failoverStrategy)
	}
	if !c.cfg.doNotTrack {
		t.Error("doNotTrack should be true")
	}
	if len(c.cfg.allowlisted) != 1 || c.cfg.allowlisted[0] != "X-Custom" {
		t.Errorf("allowlisted: got %v", c.cfg.allowlisted)
	}
	if len(c.cfg.denylisted) != 1 || c.cfg.denylisted[0] != "X-Secret" {
		t.Errorf("denylisted: got %v", c.cfg.denylisted)
	}
	if len(c.cfg.ipHeaders) != 1 || c.cfg.ipHeaders[0] != "CF-Connecting-IP" {
		t.Errorf("ipHeaders: got %v", c.cfg.ipHeaders)
	}
	if c.cfg.trustedProxyDepth != 2 {
		t.Errorf("trustedProxyDepth: got %d", c.cfg.trustedProxyDepth)
	}
	if !c.cfg.trustProxyChain {
		t.Error("trustProxyChain should be true")
	}
}

func TestNewClient_CustomHTTPClient(t *testing.T) {
	fake := &fakeDoer{}
	c, err := NewClient(WithAPISecret("sk"), WithHTTPClient(fake))
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.httpClient != fake {
		t.Error("expected custom HTTP client to be set")
	}
}
