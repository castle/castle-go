package castle

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContextFromRequestLibrary(t *testing.T) {
	client, err := New("secret")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	ctx := client.ContextFromRequest(req)

	lib, ok := ctx["library"].(Params)
	require.True(t, ok)
	assert.Equal(t, libraryName, lib["name"])
	assert.Equal(t, Version, lib["version"])
}

func TestExtractHeadersDenyListMode(t *testing.T) {
	client, err := New("secret", WithDenyList("X-Secret"))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "agent")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("Authorization", "Bearer x")
	req.Header.Set("X-Secret", "hush")

	headers := client.extractHeaders(req)
	assert.Equal(t, "agent", headers["User-Agent"])
	assert.Equal(t, "application/json", headers["Accept"])
	assert.Equal(t, true, headers["Cookie"])
	assert.Equal(t, true, headers["Authorization"])
	assert.Equal(t, true, headers["X-Secret"])
}

func TestExtractHeadersAllowListMode(t *testing.T) {
	client, err := New("secret", WithAllowList("Accept"))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "agent")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Other", "value")

	headers := client.extractHeaders(req)
	assert.Equal(t, "application/json", headers["Accept"])
	assert.Equal(t, "agent", headers["User-Agent"]) // always preserved
	assert.Equal(t, true, headers["X-Other"])
}

func TestExtractIPForwardedFor(t *testing.T) {
	client, err := New("secret")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	// last untrusted entry is the real client; 10.x is a trusted proxy
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.5")

	assert.Equal(t, "1.2.3.4", client.extractIP(req))
}

func TestExtractIPTrustProxyChain(t *testing.T) {
	client, err := New("secret", WithTrustProxyChain(true))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 1.2.3.4")

	assert.Equal(t, "9.9.9.9", client.extractIP(req))
}

func TestExtractIPTrustedProxyDepth(t *testing.T) {
	client, err := New("secret", WithTrustedProxyDepth(1))
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8")

	assert.Equal(t, "1.2.3.4", client.extractIP(req))
}

func TestExtractIPFallsBackToRemoteAddr(t *testing.T) {
	client, err := New("secret")
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.7:5555"

	assert.Equal(t, "203.0.113.7", client.extractIP(req))
}
