package castle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sign(body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhook(t *testing.T) {
	client, err := New("secret")
	require.NoError(t, err)
	body := []byte(`{"type":"$incident.confirmed"}`)

	t.Run("valid", func(t *testing.T) {
		assert.NoError(t, client.VerifyWebhook(body, sign(string(body), "secret")))
	})

	t.Run("invalid", func(t *testing.T) {
		var verifyErr *WebhookVerificationError
		assert.ErrorAs(t, client.VerifyWebhook(body, "nope"), &verifyErr)
	})

	t.Run("empty body", func(t *testing.T) {
		var verifyErr *WebhookVerificationError
		assert.ErrorAs(t, client.VerifyWebhook(nil, ""), &verifyErr)
	})
}

func TestVerifyWebhookRequest(t *testing.T) {
	client, err := New("secret")
	require.NoError(t, err)
	body := `{"type":"$incident.confirmed"}`

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(body))
	req.Header.Set(WebhookSignatureHeader, sign(body, "secret"))

	require.NoError(t, client.VerifyWebhookRequest(req))

	// Body must still be readable after verification.
	rest, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.Equal(t, body, string(rest))
}
