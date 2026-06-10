package castle

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
)

// WebhookSignatureHeader is the header Castle uses to sign webhook payloads.
const WebhookSignatureHeader = "X-Castle-Signature"

// VerifyWebhook checks that signature matches the HMAC-SHA256 of body keyed by
// the configured API secret. It returns nil when the signature is valid and a
// *WebhookVerificationError otherwise.
func (c *Castle) VerifyWebhook(body []byte, signature string) error {
	if len(body) == 0 {
		return &WebhookVerificationError{Message: "castle: webhook body is empty"}
	}

	expected := computeWebhookSignature(body, c.config.apiSecret)
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return &WebhookVerificationError{Message: "castle: invalid webhook signature"}
	}
	return nil
}

// VerifyWebhookRequest verifies the X-Castle-Signature header of an incoming
// HTTP request. The request body is fully read and replaced so it can be read
// again by the caller.
func (c *Castle) VerifyWebhookRequest(r *http.Request) error {
	var body []byte
	if r.Body != nil {
		read, err := io.ReadAll(r.Body)
		if err != nil {
			return &WebhookVerificationError{Message: "castle: failed to read webhook body"}
		}
		_ = r.Body.Close()
		body = read
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return c.VerifyWebhook(body, r.Header.Get(WebhookSignatureHeader))
}

func computeWebhookSignature(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
