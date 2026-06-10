package castle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// SecureModeSignature returns the HMAC-SHA256 signature of userID keyed by the
// configured API secret, hex-encoded. Use it to authenticate the user passed to
// Castle's client-side scripts in secure mode.
func (c *Castle) SecureModeSignature(userID string) string {
	mac := hmac.New(sha256.New, []byte(c.config.apiSecret))
	mac.Write([]byte(userID))
	return hex.EncodeToString(mac.Sum(nil))
}
