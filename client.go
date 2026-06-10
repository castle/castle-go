package castle

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// Params is a JSON object passed to, or returned from, the Castle API. The SDK
// forwards request parameters to the API verbatim and returns parsed responses
// without imposing a fixed schema.
type Params = map[string]interface{}

// Castle is a client for the Castle API. Create one with New; it is safe for
// concurrent use by multiple goroutines.
type Castle struct {
	config *config
}

// New creates a Castle client authenticated with the given API secret.
func New(secret string, opts ...Option) (*Castle, error) {
	cfg := defaultConfig(secret)
	for _, opt := range opts {
		opt(cfg)
	}

	if strings.TrimSpace(cfg.apiSecret) == "" {
		return nil, &ConfigurationError{Message: "castle: API secret is missing"}
	}
	if !cfg.failoverStrategy.valid() {
		return nil, &ConfigurationError{Message: "castle: invalid failover strategy: " + string(cfg.failoverStrategy)}
	}
	if cfg.timeout <= 0 {
		cfg.timeout = DefaultTimeout
	}
	if cfg.httpClient == nil {
		cfg.httpClient = &http.Client{Timeout: cfg.timeout}
	} else if cfg.httpClient.Timeout == 0 {
		cfg.httpClient.Timeout = cfg.timeout
	}
	cfg.trustedProxyRes = compileTrustedProxies(cfg.trustedProxies)

	return &Castle{config: cfg}, nil
}

// DoNotTrack reports whether outbound tracking is disabled.
func (c *Castle) DoNotTrack() bool { return c.config.doNotTrack }

func (c *Castle) request(ctx context.Context, method, path string, payload Params) (Params, error) {
	url := strings.TrimRight(c.config.baseURL, "/") + "/" + strings.TrimLeft(path, "/")

	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, &RequestError{Message: "castle: failed to encode request body", Err: err}
		}
		body = bytes.NewReader(encoded)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, &RequestError{Message: "castle: failed to build request", Err: err}
	}
	req.SetBasicAuth("", c.config.apiSecret)
	req.Header.Set("Content-Type", "application/json")

	res, err := c.config.httpClient.Do(req)
	if err != nil {
		return nil, &RequestError{Message: "castle: request failed", Err: err}
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, &RequestError{Message: "castle: failed to read response body", Err: err}
	}

	if res.StatusCode == http.StatusNoContent || len(bytes.TrimSpace(resBody)) == 0 {
		if res.StatusCode >= 200 && res.StatusCode < 300 {
			return Params{}, nil
		}
		return nil, errorFromResponse(res.StatusCode, "", "")
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var apiErr struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(resBody, &apiErr)
		message := apiErr.Message
		if message == "" {
			message = string(bytes.TrimSpace(resBody))
		}
		return nil, errorFromResponse(res.StatusCode, apiErr.Type, message)
	}

	return decodeBody(resBody)
}

// decodeBody parses a JSON response into Params. Bare JSON arrays are returned
// under the "data" key so every command has a uniform map return type.
func decodeBody(b []byte) (Params, error) {
	var value interface{}
	if err := json.Unmarshal(b, &value); err != nil {
		return nil, &APIError{Message: "castle: failed to decode response body: " + err.Error()}
	}
	switch v := value.(type) {
	case map[string]interface{}:
		return v, nil
	default:
		return Params{"data": v}, nil
	}
}

func generateTimestamp() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}
