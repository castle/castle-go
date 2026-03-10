package castle

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// HTTPDoer abstracts HTTP calls for testing and customization.
// *http.Client satisfies this interface.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Logger is an optional structured logger interface.
type Logger interface {
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// do executes an API request and returns the raw response.
func (c *Client) do(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	url := c.cfg.baseURL + path

	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("castle: failed to marshal request body: %w", err)
		}
		buf, err = injectSentAt(buf)
		if err != nil {
			return nil, fmt.Errorf("castle: failed to inject sent_at: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("castle: failed to create request: %w", err)
	}

	req.SetBasicAuth("", c.cfg.apiSecret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "castle-go/"+Version)

	if c.cfg.logger != nil {
		c.cfg.logger.Debugf("castle: %s %s", method, url)
	}

	resp, err := c.cfg.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// doJSON executes an API request and decodes the JSON response into dest.
// Returns an *APIError for non-2xx responses.
func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}, dest interface{}) error {
	resp, err := c.do(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("castle: failed to read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return mapResponseError(resp.StatusCode, respBody)
	}

	if dest != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, dest); err != nil {
			return fmt.Errorf("castle: failed to parse response: %w", err)
		}
	}

	return nil
}

// injectSentAt adds a "sent_at" ISO 8601 timestamp to a JSON object payload.
// Matches Ruby SDK behavior where command builders append sent_at to every request.
func injectSentAt(buf []byte) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf, &m); err != nil {
		return buf, nil
	}
	ts, _ := json.Marshal(time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	m["sent_at"] = ts
	return json.Marshal(m)
}
