package castle

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeDoer is a mock HTTPDoer for unit tests.
type fakeDoer struct {
	handler func(req *http.Request) (*http.Response, error)
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	if f.handler != nil {
		return f.handler(req)
	}
	return nil, errors.New("no handler configured")
}

func TestFilter_Success(t *testing.T) {
	respJSON := `{
		"policy": {"id": "p1", "revision_id": "r1", "name": "Login policy", "action": "allow"},
		"risk": 0.2,
		"device_token": "dt_abc"
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth
		_, pass, ok := r.BasicAuth()
		if !ok || pass != "sk_test" {
			t.Error("expected basic auth with api secret")
		}

		// Verify content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected JSON content type, got %q", r.Header.Get("Content-Type"))
		}

		// Verify request body
		body, _ := io.ReadAll(r.Body)
		var reqBody map[string]interface{}
		json.Unmarshal(body, &reqBody)
		if reqBody["type"] != "$login" {
			t.Errorf("expected type '$login', got %v", reqBody["type"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(respJSON))
	}))
	defer ts.Close()

	c, _ := NewClient(WithAPISecret("sk_test"), WithBaseURL(ts.URL))

	resp, err := c.Filter(context.Background(), &FilterRequest{
		Type:         "$login",
		Status:       "$attempted",
		RequestToken: "token123",
		Context:      &Context{IP: "1.2.3.4"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Policy.Action != ActionAllow {
		t.Errorf("expected allow, got %v", resp.Policy.Action)
	}
	if resp.DeviceToken != "dt_abc" {
		t.Errorf("expected device_token 'dt_abc', got %q", resp.DeviceToken)
	}
	if resp.Failover {
		t.Error("should not be failover")
	}
}

func TestFilter_Failover_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer ts.Close()

	c, _ := NewClient(
		WithAPISecret("sk_test"),
		WithBaseURL(ts.URL),
		WithTimeout(50*time.Millisecond),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	resp, err := c.Filter(ctx, &FilterRequest{Type: "$login"})
	if err != nil {
		t.Fatalf("failover should not return error, got: %v", err)
	}
	if resp.Policy.Action != ActionAllow {
		t.Errorf("expected allow failover, got %v", resp.Policy.Action)
	}
	if !resp.Failover {
		t.Error("expected Failover=true")
	}
	if resp.FailoverReason != "timeout" && resp.FailoverReason != "canceled" {
		t.Errorf("expected timeout/canceled reason, got %q", resp.FailoverReason)
	}
}

func TestFilter_Failover_5xx(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		w.Write([]byte(`{"message":"bad gateway"}`))
	}))
	defer ts.Close()

	c, _ := NewClient(WithAPISecret("sk_test"), WithBaseURL(ts.URL))

	resp, err := c.Filter(context.Background(), &FilterRequest{Type: "$login"})
	if err != nil {
		t.Fatalf("failover should not return error, got: %v", err)
	}
	if resp.Policy.Action != ActionAllow {
		t.Errorf("expected allow failover, got %v", resp.Policy.Action)
	}
	if !resp.Failover {
		t.Error("expected Failover=true")
	}
	if resp.FailoverReason != "server_error" {
		t.Errorf("expected 'server_error' reason, got %q", resp.FailoverReason)
	}
}

func TestFilter_Failover_DenyStrategy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	c, _ := NewClient(
		WithAPISecret("sk_test"),
		WithBaseURL(ts.URL),
		WithFailoverStrategy(FailoverDeny),
	)

	resp, err := c.Filter(context.Background(), &FilterRequest{Type: "$login"})
	if err != nil {
		t.Fatalf("failover should not return error, got: %v", err)
	}
	if resp.Policy.Action != ActionDeny {
		t.Errorf("expected deny failover, got %v", resp.Policy.Action)
	}
}

func TestFilter_Failover_ThrowStrategy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	c, _ := NewClient(
		WithAPISecret("sk_test"),
		WithBaseURL(ts.URL),
		WithFailoverStrategy(FailoverThrow),
	)

	_, err := c.Filter(context.Background(), &FilterRequest{Type: "$login"})
	if err == nil {
		t.Fatal("FailoverThrow should return error")
	}
	if !errors.Is(err, ErrInternalServer) {
		t.Errorf("expected ErrInternalServer, got %v", err)
	}
}

func TestFilter_4xx_NoFailover(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		w.Write([]byte(`{"type":"invalid_request_token","message":"expired"}`))
	}))
	defer ts.Close()

	c, _ := NewClient(WithAPISecret("sk_test"), WithBaseURL(ts.URL))

	_, err := c.Filter(context.Background(), &FilterRequest{Type: "$login"})
	if err == nil {
		t.Fatal("4xx should return error, not failover")
	}
	if !errors.Is(err, ErrInvalidRequestToken) {
		t.Errorf("expected ErrInvalidRequestToken, got %v", err)
	}
}

func TestFilter_DoNotTrack(t *testing.T) {
	c, _ := NewClient(WithAPISecret("sk_test"), WithDoNotTrack(true))

	resp, err := c.Filter(context.Background(), &FilterRequest{Type: "$login"})
	if err != nil {
		t.Fatalf("doNotTrack should not error: %v", err)
	}
	if !resp.Failover {
		t.Error("doNotTrack should set Failover=true")
	}
	if resp.FailoverReason != "do_not_track" {
		t.Errorf("expected reason 'do_not_track', got %q", resp.FailoverReason)
	}
}

func TestFilter_DoNotTrack_AlwaysAllow(t *testing.T) {
	c, _ := NewClient(
		WithAPISecret("sk_test"),
		WithDoNotTrack(true),
		WithFailoverStrategy(FailoverDeny),
	)

	resp, err := c.Filter(context.Background(), &FilterRequest{Type: "$login"})
	if err != nil {
		t.Fatalf("doNotTrack should not error: %v", err)
	}
	if resp.Policy.Action != ActionAllow {
		t.Errorf("doNotTrack should always use allow regardless of configured strategy, got %v", resp.Policy.Action)
	}
}

func TestFilter_RequestBody(t *testing.T) {
	var captured map[string]interface{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &captured)
		w.WriteHeader(201)
		w.Write([]byte(`{"policy":{"action":"allow"}}`))
	}))
	defer ts.Close()

	c, _ := NewClient(WithAPISecret("sk_test"), WithBaseURL(ts.URL))

	c.Filter(context.Background(), &FilterRequest{
		Type:         "$registration",
		Status:       "$attempted",
		RequestToken: "tok_123",
		Context:      &Context{Active: true, IP: "1.1.1.1", Headers: map[string]interface{}{"User-Agent": "test"}},
		User:         &User{Email: "test@example.com"},
	})

	if captured["type"] != "$registration" {
		t.Errorf("type: expected '$registration', got %v", captured["type"])
	}
	if captured["status"] != "$attempted" {
		t.Errorf("status: expected '$attempted', got %v", captured["status"])
	}
	if captured["request_token"] != "tok_123" {
		t.Errorf("request_token: expected 'tok_123', got %v", captured["request_token"])
	}

	ctxMap, ok := captured["context"].(map[string]interface{})
	if !ok {
		t.Fatal("context should be present")
	}
	if ctxMap["ip"] != "1.1.1.1" {
		t.Errorf("context.ip: expected '1.1.1.1', got %v", ctxMap["ip"])
	}
}

func TestFilter_SentAt_Injected(t *testing.T) {
	var captured map[string]interface{}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &captured)
		w.WriteHeader(200)
		w.Write([]byte(`{"policy":{"action":"allow"}}`))
	}))
	defer ts.Close()

	c, _ := NewClient(WithAPISecret("sk_test"), WithBaseURL(ts.URL))
	c.Filter(context.Background(), &FilterRequest{Type: "$login"})

	sentAt, ok := captured["sent_at"].(string)
	if !ok || sentAt == "" {
		t.Fatal("sent_at should be injected as ISO 8601 timestamp")
	}
	if len(sentAt) < 20 {
		t.Errorf("sent_at looks too short for ISO 8601: %q", sentAt)
	}
}
