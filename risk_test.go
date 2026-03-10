package castle

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRisk_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		w.Write([]byte(`{
			"policy": {"id":"p1","revision_id":"r1","name":"Auth policy","action":"deny"},
			"risk": 0.95,
			"scores": {"account_takeover": {"score": 0.95}}
		}`))
	}))
	defer ts.Close()

	c, _ := NewClient(WithAPISecret("sk_test"), WithBaseURL(ts.URL))

	resp, err := c.Risk(context.Background(), &RiskRequest{
		Type:         "$login",
		Status:       "$succeeded",
		RequestToken: "token",
		User:         &User{ID: "user-123"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Policy.Action != ActionDeny {
		t.Errorf("expected deny, got %v", resp.Policy.Action)
	}
	if resp.Scores == nil || resp.Scores.AccountTakeover == nil {
		t.Fatal("expected scores.account_takeover")
	}
	if resp.Scores.AccountTakeover.Score != 0.95 {
		t.Errorf("expected score 0.95, got %v", resp.Scores.AccountTakeover.Score)
	}
}

func TestRisk_Failover_Timeout(t *testing.T) {
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

	resp, err := c.Risk(ctx, &RiskRequest{Type: "$login", User: &User{ID: "u1"}})
	if err != nil {
		t.Fatalf("failover should not return error: %v", err)
	}
	if !resp.Failover {
		t.Error("expected Failover=true")
	}
	if resp.Policy.Action != ActionAllow {
		t.Errorf("expected allow failover, got %v", resp.Policy.Action)
	}
}

func TestRisk_Failover_ThrowStrategy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer ts.Close()

	c, _ := NewClient(
		WithAPISecret("sk_test"),
		WithBaseURL(ts.URL),
		WithFailoverStrategy(FailoverThrow),
	)

	_, err := c.Risk(context.Background(), &RiskRequest{Type: "$login", User: &User{ID: "u1"}})
	if err == nil {
		t.Fatal("FailoverThrow should return error")
	}
	if !errors.Is(err, ErrInternalServer) {
		t.Errorf("expected ErrInternalServer, got %v", err)
	}
}

func TestRisk_DoNotTrack(t *testing.T) {
	c, _ := NewClient(WithAPISecret("sk_test"), WithDoNotTrack(true))

	resp, err := c.Risk(context.Background(), &RiskRequest{Type: "$login", User: &User{ID: "u1"}})
	if err != nil {
		t.Fatalf("doNotTrack should not error: %v", err)
	}
	if !resp.Failover {
		t.Error("expected Failover=true")
	}
	if resp.FailoverReason != "do_not_track" {
		t.Errorf("expected 'do_not_track', got %q", resp.FailoverReason)
	}
}

func TestRisk_DoNotTrack_AlwaysAllow(t *testing.T) {
	c, _ := NewClient(
		WithAPISecret("sk_test"),
		WithDoNotTrack(true),
		WithFailoverStrategy(FailoverDeny),
	)

	resp, err := c.Risk(context.Background(), &RiskRequest{Type: "$login", User: &User{ID: "u1"}})
	if err != nil {
		t.Fatalf("doNotTrack should not error: %v", err)
	}
	if resp.Policy.Action != ActionAllow {
		t.Errorf("doNotTrack should always use allow regardless of configured strategy, got %v", resp.Policy.Action)
	}
}
