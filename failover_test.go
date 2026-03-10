package castle

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestIsFailoverError_Timeout(t *testing.T) {
	if !isFailoverError(context.DeadlineExceeded) {
		t.Error("DeadlineExceeded should trigger failover")
	}
}

func TestIsFailoverError_Canceled(t *testing.T) {
	if !isFailoverError(context.Canceled) {
		t.Error("Canceled should trigger failover")
	}
}

func TestIsFailoverError_NetError(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	if !isFailoverError(err) {
		t.Error("net.OpError should trigger failover")
	}
}

func TestIsFailoverError_5xx(t *testing.T) {
	err := &APIError{StatusCode: 502, sentinel: ErrInternalServer}
	if !isFailoverError(err) {
		t.Error("502 APIError should trigger failover")
	}
}

func TestIsFailoverError_4xx_NoFailover(t *testing.T) {
	err := &APIError{StatusCode: 422, sentinel: ErrInvalidParameters}
	if isFailoverError(err) {
		t.Error("422 should NOT trigger failover")
	}
}

func TestIsFailoverError_Nil(t *testing.T) {
	if isFailoverError(nil) {
		t.Error("nil should not trigger failover")
	}
}

func TestIsFailoverError_GenericError_NoFailover(t *testing.T) {
	if isFailoverError(errors.New("some random error")) {
		t.Error("generic error should not trigger failover")
	}
}

func TestFailoverReason_Timeout(t *testing.T) {
	if r := failoverReason(context.DeadlineExceeded); r != "timeout" {
		t.Errorf("expected 'timeout', got %q", r)
	}
}

func TestFailoverReason_Canceled(t *testing.T) {
	if r := failoverReason(context.Canceled); r != "canceled" {
		t.Errorf("expected 'canceled', got %q", r)
	}
}

func TestFailoverReason_ServerError(t *testing.T) {
	err := &APIError{StatusCode: 500, sentinel: ErrInternalServer}
	if r := failoverReason(err); r != "server_error" {
		t.Errorf("expected 'server_error', got %q", r)
	}
}

func TestFailoverFilterResponse(t *testing.T) {
	resp := failoverFilterResponse(FailoverAllow, "timeout")
	if resp.Policy.Action != ActionAllow {
		t.Errorf("expected allow, got %v", resp.Policy.Action)
	}
	if !resp.Failover {
		t.Error("expected Failover=true")
	}
	if resp.FailoverReason != "timeout" {
		t.Errorf("expected reason 'timeout', got %q", resp.FailoverReason)
	}
}

func TestFailoverFilterResponse_Deny(t *testing.T) {
	resp := failoverFilterResponse(FailoverDeny, "server_error")
	if resp.Policy.Action != ActionDeny {
		t.Errorf("expected deny, got %v", resp.Policy.Action)
	}
}

func TestFailoverRiskResponse(t *testing.T) {
	resp := failoverRiskResponse(FailoverChallenge, "timeout")
	if resp.Policy.Action != ActionChallenge {
		t.Errorf("expected challenge, got %v", resp.Policy.Action)
	}
	if !resp.Failover {
		t.Error("expected Failover=true")
	}
}
