package castle

import (
	"context"
	"errors"
	"net"
)

// isFailoverError returns true if the error is a transient failure that
// should trigger failover (timeout, network error, or 5xx).
func isFailoverError(err error) bool {
	if err == nil {
		return false
	}

	// Context deadline/cancel
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return true
	}

	// Network errors (dial, DNS, connection refused, etc.)
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}

	// 5xx from Castle API
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode >= 500 {
		return true
	}

	return false
}

// failoverReason returns a string describing why failover was triggered.
func failoverReason(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode >= 500 {
		return "server_error"
	}
	return "request_error"
}

func failoverFilterResponse(strategy FailoverStrategy, reason string) *FilterResponse {
	return &FilterResponse{
		Policy:         Policy{Action: Action(strategy)},
		Failover:       true,
		FailoverReason: reason,
	}
}

func failoverRiskResponse(strategy FailoverStrategy, reason string) *RiskResponse {
	return &RiskResponse{
		Policy:         Policy{Action: Action(strategy)},
		Failover:       true,
		FailoverReason: reason,
	}
}
