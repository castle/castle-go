package castle

// Verdict is a recommended action returned by the Castle API (or produced by a
// failover strategy) for risk and filter requests.
type Verdict string

const (
	// VerdictAllow allows the request to proceed.
	VerdictAllow Verdict = "allow"
	// VerdictChallenge asks the user for an additional verification step.
	VerdictChallenge Verdict = "challenge"
	// VerdictDeny blocks the request.
	VerdictDeny Verdict = "deny"
)

// FailoverStrategy controls what a risk or filter call returns when the Castle
// API is unreachable, times out, or responds with a server error.
type FailoverStrategy string

const (
	// FailoverAllow returns an "allow" verdict on failure.
	FailoverAllow FailoverStrategy = "allow"
	// FailoverChallenge returns a "challenge" verdict on failure.
	FailoverChallenge FailoverStrategy = "challenge"
	// FailoverDeny returns a "deny" verdict on failure.
	FailoverDeny FailoverStrategy = "deny"
	// FailoverThrow re-raises the underlying error instead of returning a verdict.
	FailoverThrow FailoverStrategy = "throw"
)

func (s FailoverStrategy) valid() bool {
	switch s {
	case FailoverAllow, FailoverChallenge, FailoverDeny, FailoverThrow:
		return true
	default:
		return false
	}
}
