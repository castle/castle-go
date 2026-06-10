package castle

import "context"

const (
	pathRisk   = "risk"
	pathFilter = "filter"
	pathLog    = "log"
)

// Risk sends a risk request and returns the API verdict. When the API is
// unreachable (transport error, timeout, or 5xx) the configured failover
// strategy applies: a synthetic verdict is returned, unless the strategy is
// FailoverThrow, in which case the underlying error is returned.
func (c *Castle) Risk(ctx context.Context, params Params) (Params, error) {
	return c.track(ctx, pathRisk, params)
}

// Filter sends a filter request. It follows the same failover semantics as Risk.
func (c *Castle) Filter(ctx context.Context, params Params) (Params, error) {
	return c.track(ctx, pathFilter, params)
}

// Log sends a log request. Log does not apply failover: transport and API
// errors are returned to the caller. When tracking is disabled Log is a no-op
// and returns a nil response and nil error.
func (c *Castle) Log(ctx context.Context, params Params) (Params, error) {
	if c.config.doNotTrack {
		return nil, nil
	}
	payload := withSentAt(params)
	return c.request(ctx, "POST", pathLog, payload)
}

func (c *Castle) track(ctx context.Context, path string, params Params) (Params, error) {
	if c.config.doNotTrack {
		return failoverResponse(failoverUserID(params), c.config.failoverStrategy, "Castle set to do not track."), nil
	}

	payload := withSentAt(params)
	res, err := c.request(ctx, "POST", path, payload)
	if err != nil {
		if isFailoverError(err) && c.config.failoverStrategy != FailoverThrow {
			reason := err.Error()
			return failoverResponse(failoverUserID(params), c.config.failoverStrategy, reason), nil
		}
		return nil, err
	}

	res["failover"] = false
	res["failover_reason"] = nil
	return res, nil
}

// withSentAt returns a shallow copy of params with sent_at populated if absent.
func withSentAt(params Params) Params {
	payload := make(Params, len(params)+1)
	for k, v := range params {
		payload[k] = v
	}
	if _, ok := payload["sent_at"]; !ok {
		payload["sent_at"] = generateTimestamp()
	}
	return payload
}
