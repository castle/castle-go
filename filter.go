package castle

import (
	"context"
	"net/http"
)

// FilterRequest is the request body for POST /v1/filter.
// Used for pre-authentication risk assessment.
type FilterRequest struct {
	Type                       string                `json:"type,omitempty"`
	Event                      string                `json:"event,omitempty"`
	Status                     string                `json:"status,omitempty"`
	RequestToken               string                `json:"request_token,omitempty"`
	Context                    *Context              `json:"context,omitempty"`
	User                       *User                 `json:"user,omitempty"`
	MatchingUserID             string                `json:"matching_user_id,omitempty"`
	Params                     *UserParams           `json:"params,omitempty"`
	Properties                 map[string]interface{} `json:"properties,omitempty"`
	Product                    *Product              `json:"product,omitempty"`
	Session                    *Session              `json:"session,omitempty"`
	CreatedAt                  string                `json:"created_at,omitempty"`
	AuthenticationMethod       *AuthenticationMethod `json:"authentication_method,omitempty"`
	SkipRequestTokenValidation bool                  `json:"skip_request_token_validation,omitempty"`
	SkipContextValidation      bool                  `json:"skip_context_validation,omitempty"`
}

// FilterResponse is the response from POST /v1/filter.
type FilterResponse struct {
	Policy      Policy                 `json:"policy"`
	Risk        float64                `json:"risk,omitempty"`
	Scores      *RiskScores            `json:"scores,omitempty"`
	Signals     map[string]interface{} `json:"signals,omitempty"`
	Device      map[string]interface{} `json:"device,omitempty"`
	IP          map[string]interface{} `json:"ip,omitempty"`
	Type        string                 `json:"type,omitempty"`
	Status      string                 `json:"status,omitempty"`
	Name        string                 `json:"name,omitempty"`
	ID          string                 `json:"id,omitempty"`
	CreatedAt   string                 `json:"created_at,omitempty"`
	DeviceToken string                 `json:"device_token,omitempty"`

	Failover       bool   `json:"failover,omitempty"`
	FailoverReason string `json:"failover_reason,omitempty"`
}

// Filter calls POST /v1/filter for pre-authentication risk assessment.
//
// On timeout or 5xx, returns a synthetic response based on the configured
// FailoverStrategy (default: allow) with Failover=true and err=nil.
// Only FailoverThrow returns the actual error.
func (c *Client) Filter(ctx context.Context, req *FilterRequest) (*FilterResponse, error) {
	if c.cfg.doNotTrack {
		return failoverFilterResponse(FailoverAllow, "do_not_track"), nil
	}

	var resp FilterResponse
	err := c.doJSON(ctx, http.MethodPost, "/filter", req, &resp)

	if err != nil {
		if isFailoverError(err) {
			if c.cfg.failoverStrategy == FailoverThrow {
				return nil, err
			}
			reason := failoverReason(err)
			if c.cfg.logger != nil {
				c.cfg.logger.Warnf("castle: filter failover (%s): %v", reason, err)
			}
			return failoverFilterResponse(c.cfg.failoverStrategy, reason), nil
		}
		return nil, err
	}

	return &resp, nil
}
