package castle

import (
	"context"
	"net/http"
)

// RiskRequest is the request body for POST /v1/risk.
// Used for post-authentication risk assessment. Requires User.ID.
type RiskRequest struct {
	Type                       string                `json:"type,omitempty"`
	Event                      string                `json:"event,omitempty"`
	Status                     string                `json:"status,omitempty"`
	RequestToken               string                `json:"request_token,omitempty"`
	Context                    *Context              `json:"context,omitempty"`
	User                       *User                 `json:"user,omitempty"`
	Properties                 map[string]interface{} `json:"properties,omitempty"`
	Product                    *Product              `json:"product,omitempty"`
	Session                    *Session              `json:"session,omitempty"`
	CreatedAt                  string                `json:"created_at,omitempty"`
	AuthenticationMethod       *AuthenticationMethod `json:"authentication_method,omitempty"`
	SkipRequestTokenValidation bool                  `json:"skip_request_token_validation,omitempty"`
	SkipContextValidation      bool                  `json:"skip_context_validation,omitempty"`
}

// RiskResponse is the response from POST /v1/risk.
type RiskResponse struct {
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

// Risk calls POST /v1/risk for post-authentication risk assessment.
//
// On timeout or 5xx, returns a synthetic response based on the configured
// FailoverStrategy (default: allow) with Failover=true and err=nil.
// Only FailoverThrow returns the actual error.
func (c *Client) Risk(ctx context.Context, req *RiskRequest) (*RiskResponse, error) {
	if c.cfg.doNotTrack {
		return failoverRiskResponse(FailoverAllow, "do_not_track"), nil
	}

	var resp RiskResponse
	err := c.doJSON(ctx, http.MethodPost, "/risk", req, &resp)

	if err != nil {
		if isFailoverError(err) {
			if c.cfg.failoverStrategy == FailoverThrow {
				return nil, err
			}
			reason := failoverReason(err)
			if c.cfg.logger != nil {
				c.cfg.logger.Warnf("castle: risk failover (%s): %v", reason, err)
			}
			return failoverRiskResponse(c.cfg.failoverStrategy, reason), nil
		}
		return nil, err
	}

	return &resp, nil
}
