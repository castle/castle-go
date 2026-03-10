// Package castle provides a Go SDK for the Castle (https://castle.io) API.
//
// Castle detects account takeover, bot activity, and account abuse by
// analyzing signals from your application's HTTP requests. This SDK handles
// context extraction from *http.Request (IP, headers, client ID), failover
// on timeout/error, and typed API responses.
//
// Quick start:
//
//	client, err := castle.NewClient(castle.WithAPISecret("sk_..."))
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	ctx := client.ContextFromRequest(r)
//	resp, err := client.Filter(r.Context(), &castle.FilterRequest{
//	    Type:         "$login",
//	    Status:       "$attempted",
//	    RequestToken: token,
//	    Context:      ctx,
//	    User:         &castle.User{Email: email},
//	})
package castle

const Version = "1.0.0"

const defaultBaseURL = "https://api.castle.io/v1"

// Action represents a Castle policy decision.
type Action string

const (
	ActionAllow     Action = "allow"
	ActionDeny      Action = "deny"
	ActionChallenge Action = "challenge"
)

// FailoverStrategy determines what the SDK returns when the Castle API
// is unreachable (timeout, network error, or 5xx).
type FailoverStrategy string

const (
	FailoverAllow     FailoverStrategy = "allow"
	FailoverDeny      FailoverStrategy = "deny"
	FailoverChallenge FailoverStrategy = "challenge"
	FailoverThrow     FailoverStrategy = "throw"
)

// User represents user information sent with Castle API requests.
type User struct {
	ID           string                 `json:"id,omitempty"`
	Email        string                 `json:"email,omitempty"`
	Phone        string                 `json:"phone,omitempty"`
	Name         string                 `json:"name,omitempty"`
	RegisteredAt string                 `json:"registered_at,omitempty"`
	Traits       map[string]interface{} `json:"traits,omitempty"`
	Address      *Address               `json:"address,omitempty"`
}

// Address represents a physical address associated with a user.
type Address struct {
	CountryCode string `json:"country_code"`
	Line1       string `json:"line1,omitempty"`
	Line2       string `json:"line2,omitempty"`
	City        string `json:"city,omitempty"`
	PostalCode  string `json:"postal_code,omitempty"`
	RegionCode  string `json:"region_code,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// UserParams holds the params.email/phone/username fields on filter requests
// for pre-authentication matching.
type UserParams struct {
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Username string `json:"username,omitempty"`
}

// Product identifies the product context for multi-product setups.
type Product struct {
	ID string `json:"id"`
}

// Session represents a session context.
type Session struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at,omitempty"`
}

// AuthenticationMethod describes how the user authenticated.
type AuthenticationMethod struct {
	Type    string `json:"type"`
	Variant string `json:"variant,omitempty"`
	Email   string `json:"email,omitempty"`
	Phone   string `json:"phone,omitempty"`
}

// Policy is returned by Filter and Risk calls with the action decision.
type Policy struct {
	ID         string          `json:"id"`
	RevisionID string          `json:"revision_id"`
	Name       string          `json:"name"`
	Action     Action          `json:"action"`
	Response   *PolicyResponse `json:"response,omitempty"`
}

// PolicyResponse contains the custom response configured on a policy,
// allowing policies to specify exact HTTP responses to return.
type PolicyResponse struct {
	StatusCode int               `json:"status_code,omitempty"`
	Body       string            `json:"body,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// RiskScore holds a single risk score value.
type RiskScore struct {
	Score float64 `json:"score"`
}

// RiskScores contains the breakdown of risk scores by category.
type RiskScores struct {
	AccountAbuse    *RiskScore `json:"account_abuse,omitempty"`
	AccountTakeover *RiskScore `json:"account_takeover,omitempty"`
	Bot             *RiskScore `json:"bot,omitempty"`
}
