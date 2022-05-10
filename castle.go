package castle

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
	"github.com/tomasen/realip"
)

// FilterEndpoint defines the filter URL castle.io side
var FilterEndpoint = "https://api.castle.io/v1/filter"

// RiskEndpoint defines the risk URL castle.io side
var RiskEndpoint = "https://api.castle.io/v1/risk"

// EventType is an enum defining types of event castle tracks
type EventType string

// See https://docs.castle.io/docs/events
const (
	EventTypeLogin                EventType = "$login"
	EventTypeRegistration         EventType = "$registration"
	EventTypeProfileUpdate        EventType = "$profile_update"
	EventTypeProfileReset         EventType = "$profile_reset"
	EventTypePasswordResetRequest EventType = "$password_reset_request"
	EventTypeChallenge            EventType = "$challenge"
)

// Status is an enum defining the statuses for a given event.
type Status string

// See https://docs.castle.io/docs/events
const (
	StatusAttempted Status = "$attempted"
	StatusSucceeded Status = "$succeeded"
	StatusFailed    Status = "$failed"
)

// AuthenticationRecommendedAction encapsulates the 3 possible responses from auth call (allow, challenge, deny)
type AuthenticationRecommendedAction string

// See https://castle.io/docs/authentication
const (
	RecommendedActionNone      AuthenticationRecommendedAction = ""
	RecommendedActionAllow     AuthenticationRecommendedAction = "allow"
	RecommendedActionChallenge AuthenticationRecommendedAction = "challenge"
	RecommendedActionDeny      AuthenticationRecommendedAction = "deny"
)

// New creates a new castle client
func New(secret string) (*Castle, error) {
	client := &http.Client{}

	return NewWithHTTPClient(secret, client)
}

// HeaderAllowList keeps a list of headers that will be forwarded to castle
var HeaderAllowList = []string{
	"Accept",
	"Accept-Charset",
	"Accept-Datetime",
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Connection",
	"Content-Length",
	"Content-Type",
	"Dnt",
	"Host",
	"Origin",
	"Pragma",
	"Referer",
	"Sec-Fetch-Dest",
	"Sec-Fetch-Mode",
	"Sec-Fetch-Site",
	"Sec-Fetch-User",
	"Te",
	"Upgrade-Insecure-Requests",
	"User-Agent",
	"X-Castle-Client-Id",
}

// NewWithHTTPClient same as New but allows passing of http.Client with custom config
func NewWithHTTPClient(secret string, client *http.Client) (*Castle, error) {
	return &Castle{client: client, apiSecret: secret}, nil
}

// Castle encapsulates http client
type Castle struct {
	client    *http.Client
	apiSecret string
}

// Context captures data from HTTP request
type Context struct {
	IP      string            `json:"ip"`
	Headers map[string]string `json:"headers"`
}

func isHeaderAllowed(header string) bool {
	for _, allowedHeader := range HeaderAllowList {
		if header == http.CanonicalHeaderKey(allowedHeader) {
			return true
		}
	}
	return false
}

// ContextFromRequest builds castle context from current http.Request
func ContextFromRequest(r *http.Request) *Context {
	headers := make(map[string]string)

	for requestHeader := range r.Header {
		if isHeaderAllowed(requestHeader) {
			headers[requestHeader] = r.Header.Get(requestHeader)
		}
	}

	return &Context{IP: realip.FromRequest(r), Headers: headers}
}

type User struct {
	Id           string            `json:"id"`
	Email        string            `json:"email"`
	Phone        string            `json:"phone"`
	Name         string            `json:"name"`
	RegisteredAt string            `json:"registered_at"`
	Traits       map[string]string `json:"traits"`
}

type castleAPIRequest struct {
	Type         EventType         `json:"type"`
	Status       Status            `json:"status"`
	RequestToken string            `json:"request_token"`
	User         User              `json:"user"`
	Context      *Context          `json:"context"`
	Properties   map[string]string `json:"properties"`
}

type castleAPIResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Risk    string `json:"risk"`
	Policy  struct {
		Name       string `json:"name"`
		Id         string `json:"id"`
		RevisionId string `json:"revision_id"`
		Action     string `json:"action"`
	} `json:"policy"`
	Device struct {
		Token string `json:"token"`
	} `json:"device"`
}

// Filter sends a filter request to castle.io
// see https://reference.castle.io/#operation/filter for details
func (c *Castle) Filter(eventType EventType, eventStatus Status, user User, requestToken string, properties map[string]string, context *Context) error {
	e := &castleAPIRequest{Type: eventType, User: user, Context: context, Properties: properties}
	return c.SendFilterCall(e)
}

// SendFilterCall is a plumbing method constructing the HTTP req/res and interpreting results
func (c *Castle) SendFilterCall(e *castleAPIRequest) error {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(e)

	req, err := http.NewRequest(http.MethodPost, FilterEndpoint, b)
	if err != nil {
		return err
	}

	req.SetBasicAuth("", c.apiSecret)
	req.Header.Set("content-type", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if expected, got := http.StatusNoContent, res.StatusCode; expected != got {
		return errors.Errorf("expected %d status but got %d", expected, got)
	}

	resp := &castleAPIResponse{}

	if resp.Type != "" {
		// we have an api error
		return errors.New(resp.Type)
	}

	if resp.Message != "" {
		// we have an api error
		return errors.Errorf("%s: %s", resp.Type, resp.Message)
	}

	return json.NewDecoder(res.Body).Decode(resp)
}

// Risk sends a risk request to castle.io
// see https://reference.castle.io/#operation/risk for details
func (c *Castle) Risk(eventType EventType, eventStatus Status, user User, requestToken string, properties map[string]string, context *Context) (AuthenticationRecommendedAction, error) {
	e := &castleAPIRequest{Type: eventType, Status: eventStatus, User: user, RequestToken: requestToken, Context: context, Properties: properties}
	return c.SendRiskCall(e)
}

func authenticationRecommendedActionFromString(action string) AuthenticationRecommendedAction {
	switch action {
	case "allow":
		return RecommendedActionAllow
	case "deny":
		return RecommendedActionDeny
	case "challenge":
		return RecommendedActionChallenge
	default:
		return RecommendedActionNone
	}
}

// SendRiskCall is a plumbing method constructing the HTTP req/res and interpreting results
func (c *Castle) SendRiskCall(e *castleAPIRequest) (AuthenticationRecommendedAction, error) {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(e)

	req, err := http.NewRequest(http.MethodPost, RiskEndpoint, b)
	if err != nil {
		return RecommendedActionNone, err
	}

	req.SetBasicAuth("", c.apiSecret)
	req.Header.Set("content-type", "application/json")

	res, err := c.client.Do(req)
	if err != nil {
		return RecommendedActionNone, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		return RecommendedActionNone, errors.Errorf("expected 201 status but got %s", res.Status)
	}

	resp := &castleAPIResponse{}

	json.NewDecoder(res.Body).Decode(resp)

	if resp.Type != "" {
		// we have an api error
		return RecommendedActionNone, errors.New(resp.Type)
	}

	if resp.Message != "" {
		// we have an api error
		return RecommendedActionNone, errors.Errorf("%s: %s", resp.Type, resp.Message)
	}

	return authenticationRecommendedActionFromString(resp.Policy.Action), err
}

// WebhookBody encapsulates body of webhook notificationc coming from castle.io
// see https://castle.io/docs/webhooks
type WebhookBody struct{}
