package castle

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/pkg/errors"
	"github.com/tomasen/realip"
)

// TrackEndpoint defines the tracking URL castle.io side
var TrackEndpoint = "https://api.castle.io/v1/track"

// AuthenticateEndpoint defines the adaptive authentication URL castle.io side
var AuthenticateEndpoint = "https://api.castle.io/v1/authenticate"

// Event is an enum defining types of event castle tracks
type Event string

// See https://castle.io/docs/events
const (
	EventLoginSucceeded                Event = "$login.succeeded"
	EventLoginFailed                   Event = "$login.failed"
	EventPasswordResetRequestSucceeded Event = "$password_reset_request.succeeded"
	EventPasswordResetRequestFailed    Event = "$password_reset_request.failed"
	EventPasswordResetSucceeded        Event = "$password_reset.succeeded"
	EventPasswordResetFailed           Event = "$password_reset.failed"
	EventIncidentMitigated             Event = "$incident.mitigated"
	EventReviewResolved                Event = "$review.resolved"
	EventReviewEscalated               Event = "$review.escalated"
	EventChallengeRequested            Event = "$challenge.requested"
	EventChallengeSucceeded            Event = "$challenge.succeeded"
	EventChallengeFailed               Event = "$challenge.failed"
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
	ClientID string            `json:"client_id"`
	IP       string            `json:"ip"`
	Headers  map[string]string `json:"headers"`
}

func getClientID(r *http.Request) string {

	var clientID string

	// ClientID is __cid cookie or X-Castle-Client-Id header
	cidCookie, _ := r.Cookie("__cid")

	if cidCookie != nil {
		clientID = cidCookie.Value
	}

	cidHeader := r.Header.Get("X-Castle-Client-Id")

	if cidHeader != "" {
		clientID = cidHeader
	}

	return clientID
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

	return &Context{ClientID: getClientID(r), IP: realip.FromRequest(r), Headers: headers}
}

type castleAPIRequest struct {
	Event      Event             `json:"event"`
	UserID     string            `json:"user_id"`
	Context    *Context          `json:"context"`
	Properties map[string]string `json:"properties"`
	UserTraits map[string]string `json:"user_traits"`
}

type castleAPIResponse struct {
	Error       string `json:"error"`
	Type        string `json:"type"`
	Message     string `json:"message"`
	Action      string `json:"action"`
	UserID      string `json:"user_id"`
	DeviceToken string `json:"device_token"`
}

// Track sends a tracking request to castle.io
// see https://castle.io/docs/events for details
func (c *Castle) Track(event Event, userID string, properties map[string]string, userTraits map[string]string, context *Context) error {
	e := &castleAPIRequest{Event: event, UserID: userID, Context: context, Properties: properties, UserTraits: userTraits}
	return c.SendTrackCall(e)
}

// TrackSimple allows simple tracking of events into castle without specifying traits or properties
func (c *Castle) TrackSimple(event Event, userID string, context *Context) error {
	EmptyMap := make(map[string]string)
	e := &castleAPIRequest{Event: event, UserID: userID, Context: context, Properties: EmptyMap, UserTraits: EmptyMap}
	return c.SendTrackCall(e)
}

// SendTrackCall is a plumbing method constructing the HTTP req/res and interpreting results
func (c *Castle) SendTrackCall(e *castleAPIRequest) error {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(e)

	req, err := http.NewRequest(http.MethodPost, TrackEndpoint, b)

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

	if resp.Error != "" {
		// we have an api error
		return errors.New(resp.Error)
	}

	json.NewDecoder(res.Body).Decode(resp)

	return err
}

// Authenticate sends an authentication request to castle.io
// see https://castle.io/docs/authentication for details
func (c *Castle) Authenticate(event Event, userID string, properties map[string]string, userTraits map[string]string, context *Context) (AuthenticationRecommendedAction, error) {
	e := &castleAPIRequest{Event: event, UserID: userID, Context: context, Properties: properties, UserTraits: userTraits}
	return c.SendAuthenticateCall(e)
}

// AuthenticateSimple allows authenticate call into castle without specifying traits or properties
func (c *Castle) AuthenticateSimple(event Event, userID string, context *Context) (AuthenticationRecommendedAction, error) {
	EmptyMap := make(map[string]string)
	e := &castleAPIRequest{Event: event, UserID: userID, Context: context, Properties: EmptyMap, UserTraits: EmptyMap}
	return c.SendAuthenticateCall(e)
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

// SendAuthenticateCall is a plumbing method constructing the HTTP req/res and interpreting results
func (c *Castle) SendAuthenticateCall(e *castleAPIRequest) (AuthenticationRecommendedAction, error) {
	b := new(bytes.Buffer)
	json.NewEncoder(b).Encode(e)

	req, err := http.NewRequest(http.MethodPost, AuthenticateEndpoint, b)

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
		return RecommendedActionNone, errors.Errorf("expected 201 status but go %s", res.Status)
	}

	resp := &castleAPIResponse{}

	json.NewDecoder(res.Body).Decode(resp)

	if resp.Error != "" {
		//we have an api error
		return RecommendedActionNone, errors.New(resp.Error)
	}

	if resp.Type != "" {
		//we have an api error
		return RecommendedActionNone, errors.Errorf("%s: %s", resp.Type, resp.Message)
	}

	return authenticationRecommendedActionFromString(resp.Action), err
}

// WebhookBody encapsulates body of webhook notificationc coming from castle.io
// see https://castle.io/docs/webhooks
type WebhookBody struct {
}
