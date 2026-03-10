package castle

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Sentinel errors for well-known HTTP status codes.
// Use errors.Is to check: if errors.Is(err, ErrUnauthorized) { ... }
var (
	ErrBadRequest           = errors.New("castle: bad request")
	ErrUnauthorized         = errors.New("castle: unauthorized")
	ErrForbidden            = errors.New("castle: forbidden")
	ErrNotFound             = errors.New("castle: not found")
	ErrUserUnauthorized     = errors.New("castle: user unauthorized")
	ErrInvalidParameters    = errors.New("castle: invalid parameters")
	ErrInvalidRequestToken  = errors.New("castle: invalid request token")
	ErrRateLimit            = errors.New("castle: rate limited")
	ErrInternalServer       = errors.New("castle: internal server error")
)

// APIError is returned for non-2xx responses from the Castle API.
// Use errors.As to extract: var apiErr *castle.APIError
type APIError struct {
	// HTTP status code
	StatusCode int `json:"-"`
	// Castle error type from response body (e.g. "invalid_request_token")
	Type string `json:"type,omitempty"`
	// Human-readable message from response body
	Message string `json:"message,omitempty"`
	// Underlying sentinel error for errors.Is matching
	sentinel error
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("castle: HTTP %d: %s", e.StatusCode, e.Message)
	}
	if e.Type != "" {
		return fmt.Sprintf("castle: HTTP %d: %s", e.StatusCode, e.Type)
	}
	return fmt.Sprintf("castle: HTTP %d", e.StatusCode)
}

func (e *APIError) Unwrap() error {
	return e.sentinel
}

// statusSentinel maps HTTP status codes to sentinel errors.
var statusSentinel = map[int]error{
	400: ErrBadRequest,
	401: ErrUnauthorized,
	403: ErrForbidden,
	404: ErrNotFound,
	419: ErrUserUnauthorized,
	429: ErrRateLimit,
}

// mapResponseError creates an *APIError from HTTP status and body.
func mapResponseError(status int, body []byte) *APIError {
	apiErr := &APIError{StatusCode: status}

	if len(body) > 0 {
		json.Unmarshal(body, apiErr)
	}

	if status == 422 {
		if apiErr.Type == "invalid_request_token" {
			apiErr.sentinel = ErrInvalidRequestToken
		} else {
			apiErr.sentinel = ErrInvalidParameters
		}
		return apiErr
	}

	if status >= 500 {
		apiErr.sentinel = ErrInternalServer
		return apiErr
	}

	if s, ok := statusSentinel[status]; ok {
		apiErr.sentinel = s
	}

	return apiErr
}
