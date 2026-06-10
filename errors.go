package castle

import "fmt"

// ConfigurationError is returned when the client is misconfigured, e.g. when the
// API secret is missing or a failover strategy is invalid.
type ConfigurationError struct {
	Message string
}

func (e *ConfigurationError) Error() string { return e.Message }

// RequestError wraps a transport-level failure (connection error, timeout, etc.)
// that occurred before a response was received from the Castle API.
type RequestError struct {
	Message string
	Err     error
}

func (e *RequestError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap exposes the underlying transport error for errors.Is / errors.As.
func (e *RequestError) Unwrap() error { return e.Err }

// WebhookVerificationError is returned when a webhook signature does not match
// the signature computed from the request body.
type WebhookVerificationError struct {
	Message string
}

func (e *WebhookVerificationError) Error() string { return e.Message }

// APIError represents a non-success HTTP response from the Castle API. Every
// status-specific error below embeds it, so callers can match either the
// concrete type (via errors.As) or APIError for the status code.
type APIError struct {
	StatusCode int
	Type       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("castle: API error (status %d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("castle: API error (status %d)", e.StatusCode)
}

// BadRequestError is returned for HTTP 400 responses.
type BadRequestError struct{ *APIError }

// UnauthorizedError is returned for HTTP 401 responses.
type UnauthorizedError struct{ *APIError }

// ForbiddenError is returned for HTTP 403 responses.
type ForbiddenError struct{ *APIError }

// NotFoundError is returned for HTTP 404 responses.
type NotFoundError struct{ *APIError }

// UserUnauthorizedError is returned for HTTP 419 responses.
type UserUnauthorizedError struct{ *APIError }

// InvalidParametersError is returned for HTTP 422 responses that are not an
// invalid request token error.
type InvalidParametersError struct{ *APIError }

// InvalidRequestTokenError is returned for HTTP 422 responses whose type is
// "invalid_request_token".
type InvalidRequestTokenError struct{ *APIError }

// RateLimitError is returned for HTTP 429 responses.
type RateLimitError struct{ *APIError }

// InternalServerError is returned for HTTP 5xx responses.
type InternalServerError struct{ *APIError }

// errorFromResponse maps an HTTP status code (and a parsed error body) to the
// matching typed error.
func errorFromResponse(status int, errType, message string) error {
	base := &APIError{StatusCode: status, Type: errType, Message: message}
	switch {
	case status == 400:
		return &BadRequestError{base}
	case status == 401:
		return &UnauthorizedError{base}
	case status == 403:
		return &ForbiddenError{base}
	case status == 404:
		return &NotFoundError{base}
	case status == 419:
		return &UserUnauthorizedError{base}
	case status == 422:
		if errType == "invalid_request_token" {
			return &InvalidRequestTokenError{base}
		}
		return &InvalidParametersError{base}
	case status == 429:
		return &RateLimitError{base}
	case status >= 500 && status <= 599:
		return &InternalServerError{base}
	default:
		return base
	}
}

// isFailoverError reports whether err should trigger the failover strategy on
// risk and filter calls (transport failures and server errors).
func isFailoverError(err error) bool {
	switch err.(type) {
	case *RequestError, *InternalServerError:
		return true
	default:
		return false
	}
}
