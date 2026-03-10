package castle

import (
	"errors"
	"testing"
)

func TestMapResponseError_400(t *testing.T) {
	err := mapResponseError(400, []byte(`{"message":"bad request"}`))
	if !errors.Is(err, ErrBadRequest) {
		t.Errorf("expected ErrBadRequest, got %v", err)
	}
	if err.StatusCode != 400 {
		t.Errorf("expected status 400, got %d", err.StatusCode)
	}
	if err.Message != "bad request" {
		t.Errorf("expected message 'bad request', got %q", err.Message)
	}
}

func TestMapResponseError_401(t *testing.T) {
	err := mapResponseError(401, nil)
	if !errors.Is(err, ErrUnauthorized) {
		t.Errorf("expected ErrUnauthorized, got %v", err)
	}
}

func TestMapResponseError_403(t *testing.T) {
	err := mapResponseError(403, nil)
	if !errors.Is(err, ErrForbidden) {
		t.Errorf("expected ErrForbidden, got %v", err)
	}
}

func TestMapResponseError_404(t *testing.T) {
	err := mapResponseError(404, nil)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMapResponseError_419(t *testing.T) {
	err := mapResponseError(419, nil)
	if !errors.Is(err, ErrUserUnauthorized) {
		t.Errorf("expected ErrUserUnauthorized, got %v", err)
	}
}

func TestMapResponseError_422_InvalidParams(t *testing.T) {
	err := mapResponseError(422, []byte(`{"type":"invalid_parameter","message":"missing user"}`))
	if !errors.Is(err, ErrInvalidParameters) {
		t.Errorf("expected ErrInvalidParameters, got %v", err)
	}
	if err.Message != "missing user" {
		t.Errorf("expected message 'missing user', got %q", err.Message)
	}
}

func TestMapResponseError_422_InvalidRequestToken(t *testing.T) {
	err := mapResponseError(422, []byte(`{"type":"invalid_request_token","message":"token expired"}`))
	if !errors.Is(err, ErrInvalidRequestToken) {
		t.Errorf("expected ErrInvalidRequestToken, got %v", err)
	}
}

func TestMapResponseError_429(t *testing.T) {
	err := mapResponseError(429, nil)
	if !errors.Is(err, ErrRateLimit) {
		t.Errorf("expected ErrRateLimit, got %v", err)
	}
}

func TestMapResponseError_500(t *testing.T) {
	err := mapResponseError(500, nil)
	if !errors.Is(err, ErrInternalServer) {
		t.Errorf("expected ErrInternalServer, got %v", err)
	}
}

func TestMapResponseError_502(t *testing.T) {
	err := mapResponseError(502, nil)
	if !errors.Is(err, ErrInternalServer) {
		t.Errorf("expected ErrInternalServer for 502, got %v", err)
	}
}

func TestAPIError_ErrorString(t *testing.T) {
	err := &APIError{StatusCode: 401, Message: "invalid key"}
	expected := "castle: HTTP 401: invalid key"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestAPIError_ErrorsAs(t *testing.T) {
	raw := mapResponseError(401, []byte(`{"message":"unauthorized"}`))
	var asErr error = raw

	var apiErr *APIError
	if !errors.As(asErr, &apiErr) {
		t.Fatal("errors.As should match *APIError")
	}
	if apiErr.StatusCode != 401 {
		t.Errorf("expected 401, got %d", apiErr.StatusCode)
	}
}

func TestAPIError_ErrorsIs(t *testing.T) {
	raw := mapResponseError(401, nil)
	var asErr error = raw

	if !errors.Is(asErr, ErrUnauthorized) {
		t.Error("errors.Is should match ErrUnauthorized via Unwrap")
	}
}
