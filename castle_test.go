package castle_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/castle/castle-go"
	"github.com/stretchr/testify/assert"
)

func configureRequest() *http.Request {
	req := httptest.NewRequest("GET", "/", nil)

	req.Header.Set("HTTP_X_CASTLE_CLIENT_ID", "__cid_header")
	req.Header.Set("X-FORWARDED-FOR", "6.6.6.6, 3.3.3.3, 8.8.8.8")
	req.Header.Set("USER-AGENT", "some-agent")

	return req
}

func TestCastle_SendTrackCall(t *testing.T) {
	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"error": "this is an error"}`))
	}))

	castle.TrackEndpoint = ts.URL

	err := cstl.Track(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.Error(t, err)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(400)
	}))

	castle.TrackEndpoint = ts.URL

	err = cstl.Track(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.Error(t, err)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(204)
	}))

	castle.TrackEndpoint = ts.URL

	err = cstl.Track(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.NoError(t, err)
}

func TestCastle_Track(t *testing.T) {

	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	var executed = false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type castleTrackRequest struct {
			Event      castle.Event      `json:"event"`
			UserID     string            `json:"user_id"`
			Context    *castle.Context   `json:"context"`
			Properties map[string]string `json:"properties"`
			UserTraits map[string]string `json:"user_traits"`
		}

		reqData := &castleTrackRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castle.EventLoginSucceeded, reqData.Event)
		assert.Equal(t, "user-id", reqData.UserID)
		assert.Equal(t, map[string]string{"prop1": "propValue1"}, reqData.Properties)
		assert.Equal(t, map[string]string{"trait1": "traitValue1"}, reqData.UserTraits)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.TrackEndpoint = ts.URL

	cstl.Track(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.True(t, executed)

}

func TestCastle_TrackSimple(t *testing.T) {
	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	var executed = false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type castleTrackRequest struct {
			Event   castle.Event    `json:"event"`
			UserID  string          `json:"user_id"`
			Context *castle.Context `json:"context"`
		}

		reqData := &castleTrackRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castle.EventLoginSucceeded, reqData.Event)
		assert.Equal(t, "user-id", reqData.UserID)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.TrackEndpoint = ts.URL

	cstl.TrackSimple(
		castle.EventLoginSucceeded,
		"user-id",
		castle.ContextFromRequest(req),
	)

	assert.True(t, executed)
}

func TestContextFromRequest(t *testing.T) {

	// grabs ClientID form cookie
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{
		Name:  "__cid",
		Value: "__cid_value",
	})

	ctx := castle.ContextFromRequest(req)
	assert.Equal(t, "__cid_value", ctx.ClientID)

	// prefers header to cookie
	req.Header.Set("HTTP_X_CASTLE_CLIENT_ID", "__cid_header")

	ctx = castle.ContextFromRequest(req)
	assert.Equal(t, "__cid_header", ctx.ClientID)

	// grabs IP from request
	req.Header.Set("X-REAL-IP", "9.9.9.9")
	ctx = castle.ContextFromRequest(req)
	assert.Equal(t, "9.9.9.9", ctx.IP)

	// but prefers X-FORWARDED-FOR
	req.Header.Set("X-FORWARDED-FOR", "6.6.6.6, 3.3.3.3, 8.8.8.8")
	ctx = castle.ContextFromRequest(req)
	assert.Equal(t, "6.6.6.6", ctx.IP)

	// grabs whitelisted headers only

	for _, whitelistedHeader := range castle.HeaderAllowList {
		req.Header.Set(whitelistedHeader, whitelistedHeader)
	}

	ctx = castle.ContextFromRequest(req)
	for _, whitelistedHeader := range castle.HeaderAllowList {
		assert.Contains(t, ctx.Headers, http.CanonicalHeaderKey(whitelistedHeader))
	}

	assert.NotContains(t, ctx.Headers, "Cookie")

}

func TestCastle_Authenticate(t *testing.T) {

	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	var executed = false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type castleAuthenticateRequest struct {
			Event      castle.Event      `json:"event"`
			UserID     string            `json:"user_id"`
			Context    *castle.Context   `json:"context"`
			Properties map[string]string `json:"properties"`
			UserTraits map[string]string `json:"user_traits"`
		}

		reqData := &castleAuthenticateRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castle.EventLoginSucceeded, reqData.Event)
		assert.Equal(t, "user-id", reqData.UserID)
		assert.Equal(t, map[string]string{"prop1": "propValue1"}, reqData.Properties)
		assert.Equal(t, map[string]string{"trait1": "traitValue1"}, reqData.UserTraits)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.AuthenticateEndpoint = ts.URL

	cstl.Authenticate(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.True(t, executed)

}

func TestCastle_AuthenticateSimple(t *testing.T) {

	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	var executed = false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		type castleAuthenticateRequest struct {
			Event   castle.Event    `json:"event"`
			UserID  string          `json:"user_id"`
			Context *castle.Context `json:"context"`
		}

		reqData := &castleAuthenticateRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castle.EventLoginSucceeded, reqData.Event)
		assert.Equal(t, "user-id", reqData.UserID)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.AuthenticateEndpoint = ts.URL

	cstl.AuthenticateSimple(
		castle.EventLoginSucceeded,
		"user-id",
		castle.ContextFromRequest(req),
	)

	assert.True(t, executed)

}

func TestCastle_SendAuthenticateCall(t *testing.T) {
	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"error": "this is an error"}`))
	}))

	castle.AuthenticateEndpoint = ts.URL

	res, err := cstl.Authenticate(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(400)
	}))

	castle.AuthenticateEndpoint = ts.URL

	res, err = cstl.Authenticate(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"type": "invalid_parameter", "message": "error message"}`))
	}))

	castle.AuthenticateEndpoint = ts.URL

	res, err = cstl.Authenticate(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"action": "allow"}`))
	}))

	castle.AuthenticateEndpoint = ts.URL

	res, err = cstl.Authenticate(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionAllow, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"action": "challenge"}`))
	}))

	castle.AuthenticateEndpoint = ts.URL

	res, err = cstl.Authenticate(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionChallenge, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"action": "deny"}`))
	}))

	castle.AuthenticateEndpoint = ts.URL

	res, err = cstl.Authenticate(
		castle.EventLoginSucceeded,
		"user-id",
		map[string]string{"prop1": "propValue1"},
		map[string]string{"trait1": "traitValue1"},
		castle.ContextFromRequest(req),
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionDeny, res)
}
