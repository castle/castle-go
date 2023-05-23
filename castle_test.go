package castle_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/utilitywarehouse/castle-go"
)

func configureRequest() *http.Request {
	req := httptest.NewRequest("GET", "/", nil)

	req.Header.Set("X-FORWARDED-FOR", "6.6.6.6, 3.3.3.3, 8.8.8.8")
	req.Header.Set("USER-AGENT", "some-agent")
	req.Header.Set("X-CASTLE-REQUEST-TOKEN", "request-token")

	return req
}

func TestCastle_SendFilterCall(t *testing.T) {
	ctx := context.Background()
	req := configureRequest()

	cstl, err := castle.New("secret-string")
	require.NoError(t, err)

	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, err := w.Write([]byte(`{"error": "this is an error"}`))
		require.NoError(t, err)
	}))

	castle.FilterEndpoint = fs.URL

	evt := castle.Event{
		EventType:   castle.EventTypeLogin,
		EventStatus: castle.EventStatusSucceeded,
	}

	res, err := cstl.Filter(
		ctx,
		castle.ContextFromRequest(req),
		evt,
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	fs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(400)
	}))

	castle.FilterEndpoint = fs.URL

	evt = castle.Event{
		EventType:   castle.EventTypeLogin,
		EventStatus: castle.EventStatusSucceeded,
	}

	res, err = cstl.Filter(
		ctx,
		castle.ContextFromRequest(req),
		evt,
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	fs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(201)
		_, err := w.Write([]byte(`{"policy": {"action": "allow"}}`))
		require.NoError(t, err)
	}))

	castle.FilterEndpoint = fs.URL

	evt = castle.Event{
		EventType:   castle.EventTypeLogin,
		EventStatus: castle.EventStatusSucceeded,
	}

	res, err = cstl.Filter(
		ctx,
		castle.ContextFromRequest(req),
		evt,
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionAllow, res)
}

func TestCastle_Filter(t *testing.T) {
	ctx := context.Background()
	req := configureRequest()

	cstl, err := castle.New("secret-string")
	require.NoError(t, err)

	executed := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(201)
		_, err := w.Write([]byte(`{"policy": {"name": "name"}}`))
		require.NoError(t, err)

		type castleFilterRequest struct {
			Type         castle.EventType   `json:"type"`
			Status       castle.EventStatus `json:"status"`
			RequestToken string             `json:"request_token"`
			User         castle.User        `json:"user"`
			Context      *castle.Context    `json:"context"`
			Properties   map[string]string  `json:"properties"`
		}

		reqData := &castleFilterRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		err = json.NewDecoder(r.Body).Decode(reqData)
		require.NoError(t, err)

		assert.Equal(t, castle.EventTypeLogin, reqData.Type)
		assert.Equal(t, castle.EventStatusSucceeded, reqData.Status)
		assert.Equal(t, "user-id", reqData.User.ID)
		assert.Equal(t, map[string]string{"prop1": "propValue1"}, reqData.Properties)
		assert.Equal(t, map[string]string{"trait1": "traitValue1"}, reqData.User.Traits)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.FilterEndpoint = ts.URL

	res, err := cstl.Filter(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)
	require.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	assert.True(t, executed)
}

func TestContextFromRequest(t *testing.T) {
	// grabs ClientID form cookie
	req := httptest.NewRequest("GET", "/", nil)

	req.Header.Set("HTTP_X_CASTLE_REQUEST_TOKEN", "some-token")

	ctx := castle.ContextFromRequest(req)
	assert.Equal(t, "some-token", ctx.RequestToken)

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

func TestCastle_Risk(t *testing.T) {
	ctx := context.Background()
	req := configureRequest()

	cstl, err := castle.New("secret-string")
	require.NoError(t, err)

	executed := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(201)
		_, err := w.Write([]byte(`{"policy": {"name": "name"}}`))
		require.NoError(t, err)

		type castleRiskRequest struct {
			Type         castle.EventType   `json:"type"`
			Status       castle.EventStatus `json:"status"`
			RequestToken string             `json:"request_token"`
			User         castle.User        `json:"user"`
			Context      *castle.Context    `json:"context"`
			Properties   map[string]string  `json:"properties"`
		}

		reqData := &castleRiskRequest{}

		username, password, ok := r.BasicAuth()

		assert.Empty(t, username)
		assert.Equal(t, password, "secret-string")
		assert.True(t, ok)

		err = json.NewDecoder(r.Body).Decode(reqData)
		require.NoError(t, err)

		assert.Equal(t, castle.EventTypeLogin, reqData.Type)
		assert.Equal(t, castle.EventStatusSucceeded, reqData.Status)
		assert.Equal(t, "user-id", reqData.User.ID)
		assert.Equal(t, map[string]string{"prop1": "propValue1"}, reqData.Properties)
		assert.Equal(t, map[string]string{"trait1": "traitValue1"}, reqData.User.Traits)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.RiskEndpoint = ts.URL

	_, err = cstl.Risk(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)
	require.NoError(t, err)

	assert.True(t, executed)
}

func TestCastle_SendRiskCall(t *testing.T) {
	ctx := context.Background()
	req := configureRequest()

	cstl, err := castle.New("secret-string")
	require.NoError(t, err)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, err := w.Write([]byte(`{"error": "this is an error"}`))
		require.NoError(t, err)
	}))

	castle.RiskEndpoint = ts.URL

	res, err := cstl.Risk(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(400)
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, err := w.Write([]byte(`{"type": "invalid_parameter", "message": "error message"}`))
		require.NoError(t, err)
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte(`{"policy": { "action": "allow"}}`))
		require.NoError(t, err)
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionAllow, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte(`{"policy": { "action": "challenge"}}`))
		require.NoError(t, err)
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionChallenge, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, err := w.Write([]byte(`{"policy": { "action": "deny"}}`))
		require.NoError(t, err)
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		ctx,
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			ID:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionDeny, res)
}
