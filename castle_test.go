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

	req.Header.Set("X-FORWARDED-FOR", "6.6.6.6, 3.3.3.3, 8.8.8.8")
	req.Header.Set("USER-AGENT", "some-agent")
	req.Header.Set("X-CASTLE-REQUEST-TOKEN", "request-token")

	return req
}

func TestCastle_SendFilterCall(t *testing.T) {
	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	fs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"error": "this is an error"}`))
	}))

	castle.FilterEndpoint = fs.URL

	evt := castle.Event{
		EventType:   castle.EventTypeLogin,
		EventStatus: castle.EventStatusSucceeded,
	}

	err := cstl.Filter(
		castle.ContextFromRequest(req),
		evt,
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)

	fs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(400)
	}))

	castle.FilterEndpoint = fs.URL

	evt = castle.Event{
		EventType:   castle.EventTypeLogin,
		EventStatus: castle.EventStatusSucceeded,
	}

	err = cstl.Filter(
		castle.ContextFromRequest(req),
		evt,
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)

	fs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(204)
	}))

	castle.FilterEndpoint = fs.URL

	evt = castle.Event{
		EventType:   castle.EventTypeLogin,
		EventStatus: castle.EventStatusSucceeded,
	}

	err = cstl.Filter(
		castle.ContextFromRequest(req),
		evt,
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
}

func TestCastle_Filter(t *testing.T) {
	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	executed := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castle.EventTypeLogin, reqData.Type)
		assert.Equal(t, castle.EventStatusSucceeded, reqData.Status)
		assert.Equal(t, "user-id", reqData.User.Id)
		assert.Equal(t, map[string]string{"prop1": "propValue1"}, reqData.Properties)
		assert.Equal(t, map[string]string{"trait1": "traitValue1"}, reqData.User.Traits)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.FilterEndpoint = ts.URL

	cstl.Filter(
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

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
	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	executed := false

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		json.NewDecoder(r.Body).Decode(reqData)

		assert.Equal(t, castle.EventTypeLogin, reqData.Type)
		assert.Equal(t, castle.EventStatusSucceeded, reqData.Status)
		assert.Equal(t, "user-id", reqData.User.Id)
		assert.Equal(t, map[string]string{"prop1": "propValue1"}, reqData.Properties)
		assert.Equal(t, map[string]string{"trait1": "traitValue1"}, reqData.User.Traits)
		assert.Equal(t, castle.ContextFromRequest(req), reqData.Context)

		executed = true
	}))

	castle.RiskEndpoint = ts.URL

	cstl.Risk(
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.True(t, executed)
}

func TestCastle_SendRiskCall(t *testing.T) {
	req := configureRequest()

	cstl, _ := castle.New("secret-string")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"error": "this is an error"}`))
	}))

	castle.RiskEndpoint = ts.URL

	res, err := cstl.Risk(
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
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
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"type": "invalid_parameter", "message": "error message"}`))
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.Error(t, err)
	assert.Equal(t, castle.RecommendedActionNone, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"policy": { "action": "allow"}}`))
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionAllow, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"policy": { "action": "challenge"}}`))
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionChallenge, res)

	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"policy": { "action": "deny"}}`))
	}))

	castle.RiskEndpoint = ts.URL

	res, err = cstl.Risk(
		castle.ContextFromRequest(req),
		castle.Event{
			EventType:   castle.EventTypeLogin,
			EventStatus: castle.EventStatusSucceeded,
		},
		castle.User{
			Id:     "user-id",
			Traits: map[string]string{"trait1": "traitValue1"},
		},
		map[string]string{"prop1": "propValue1"},
	)

	assert.NoError(t, err)
	assert.Equal(t, castle.RecommendedActionDeny, res)
}
