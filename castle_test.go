package castle

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testServer spins up an httptest server and a client pointed at it. The
// handler receives every request so tests can assert on method/path/body.
func testServer(t *testing.T, handler http.HandlerFunc, opts ...Option) *Castle {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	opts = append([]Option{WithBaseURL(srv.URL)}, opts...)
	client, err := New("secret", opts...)
	require.NoError(t, err)
	return client
}

func decodeRequest(t *testing.T, r *http.Request) Params {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	if len(body) == 0 {
		return nil
	}
	var p Params
	require.NoError(t, json.Unmarshal(body, &p))
	return p
}

func TestNewValidation(t *testing.T) {
	t.Run("missing secret", func(t *testing.T) {
		_, err := New("")
		var cfgErr *ConfigurationError
		assert.ErrorAs(t, err, &cfgErr)
	})

	t.Run("invalid failover strategy", func(t *testing.T) {
		_, err := New("secret", WithFailoverStrategy("bogus"))
		var cfgErr *ConfigurationError
		assert.ErrorAs(t, err, &cfgErr)
	})

	t.Run("defaults", func(t *testing.T) {
		client, err := New("secret")
		require.NoError(t, err)
		assert.Equal(t, DefaultBaseURL, client.config.baseURL)
		assert.Equal(t, DefaultTimeout, client.config.timeout)
		assert.Equal(t, FailoverAllow, client.config.failoverStrategy)
	})
}

func TestRequestAuthAndContentType(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "", user)
		assert.Equal(t, "secret", pass)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	})

	_, err := client.Risk(context.Background(), Params{"event": "$login"})
	require.NoError(t, err)
}

func TestRiskSuccessAddsSentAtAndFailoverFields(t *testing.T) {
	var received Params
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/risk", r.URL.Path)
		received = decodeRequest(t, r)
		_, _ = w.Write([]byte(`{"action":"allow","user_id":"u1"}`))
	})

	res, err := client.Risk(context.Background(), Params{"event": "$login"})
	require.NoError(t, err)
	assert.Equal(t, "allow", res["action"])
	assert.Equal(t, false, res["failover"])
	assert.Nil(t, res["failover_reason"])
	assert.Contains(t, received, "sent_at")
}

func TestRiskPreservesProvidedSentAt(t *testing.T) {
	var received Params
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		received = decodeRequest(t, r)
		_, _ = w.Write([]byte(`{}`))
	})

	_, err := client.Risk(context.Background(), Params{"event": "$login", "sent_at": "2020-01-01T00:00:00.000Z"})
	require.NoError(t, err)
	assert.Equal(t, "2020-01-01T00:00:00.000Z", received["sent_at"])
}

func TestRiskFailoverOnServerError(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	res, err := client.Risk(context.Background(), Params{"user": Params{"id": "u1"}})
	require.NoError(t, err)
	assert.Equal(t, "allow", res["action"])
	assert.Equal(t, true, res["failover"])
	assert.Equal(t, "u1", res["user_id"])
	assert.NotEmpty(t, res["failover_reason"])
}

func TestRiskFailoverThrow(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}, WithFailoverStrategy(FailoverThrow))

	_, err := client.Risk(context.Background(), Params{"user": Params{"id": "u1"}})
	var serverErr *InternalServerError
	assert.ErrorAs(t, err, &serverErr)
}

func TestFilterFailoverUsesMatchingUserID(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/filter", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}, WithFailoverStrategy(FailoverDeny))

	res, err := client.Filter(context.Background(), Params{"matching_user_id": "m1"})
	require.NoError(t, err)
	assert.Equal(t, "deny", res["action"])
	assert.Equal(t, "m1", res["user_id"])
}

func TestLogDoesNotFailover(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/log", r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := client.Log(context.Background(), Params{"event": "$login"})
	var serverErr *InternalServerError
	assert.ErrorAs(t, err, &serverErr)
}

func TestDoNotTrack(t *testing.T) {
	called := false
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	}, WithDoNotTrack(true))

	res, err := client.Risk(context.Background(), Params{"user": Params{"id": "u1"}})
	require.NoError(t, err)
	assert.Equal(t, "allow", res["action"])
	assert.Equal(t, true, res["failover"])

	logRes, err := client.Log(context.Background(), Params{"event": "$login"})
	require.NoError(t, err)
	assert.Nil(t, logRes)
	assert.False(t, called)
}

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		body   string
		check  func(error) bool
	}{
		{400, `{"message":"bad"}`, func(e error) bool { var t *BadRequestError; return errors.As(e, &t) }},
		{401, ``, func(e error) bool { var t *UnauthorizedError; return errors.As(e, &t) }},
		{403, ``, func(e error) bool { var t *ForbiddenError; return errors.As(e, &t) }},
		{404, ``, func(e error) bool { var t *NotFoundError; return errors.As(e, &t) }},
		{419, ``, func(e error) bool { var t *UserUnauthorizedError; return errors.As(e, &t) }},
		{422, `{"type":"invalid_request_token"}`, func(e error) bool { var t *InvalidRequestTokenError; return errors.As(e, &t) }},
		{422, `{"type":"other","message":"x"}`, func(e error) bool { var t *InvalidParametersError; return errors.As(e, &t) }},
		{429, ``, func(e error) bool { var t *RateLimitError; return errors.As(e, &t) }},
	}

	for _, tc := range cases {
		tc := tc
		client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tc.status)
			if tc.body != "" {
				_, _ = w.Write([]byte(tc.body))
			}
		})
		_, err := client.GetAllLists(context.Background())
		require.Error(t, err)
		assert.Truef(t, tc.check(err), "status %d produced %T", tc.status, err)
	}
}

func TestListsEndpoints(t *testing.T) {
	type call struct{ method, path string }
	var got call
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = call{r.Method, r.URL.Path}
		_, _ = w.Write([]byte(`{}`))
	})
	ctx := context.Background()

	cases := []struct {
		run    func() (Params, error)
		method string
		path   string
	}{
		{func() (Params, error) { return client.CreateList(ctx, Params{"name": "x"}) }, "POST", "/lists"},
		{func() (Params, error) { return client.GetAllLists(ctx) }, "GET", "/lists"},
		{func() (Params, error) { return client.GetList(ctx, "l1") }, "GET", "/lists/l1"},
		{func() (Params, error) { return client.QueryLists(ctx, Params{}) }, "POST", "/lists/query"},
		{func() (Params, error) { return client.UpdateList(ctx, "l1", Params{}) }, "PUT", "/lists/l1"},
		{func() (Params, error) { return client.DeleteList(ctx, "l1") }, "DELETE", "/lists/l1"},
		{func() (Params, error) { return client.CreateListItem(ctx, "l1", Params{}) }, "POST", "/lists/l1/items"},
		{func() (Params, error) { return client.CreateListItemsBatch(ctx, "l1", []Params{{"a": 1}}) }, "POST", "/lists/l1/items/batch"},
		{func() (Params, error) { return client.GetListItem(ctx, "l1", "i1") }, "GET", "/lists/l1/items/i1"},
		{func() (Params, error) { return client.QueryListItems(ctx, "l1", Params{}) }, "POST", "/lists/l1/items/query"},
		{func() (Params, error) { return client.CountListItems(ctx, "l1", Params{}) }, "POST", "/lists/l1/items/count"},
		{func() (Params, error) { return client.UpdateListItem(ctx, "l1", "i1", Params{}) }, "PUT", "/lists/l1/items/i1"},
		{func() (Params, error) { return client.ArchiveListItem(ctx, "l1", "i1") }, "DELETE", "/lists/l1/items/i1/archive"},
		{func() (Params, error) { return client.UnarchiveListItem(ctx, "l1", "i1") }, "PUT", "/lists/l1/items/i1/unarchive"},
	}

	for _, tc := range cases {
		_, err := tc.run()
		require.NoError(t, err)
		assert.Equal(t, tc.method, got.method)
		assert.Equal(t, tc.path, got.path)
	}
}

func TestPrivacyAndEventsEndpoints(t *testing.T) {
	type call struct{ method, path string }
	var got call
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = call{r.Method, r.URL.Path}
		_, _ = w.Write([]byte(`{}`))
	})
	ctx := context.Background()

	cases := []struct {
		run    func() (Params, error)
		method string
		path   string
	}{
		{func() (Params, error) { return client.RequestUserData(ctx, Params{}) }, "POST", "/privacy/users"},
		{func() (Params, error) { return client.DeleteUserData(ctx, Params{}) }, "DELETE", "/privacy/users"},
		{func() (Params, error) { return client.EventsSchema(ctx) }, "GET", "/events/schema"},
		{func() (Params, error) { return client.QueryEvents(ctx, Params{}) }, "POST", "/events/query"},
		{func() (Params, error) { return client.GroupEvents(ctx, Params{}) }, "POST", "/events/group"},
	}
	for _, tc := range cases {
		_, err := tc.run()
		require.NoError(t, err)
		assert.Equal(t, tc.method, got.method)
		assert.Equal(t, tc.path, got.path)
	}
}

func TestTimeoutTriggersFailover(t *testing.T) {
	client := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte(`{}`))
	}, WithTimeout(5*time.Millisecond))

	res, err := client.Risk(context.Background(), Params{"user": Params{"id": "u1"}})
	require.NoError(t, err)
	assert.Equal(t, true, res["failover"])
}
