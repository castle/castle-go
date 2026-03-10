# castle-go

[![Go Reference](https://pkg.go.dev/badge/github.com/castle/castle-go.svg)](https://pkg.go.dev/github.com/castle/castle-go)

The official [Castle](https://castle.io) Go SDK for account security and fraud prevention.

## Requirements

Go 1.21 or later. Zero external dependencies.

## Installation

```sh
go get github.com/castle/castle-go
```

## Usage

```go
import "github.com/castle/castle-go"
```

Construct a client with your API secret, then call `Filter` or `Risk`:

```go
client, err := castle.NewClient(castle.WithAPISecret("sk_your_api_secret"))
```

### Context extraction

Castle needs the end-user's IP and HTTP headers from each request. The SDK extracts and prepares the context automatically:

```go
castleCtx := client.ContextFromRequest(r)
```

This resolves the client IP from X-Forwarded-For (with trusted proxy filtering), scrubs sensitive headers (Cookie and Authorization are always redacted), and captures other request metadata needed by the Castle API.

### Filter (pre-authentication)

```go
resp, err := client.Filter(r.Context(), &castle.FilterRequest{
    Type:         "$login",
    Status:       "$attempted",
    RequestToken: r.FormValue("castle_request_token"),
    Context:      castleCtx,
    User:         &castle.User{Email: r.FormValue("email")},
})

switch resp.Policy.Action {
case castle.ActionAllow:
    // Proceed with login
case castle.ActionDeny:
    // Block the request
case castle.ActionChallenge:
    // Trigger MFA
}
```

### Risk (post-authentication)

```go
resp, err := client.Risk(r.Context(), &castle.RiskRequest{
    Type:         "$login",
    Status:       "$succeeded",
    RequestToken: r.FormValue("castle_request_token"),
    Context:      castleCtx,
    User:         &castle.User{ID: "user-123", Email: r.FormValue("email")},
})
```

## Failover

Castle sits in the authentication path. On timeout, network error, or 5xx, the SDK returns a synthetic response instead of an error so your auth flow is never blocked:

| Strategy | Behavior | Use when |
|----------|----------|----------|
| `FailoverAllow` (default) | Returns allow | Don't block users during outages |
| `FailoverDeny` | Returns deny | Strict security requirements |
| `FailoverChallenge` | Returns challenge | Trigger MFA on uncertainty |
| `FailoverThrow` | Returns the error | You handle failover yourself |

Failover responses have `resp.Failover == true` and `resp.FailoverReason` set. Client errors (4xx) always return an error and never trigger failover.

## Configuration

```go
client, err := castle.NewClient(
    castle.WithAPISecret("sk_..."),
    castle.WithTimeout(500 * time.Millisecond),
    castle.WithFailoverStrategy(castle.FailoverAllow),

    // IP resolution
    castle.WithIPHeaders([]string{"CF-Connecting-IP"}),
    castle.WithTrustedProxies([]string{"10.0.0.0/8"}),
    castle.WithTrustedProxyDepth(1),
    castle.WithTrustProxyChain(false),

    // Header control
    castle.WithAllowlistedHeaders(castle.DefaultAllowlist),
    castle.WithDenylistedHeaders([]string{"X-Internal-Token"}),

    // HTTP client
    castle.WithHTTPClient(customClient),
    castle.WithBaseURL("https://api.castle.io/v1"),
    castle.WithDoNotTrack(true),
    castle.WithLogger(myLogger),
)
```

By default, all headers are forwarded (with Cookie and Authorization scrubbed to `true`). Use `WithAllowlistedHeaders(castle.DefaultAllowlist)` to restrict to the [recommended set of 22 headers](https://docs.castle.io).

## Error handling

```go
resp, err := client.Filter(ctx, req)
if err != nil {
    var apiErr *castle.APIError
    if errors.As(err, &apiErr) {
        log.Printf("HTTP %d: %s", apiErr.StatusCode, apiErr.Message)
    }

    if errors.Is(err, castle.ErrUnauthorized) {
        // Bad API secret
    }
    if errors.Is(err, castle.ErrInvalidRequestToken) {
        // Expired or invalid request token
    }
}
```

All API errors implement `errors.Is` and `errors.As`:

| Status | Sentinel |
|--------|----------|
| 400 | `ErrBadRequest` |
| 401 | `ErrUnauthorized` |
| 403 | `ErrForbidden` |
| 404 | `ErrNotFound` |
| 419 | `ErrUserUnauthorized` |
| 422 | `ErrInvalidParameters` or `ErrInvalidRequestToken` |
| 429 | `ErrRateLimit` |
| 5xx | `ErrInternalServer` (triggers failover) |

## Testing

The SDK is designed for testing without hitting the Castle API:

```go
// Option 1: point at a local test server
ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(201)
    w.Write([]byte(`{"policy":{"action":"allow"}}`))
}))
client, _ := castle.NewClient(
    castle.WithAPISecret("test"),
    castle.WithBaseURL(ts.URL),
)

// Option 2: skip all HTTP calls (returns synthetic allow)
client, _ := castle.NewClient(
    castle.WithAPISecret("test"),
    castle.WithDoNotTrack(true),
)
```

## Documentation

For the complete API reference, see the [Castle API documentation](https://docs.castle.io).

For Go package documentation, see [pkg.go.dev](https://pkg.go.dev/github.com/castle/castle-go).

## License

MIT
