# castle-go

`castle-go` is the Go SDK for the [Castle](https://castle.io) API. It wraps the
scoring endpoints (Risk, Filter, Log), the Lists, List items, Privacy and Events
APIs, webhook signature verification and secure mode.

## Install

```
go get github.com/castle/castle-go
```

```go
import castle "github.com/castle/castle-go"
```

Requires Go 1.21+.

## Configuration

Create a client with your API secret and, optionally, functional options:

```go
client, err := castle.New(
    "YOUR_API_SECRET",
    castle.WithBaseURL("https://api.castle.io/v1"),     // default
    castle.WithTimeout(1000*time.Millisecond),           // default
    castle.WithFailoverStrategy(castle.FailoverAllow),   // default
    castle.WithAllowList("User-Agent", "Accept"),        // allowlist header mode
    castle.WithDenyList("Cookie"),                       // denylist header mode
    castle.WithIPHeaders("X-Forwarded-For"),
    castle.WithTrustedProxies(`\A203\.0\.113\.`),
    castle.WithTrustProxyChain(false),
    castle.WithTrustedProxyDepth(1),
    castle.WithDoNotTrack(false),
    castle.WithHTTPClient(&http.Client{}),
)
if err != nil {
    log.Fatal(err)
}
```

| Option | Default | Description |
| --- | --- | --- |
| `WithBaseURL` | `https://api.castle.io/v1` | API base URL (includes the version segment). |
| `WithTimeout` | `1000ms` | Per-request timeout. |
| `WithFailoverStrategy` | `FailoverAllow` | Verdict returned by `Risk`/`Filter` when the API is unreachable (`allow`, `challenge`, `deny`, `throw`). |
| `WithAllowList` | — | Allowlist header mode: only the listed headers are forwarded with their values; all others are sent as `true`. |
| `WithDenyList` | — | Headers always scrubbed (sent as `true`) in the default denylist mode. |
| `WithIPHeaders` | `X-Forwarded-For`, `Remote-Addr` | Ordered sources consulted when resolving the client IP. |
| `WithTrustedProxies` | — | Proxy IPs (literals or regexes) stripped from the forwarded-for chain. |
| `WithTrustProxyChain` | `false` | Trust the whole chain and resolve to the left-most entry. |
| `WithTrustedProxyDepth` | `0` | Trim N trailing proxies before resolving the IP. |
| `WithDoNotTrack` | `false` | Disable outbound tracking. |
| `WithHTTPClient` | — | Supply a custom `*http.Client`. |

`Cookie` and `Authorization` are always scrubbed, and `User-Agent` is always
forwarded, regardless of the allow/deny configuration.

## Request context

Build the request context from an incoming `*http.Request` and pass it as the
`context` field of a scoring call:

```go
ctx := r.Context()
res, err := client.Risk(ctx, castle.Params{
    "type":          "$login",
    "status":        "$succeeded",
    "request_token": requestToken,
    "user":          castle.Params{"id": "user-123"},
    "context":       client.ContextFromRequest(r),
})
```

`Params` is an alias for `map[string]interface{}`. Request parameters are sent
to the API verbatim, and responses are returned as parsed `Params`.

## Scoring

```go
risk, err := client.Risk(ctx, params)     // POST /risk
filter, err := client.Filter(ctx, params) // POST /filter
err := client.Log(ctx, params)            // POST /log
```

`Risk` and `Filter` apply the configured failover strategy on transport errors,
timeouts and `5xx` responses, returning a synthetic verdict:

```go
res, _ := client.Risk(ctx, params)
if failed, _ := res["failover"].(bool); failed {
    // res["action"] is the failover verdict
}
```

With `FailoverThrow` the underlying error is returned instead. `Log` never
fails over.

## Lists and list items

```go
client.CreateList(ctx, params)
client.GetAllLists(ctx)
client.GetList(ctx, listID)
client.QueryLists(ctx, params)
client.UpdateList(ctx, listID, params)
client.DeleteList(ctx, listID)

client.CreateListItem(ctx, listID, params)
client.CreateListItemsBatch(ctx, listID, items)
client.GetListItem(ctx, listID, itemID)
client.QueryListItems(ctx, listID, params)
client.CountListItems(ctx, listID, params)
client.UpdateListItem(ctx, listID, itemID, params)
client.ArchiveListItem(ctx, listID, itemID)
client.UnarchiveListItem(ctx, listID, itemID)
```

## Privacy

```go
client.RequestUserData(ctx, castle.Params{"identifier": "user@example.com", "identifier_type": "$email"})
client.DeleteUserData(ctx, castle.Params{"identifier": "user@example.com", "identifier_type": "$email"})
```

## Events

```go
client.EventsSchema(ctx)
client.QueryEvents(ctx, params)
client.GroupEvents(ctx, params)
```

## Webhook verification

```go
if err := client.VerifyWebhookRequest(r); err != nil {
    http.Error(w, "invalid signature", http.StatusBadRequest)
    return
}
// r.Body is still readable here
```

`VerifyWebhook(body, signature)` is available when you already have the raw
body and the `X-Castle-Signature` header value.

## Secure mode

```go
signature := client.SecureModeSignature("user-123")
```

## Errors

API failures are returned as typed errors that embed `*APIError`
(`BadRequestError`, `UnauthorizedError`, `ForbiddenError`, `NotFoundError`,
`UserUnauthorizedError`, `InvalidParametersError`, `InvalidRequestTokenError`,
`RateLimitError`, `InternalServerError`). Transport failures are returned as
`*RequestError`, configuration problems as `*ConfigurationError`, and webhook
mismatches as `*WebhookVerificationError`.

```go
var invalidToken *castle.InvalidRequestTokenError
if errors.As(err, &invalidToken) {
    // ...
}
```

## Development

```
make test   # go test ./...
make vet     # go vet ./...
make fmt     # gofmt -w .
make lint    # gofmt check + go vet
```
