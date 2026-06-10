package castle

import (
	"net/http"
	"regexp"
	"time"
)

const (
	// DefaultBaseURL is the Castle API base URL, including the version segment.
	DefaultBaseURL = "https://api.castle.io/v1"
	// DefaultTimeout is the default per-request timeout.
	DefaultTimeout = 1000 * time.Millisecond
)

// DefaultAllowList is the recommended set of request headers to forward to
// Castle when running in allowlist mode. It is exported so callers can opt into
// strict header forwarding via WithAllowList(castle.DefaultAllowList...).
var DefaultAllowList = []string{
	"Accept",
	"Accept-Charset",
	"Accept-Datetime",
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Connection",
	"Content-Length",
	"Content-Type",
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
	"X-Forwarded-For",
	"X-Forwarded-Proto",
	"X-Requested-With",
}

// config holds the resolved client configuration.
type config struct {
	apiSecret         string
	baseURL           string
	timeout           time.Duration
	allowList         []string
	denyList          []string
	failoverStrategy  FailoverStrategy
	ipHeaders         []string
	trustedProxies    []string
	trustProxyChain   bool
	trustedProxyDepth int
	doNotTrack        bool
	httpClient        *http.Client
	trustedProxyRes   []*regexp.Regexp
}

// Option configures a Castle client. Options are applied in order by New.
type Option func(*config)

// WithBaseURL overrides the Castle API base URL (default DefaultBaseURL).
func WithBaseURL(baseURL string) Option {
	return func(c *config) { c.baseURL = baseURL }
}

// WithTimeout sets the per-request timeout (default DefaultTimeout).
func WithTimeout(timeout time.Duration) Option {
	return func(c *config) { c.timeout = timeout }
}

// WithAllowList enables allowlist header mode: only the listed request headers
// are forwarded with their values; all others are sent as the boolean true.
func WithAllowList(headers ...string) Option {
	return func(c *config) { c.allowList = headers }
}

// WithDenyList sets headers that are always scrubbed (sent as the boolean true)
// when running in the default denylist mode.
func WithDenyList(headers ...string) Option {
	return func(c *config) { c.denyList = headers }
}

// WithFailoverStrategy sets the strategy used by Risk and Filter when the API
// is unreachable (default FailoverAllow).
func WithFailoverStrategy(strategy FailoverStrategy) Option {
	return func(c *config) { c.failoverStrategy = strategy }
}

// WithIPHeaders sets the ordered list of headers consulted when resolving the
// client IP (default ["X-Forwarded-For", "Remote-Addr"]).
func WithIPHeaders(headers ...string) Option {
	return func(c *config) { c.ipHeaders = headers }
}

// WithTrustedProxies adds proxy IPs (literal addresses or regular expressions)
// that are stripped from the forwarded-for chain during IP resolution.
func WithTrustedProxies(proxies ...string) Option {
	return func(c *config) { c.trustedProxies = proxies }
}

// WithTrustProxyChain trusts the entire forwarded-for chain and resolves the
// client IP to the left-most entry.
func WithTrustProxyChain(trust bool) Option {
	return func(c *config) { c.trustProxyChain = trust }
}

// WithTrustedProxyDepth trims the given number of trailing proxies from the
// forwarded-for chain before resolving the client IP.
func WithTrustedProxyDepth(depth int) Option {
	return func(c *config) { c.trustedProxyDepth = depth }
}

// WithDoNotTrack disables outbound tracking: Risk and Filter return a failover
// response and Log becomes a no-op without contacting the API.
func WithDoNotTrack(doNotTrack bool) Option {
	return func(c *config) { c.doNotTrack = doNotTrack }
}

// WithHTTPClient supplies a custom *http.Client. Its Timeout, if zero, is set
// from the configured request timeout.
func WithHTTPClient(client *http.Client) Option {
	return func(c *config) { c.httpClient = client }
}

func defaultConfig(secret string) *config {
	return &config{
		apiSecret:        secret,
		baseURL:          DefaultBaseURL,
		timeout:          DefaultTimeout,
		allowList:        nil,
		denyList:         nil,
		failoverStrategy: FailoverAllow,
		ipHeaders:        nil,
		trustedProxies:   nil,
	}
}
