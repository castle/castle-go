package castle

import (
	"errors"
	"net/http"
	"time"
)

var (
	ErrMissingAPISecret = errors.New("castle: API secret is required")
)

// DefaultAllowlist is the recommended set of headers to forward to Castle.
// When no allowlist is configured (the default), ALL headers are sent with
// their real values (except always-denied ones which are scrubbed to true).
// Use WithAllowlistedHeaders(castle.DefaultAllowlist) to restrict to this set.
var DefaultAllowlist = []string{
	"Accept",
	"Accept-Charset",
	"Accept-Datetime",
	"Accept-Encoding",
	"Accept-Language",
	"Cache-Control",
	"Connection",
	"Content-Length",
	"Content-Type",
	"Dnt",
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
	"X-Requested-With",
}

// alwaysDenied headers are always scrubbed to true regardless of configuration.
var alwaysDenied = []string{
	"Cookie",
	"Authorization",
}

// alwaysAllowed headers are never scrubbed, even if user denylists them.
var alwaysAllowed = []string{
	"User-Agent",
}

// config holds all SDK configuration. Unexported; set via Option functions.
type config struct {
	apiSecret        string
	baseURL          string
	timeout          time.Duration
	failoverStrategy FailoverStrategy
	doNotTrack       bool
	allowlisted      []string
	denylisted       []string
	ipHeaders        []string
	trustedProxies   []string
	trustedProxyDepth int
	trustProxyChain  bool
	httpClient       HTTPDoer
	logger           Logger
}

// Client is the Castle SDK client. Create one with NewClient.
type Client struct {
	cfg config
}

// Option configures a Client.
type Option func(*config)

// NewClient creates a Castle client with the given options.
// At minimum, WithAPISecret must be provided.
func NewClient(opts ...Option) (*Client, error) {
	cfg := config{
		baseURL:          defaultBaseURL,
		timeout:          1000 * time.Millisecond,
		failoverStrategy: FailoverAllow,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.apiSecret == "" {
		return nil, ErrMissingAPISecret
	}

	if cfg.httpClient == nil {
		cfg.httpClient = &http.Client{Timeout: cfg.timeout}
	}

	return &Client{cfg: cfg}, nil
}

func WithAPISecret(secret string) Option {
	return func(c *config) { c.apiSecret = secret }
}

func WithBaseURL(url string) Option {
	return func(c *config) { c.baseURL = url }
}

func WithTimeout(d time.Duration) Option {
	return func(c *config) { c.timeout = d }
}

func WithFailoverStrategy(s FailoverStrategy) Option {
	return func(c *config) { c.failoverStrategy = s }
}

func WithDoNotTrack(v bool) Option {
	return func(c *config) { c.doNotTrack = v }
}

func WithAllowlistedHeaders(headers []string) Option {
	return func(c *config) { c.allowlisted = headers }
}

func WithDenylistedHeaders(headers []string) Option {
	return func(c *config) { c.denylisted = headers }
}

func WithIPHeaders(headers []string) Option {
	return func(c *config) { c.ipHeaders = headers }
}

func WithTrustedProxies(proxies []string) Option {
	return func(c *config) { c.trustedProxies = proxies }
}

func WithTrustedProxyDepth(depth int) Option {
	return func(c *config) { c.trustedProxyDepth = depth }
}

func WithTrustProxyChain(v bool) Option {
	return func(c *config) { c.trustProxyChain = v }
}

func WithHTTPClient(client HTTPDoer) Option {
	return func(c *config) { c.httpClient = client }
}

func WithLogger(l Logger) Option {
	return func(c *config) { c.logger = l }
}
