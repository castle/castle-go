package castle

import (
	"net"
	"net/http"
	"strings"
)

// Library identifies the SDK that produced the context.
type Library struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Context holds the end-user's request information needed by the Castle API.
// Create one with Client.ContextFromRequest.
type Context struct {
	Active    bool                   `json:"active"`
	IP        string                 `json:"ip"`
	Headers   map[string]interface{} `json:"headers"`
	ClientID  string                 `json:"client_id,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Locale    string                 `json:"locale,omitempty"`
	Library   *Library               `json:"library,omitempty"`
}

// ContextFromRequest extracts client IP, HTTP headers, and client ID
// from an incoming *http.Request. Uses the client's configuration for
// trusted proxies, IP headers, and header allow/deny lists.
func (c *Client) ContextFromRequest(r *http.Request) *Context {
	ctx := &Context{
		Active:   true,
		IP:       c.extractIP(r),
		Headers:  c.extractHeaders(r),
		ClientID: extractClientID(r),
		Library:  &Library{Name: "castle-go", Version: Version},
	}

	if ua := r.Header.Get("User-Agent"); ua != "" {
		ctx.UserAgent = ua
	}
	if lang := r.Header.Get("Accept-Language"); lang != "" {
		ctx.Locale = lang
	}

	return ctx
}

// extractIP resolves the client's real IP address from the request.
//
// Resolution order:
//  1. Custom IP headers (if configured via WithIPHeaders)
//  2. X-Forwarded-For (with trusted proxy filtering)
//  3. X-Real-Ip
//  4. RemoteAddr
func (c *Client) extractIP(r *http.Request) string {
	// Custom IP headers take priority
	for _, header := range c.cfg.ipHeaders {
		if val := r.Header.Get(header); val != "" {
			ips := parseIPList(val)
			if ip := c.resolveFromChain(ips, header); ip != "" {
				return ip
			}
		}
	}

	// X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := parseIPList(xff)
		if ip := c.resolveFromChain(ips, "X-Forwarded-For"); ip != "" {
			return ip
		}
		// If all IPs were proxies, fall through
	}

	// X-Real-Ip
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// RemoteAddr (strip port)
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// resolveFromChain picks the correct client IP from a chain of IPs.
//
// Strategies (matching Ruby SDK behavior):
//   - trust_proxy_chain=true: return the leftmost (first) IP
//   - trusted_proxy_depth>0 on depth-related headers (XFF): pop N from right, take rightmost remaining
//   - default: strip known proxies, take rightmost non-proxy
func (c *Client) resolveFromChain(ips []string, header string) string {
	if len(ips) == 0 {
		return ""
	}

	if c.cfg.trustProxyChain {
		return ips[0]
	}

	// Depth-related trimming only for XFF-style headers
	working := make([]string, len(ips))
	copy(working, ips)

	isDepthRelated := strings.EqualFold(header, "X-Forwarded-For")
	if isDepthRelated && c.cfg.trustedProxyDepth > 0 && c.cfg.trustedProxyDepth < len(working) {
		working = working[:len(working)-c.cfg.trustedProxyDepth]
	}

	// Strip proxies, take rightmost non-proxy
	for i := len(working) - 1; i >= 0; i-- {
		if !c.isProxy(working[i]) {
			return working[i]
		}
	}

	// All were proxies; return first from original chain
	if len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// isProxy checks whether an IP is a known proxy (private range or configured trusted proxy).
func (c *Client) isProxy(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}

	// RFC 1918 / RFC 4193 / loopback
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return true
	}

	// User-configured trusted proxies (CIDR or single IP)
	for _, proxy := range c.cfg.trustedProxies {
		if strings.Contains(proxy, "/") {
			_, cidr, err := net.ParseCIDR(proxy)
			if err == nil && cidr.Contains(parsed) {
				return true
			}
		} else {
			if net.ParseIP(proxy) != nil && net.ParseIP(proxy).Equal(parsed) {
				return true
			}
		}
	}

	return false
}

// extractHeaders collects headers from the request for the Castle context.
//
// Behavior matches Ruby SDK (Headers::Extract):
//   - Always-denied headers (Cookie, Authorization) are included but scrubbed to true
//   - Always-allowed headers (User-Agent) are always sent with real value
//   - User-configured denied headers are scrubbed to true
//   - If allowlist is set: only allowlisted headers get real values, others scrubbed to true
//   - If allowlist is empty/nil: all headers get real values (except denied ones)
func (c *Client) extractHeaders(r *http.Request) map[string]interface{} {
	headers := make(map[string]interface{})

	for name := range r.Header {
		canonical := http.CanonicalHeaderKey(name)
		headers[canonical] = c.headerValue(canonical, r.Header.Get(name))
	}

	return headers
}

// headerValue determines the value for a header in the Castle context.
// Matches Ruby SDK precedence: always-denied > always-allowed > user-denied > user-allowed > scrub.
func (c *Client) headerValue(name, value string) interface{} {
	if c.isAlwaysDenied(name) {
		return true
	}
	if c.isAlwaysAllowed(name) {
		return value
	}
	if c.isUserDenied(name) {
		return true
	}
	if c.hasAllowlist() {
		if c.isUserAllowed(name) {
			return value
		}
		return true
	}
	return value
}

func (c *Client) isAlwaysDenied(name string) bool {
	for _, denied := range alwaysDenied {
		if strings.EqualFold(name, denied) {
			return true
		}
	}
	return false
}

func (c *Client) isAlwaysAllowed(name string) bool {
	for _, allowed := range alwaysAllowed {
		if strings.EqualFold(name, allowed) {
			return true
		}
	}
	return false
}

func (c *Client) isUserDenied(name string) bool {
	for _, denied := range c.cfg.denylisted {
		if strings.EqualFold(name, denied) {
			return true
		}
	}
	return false
}

func (c *Client) hasAllowlist() bool {
	return len(c.cfg.allowlisted) > 0
}

func (c *Client) isUserAllowed(name string) bool {
	for _, allowed := range c.cfg.allowlisted {
		if strings.EqualFold(name, http.CanonicalHeaderKey(allowed)) {
			return true
		}
	}
	return false
}

// extractClientID reads the Castle client ID from the request.
// Checks X-Castle-Client-Id header first, falls back to __cid cookie.
func extractClientID(r *http.Request) string {
	if cid := r.Header.Get("X-Castle-Client-Id"); cid != "" {
		return cid
	}

	if cookie, err := r.Cookie("__cid"); err == nil {
		return cookie.Value
	}

	return ""
}

// parseIPList splits a comma-separated IP list and trims whitespace.
func parseIPList(value string) []string {
	parts := strings.Split(value, ",")
	ips := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			ips = append(ips, trimmed)
		}
	}
	return ips
}
