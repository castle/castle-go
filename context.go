package castle

import (
	"net"
	"net/http"
	"regexp"
	"strings"
)

// libraryName identifies this SDK in the request context fingerprint.
const libraryName = "castle-go"

// alwaysScrubbedHeaders are never forwarded with their value, regardless of the
// allow/deny configuration.
var alwaysScrubbedHeaders = map[string]bool{
	"Cookie":        true,
	"Authorization": true,
}

// defaultIPHeaders is the ordered list of sources consulted for the client IP
// when none is configured. "Remote-Addr" resolves to the request's RemoteAddr.
var defaultIPHeaders = []string{"X-Forwarded-For", "Remote-Addr"}

// defaultTrustedProxies matches loopback, private-range, and link-local
// addresses that should be stripped from a forwarded-for chain.
var defaultTrustedProxies = []string{
	`\A127\.0\.0\.\d{1,3}\z`,
	`\A(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.`,
	`\A::1\z`,
	`\Afd[0-9a-f]{2}:`,
	`\Alocalhost\z`,
	`\Aunix\z`,
	`\Aunix:`,
}

func compileTrustedProxies(extra []string) []*regexp.Regexp {
	patterns := make([]string, 0, len(defaultTrustedProxies)+len(extra))
	patterns = append(patterns, defaultTrustedProxies...)
	patterns = append(patterns, extra...)

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if re, err := regexp.Compile("(?i)" + p); err == nil {
			compiled = append(compiled, re)
		} else if re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(p)); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

// ContextFromRequest builds the Castle request context (headers, ip, library)
// from an incoming HTTP request, honouring the client's header allow/deny and
// IP-resolution configuration. Pass the result as the "context" field of a Risk,
// Filter, or Log call.
func (c *Castle) ContextFromRequest(r *http.Request) Params {
	return Params{
		"headers": c.extractHeaders(r),
		"ip":      c.extractIP(r),
		"library": Params{
			"name":    libraryName,
			"version": Version,
		},
	}
}

func (c *Castle) extractHeaders(r *http.Request) Params {
	headers := make(Params, len(r.Header))
	useAllowList := len(c.config.allowList) > 0

	for name, values := range r.Header {
		if len(values) == 0 {
			continue
		}
		canonical := http.CanonicalHeaderKey(name)
		value := values[0]

		switch {
		case canonical == "User-Agent":
			headers[canonical] = value
		case alwaysScrubbedHeaders[canonical]:
			headers[canonical] = true
		case containsHeader(c.config.denyList, canonical):
			headers[canonical] = true
		case useAllowList:
			if containsHeader(c.config.allowList, canonical) {
				headers[canonical] = value
			} else {
				headers[canonical] = true
			}
		default:
			headers[canonical] = value
		}
	}
	return headers
}

func containsHeader(list []string, canonical string) bool {
	for _, h := range list {
		if http.CanonicalHeaderKey(h) == canonical {
			return true
		}
	}
	return false
}

func (c *Castle) extractIP(r *http.Request) string {
	ipHeaders := c.config.ipHeaders
	if len(ipHeaders) == 0 {
		ipHeaders = defaultIPHeaders
	}

	firstSeen := ""
	for _, header := range ipHeaders {
		raw := c.rawIPSource(r, header)
		if raw == "" {
			continue
		}

		chain := splitIPChain(raw)
		if len(chain) == 0 {
			continue
		}
		if firstSeen == "" {
			firstSeen = chain[0]
		}

		if strings.EqualFold(header, "X-Forwarded-For") && c.config.trustedProxyDepth > 0 {
			if c.config.trustedProxyDepth >= len(chain) {
				continue
			}
			chain = chain[:len(chain)-c.config.trustedProxyDepth]
		}

		if c.config.trustProxyChain {
			return chain[0]
		}

		if candidate := c.lastUntrusted(chain); candidate != "" {
			return candidate
		}
	}

	if firstSeen != "" {
		return firstSeen
	}
	return remoteAddrIP(r)
}

func (c *Castle) rawIPSource(r *http.Request, header string) string {
	if strings.EqualFold(header, "Remote-Addr") {
		return remoteAddrIP(r)
	}
	return r.Header.Get(header)
}

func (c *Castle) lastUntrusted(chain []string) string {
	for i := len(chain) - 1; i >= 0; i-- {
		if !c.isTrustedProxy(chain[i]) {
			return chain[i]
		}
	}
	return ""
}

func (c *Castle) isTrustedProxy(ip string) bool {
	for _, re := range c.config.trustedProxyRes {
		if re.MatchString(ip) {
			return true
		}
	}
	return false
}

func splitIPChain(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	chain := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			chain = append(chain, trimmed)
		}
	}
	return chain
}

func remoteAddrIP(r *http.Request) string {
	if r.RemoteAddr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
