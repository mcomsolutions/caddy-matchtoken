package caddy_matchtoken

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"golang.org/x/net/idna"
)

// set XCADDY_DEBUG=1
// xcaddy build --with github.com/mcomsolutions/caddy-matchtoken=C:\java\eclipse\vertx\caddy-matchtoken

type matchToken struct {
	Prefix string   `json:"tokenprefix"`
	Host   []string `json:"host"`
}

func init() {
	caddy.RegisterModule(matchToken{})
}

func (m *matchToken) Provision(ctx caddy.Context) error {
	// check for duplicates; they are nonsensical and reduce efficiency
	// (we could just remove them, but the user should know their config is erroneous)
	seen := make(map[string]int, len(m.Host))
	for i, host := range m.Host {
		asciiHost, err := idna.ToASCII(host)
		if err != nil {
			return fmt.Errorf("converting hostname '%s' to ASCII: %v", host, err)
		}
		if asciiHost != host {
			m.Host[i] = asciiHost
		}
		normalizedHost := strings.ToLower(asciiHost)
		if firstI, ok := seen[normalizedHost]; ok {
			return fmt.Errorf("host at index %d is repeated at index %d: %s", firstI, i, host)
		}
		seen[normalizedHost] = i
	}

	if m.large() {
		// sort the slice lexicographically, grouping "fuzzy" entries (wildcards and placeholders)
		// at the front of the list; this allows us to use binary search for exact matches, which
		// we have seen from experience is the most common kind of value in large lists; and any
		// other kinds of values (wildcards and placeholders) are grouped in front so the linear
		// search should find a match fairly quickly
		sort.Slice(m.Host, func(i, j int) bool {
			iInexact, jInexact := m.fuzzy(m.Host[i]), m.fuzzy(m.Host[j])
			if iInexact && !jInexact {
				return true
			}
			if !iInexact && jInexact {
				return false
			}
			return m.Host[i] < m.Host[j]
		})
	}

	return nil
}

// CaddyModule returns the Caddy module information.
func (matchToken) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.matchToken",
		New: func() caddy.Module { return new(matchToken) },
	}
}

/**
 * Verifico que el token que me mandan tenga el prefijo especificado, si fuera el caso, entonces valido el host. Las 2 condiciones se deben de cumplir para regresar verdadero
 */
func (m *matchToken) Match(req *http.Request) bool {
	token := req.Header.Get("token")
	if len(token) == 0 {
		cookie, err := req.Cookie("token")
		if err != nil {
			return false
		}
		token = cookie.Value
	}
	if !strings.HasPrefix(token, m.Prefix) {
		return false
	}
	/********************************************************************************************************/
	reqHost, _, err := net.SplitHostPort(req.Host)
	if err != nil {
		// OK; probably didn't have a port
		reqHost = req.Host

		// make sure we strip the brackets from IPv6 addresses
		reqHost = strings.TrimPrefix(reqHost, "[")
		reqHost = strings.TrimSuffix(reqHost, "]")
	}

	if m.large() {
		// fast path: locate exact match using binary search (about 100-1000x faster for large lists)
		pos := sort.Search(len(m.Host), func(i int) bool {
			if m.fuzzy(m.Host[i]) {
				return false
			}
			return m.Host[i] >= reqHost
		})
		if pos < len(m.Host) && m.Host[pos] == reqHost {
			return true
		}
	}

	repl := req.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

outer:
	for _, host := range m.Host {
		// fast path: if matcher is large, we already know we don't have an exact
		// match, so we're only looking for fuzzy match now, which should be at the
		// front of the list; if we have reached a value that is not fuzzy, there
		// will be no match and we can short-circuit for efficiency
		if m.large() && !m.fuzzy(host) {
			break
		}

		host = repl.ReplaceAll(host, "")
		if strings.Contains(host, "*") {
			patternParts := strings.Split(host, ".")
			incomingParts := strings.Split(reqHost, ".")
			if len(patternParts) != len(incomingParts) {
				continue
			}
			for i := range patternParts {
				if patternParts[i] == "*" {
					continue
				}
				if !strings.EqualFold(patternParts[i], incomingParts[i]) {
					continue outer
				}
			}
			return true
		} else if strings.EqualFold(reqHost, host) {
			return true
		}
	}
	return false
}

func (matchToken) fuzzy(h string) bool { return strings.ContainsAny(h, "{*") }
func (m matchToken) large() bool       { return len(m.Host) > 100 }
