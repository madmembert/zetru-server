// Package rdap queries domain registration dates over RDAP (RFC 9082/9083) using the IANA
// bootstrap registry (RFC 9224) plus a supplementary map for TLDs the bootstrap does not cover.
//
// Network rules (concept §3.2): HTTPS only, port 443 only, public addresses only, redirects only to
// hosts that are themselves listed as RDAP servers, bounded response sizes, per-host rate limits.
package rdap

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Status of a lookup, as returned by the internal API.
const (
	StatusOK      = "ok"
	StatusUnknown = "unknown"
	StatusError   = "error"
)

// BootstrapURL is the IANA RDAP bootstrap file for domain names.
const BootstrapURL = "https://data.iana.org/rdap/dns.json"

// Bootstrap maps TLDs to RDAP base URLs.
type Bootstrap struct {
	Publication string
	services    map[string][]*url.URL
	hosts       map[string]bool
}

// ParseBootstrap parses an RFC 9224 bootstrap file; only https base URLs are kept.
func ParseBootstrap(data []byte) (*Bootstrap, error) {
	var raw struct {
		Version     string       `json:"version"`
		Publication string       `json:"publication"`
		Services    [][][]string `json:"services"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("bootstrap: %w", err)
	}
	if raw.Version != "1.0" || len(raw.Services) == 0 || len(raw.Services) > 10_000 {
		return nil, errors.New("bootstrap: unexpected version or size")
	}
	b := &Bootstrap{Publication: raw.Publication, services: map[string][]*url.URL{}, hosts: map[string]bool{}}
	for _, svc := range raw.Services {
		if len(svc) != 2 {
			return nil, errors.New("bootstrap: malformed service entry")
		}
		var bases []*url.URL
		for _, raw := range svc[1] {
			u, err := parseBase(raw)
			if err != nil {
				continue // http:// entries and garbage are skipped
			}
			bases = append(bases, u)
		}
		if len(bases) == 0 {
			continue
		}
		for _, tld := range svc[0] {
			tld = strings.ToLower(strings.TrimSpace(tld))
			if !validLabel(tld) {
				continue
			}
			b.services[tld] = bases
		}
		for _, u := range bases {
			b.hosts[u.Hostname()] = true
		}
	}
	if len(b.services) == 0 {
		return nil, errors.New("bootstrap: no usable services")
	}
	return b, nil
}

func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("not an https base URL")
	}
	if p := u.Port(); p != "" && p != "443" {
		return nil, errors.New("only port 443")
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	return u, nil
}

// Lookup returns the base URLs for a TLD.
func (b *Bootstrap) Lookup(tld string) []*url.URL { return b.services[tld] }

// TLDs returns the number of covered TLDs.
func (b *Bootstrap) TLDs() int { return len(b.services) }

// HasHost reports whether host serves RDAP for some TLD.
func (b *Bootstrap) HasHost(host string) bool { return b.hosts[host] }

// SupplementEntry covers a TLD missing from (or overriding) the bootstrap.
type SupplementEntry struct {
	URLs               []string `json:"urls"`
	NoRegistrationDate bool     `json:"no_registration_date"`
	Note               string   `json:"note"`
}

// Supplement is the supplementary RDAP map, keyed by TLD.
type Supplement map[string]SupplementEntry

//go:embed supplement.json
var supplementJSON []byte

// DefaultSupplement returns the map shipped with the binary.
func DefaultSupplement() (Supplement, error) { return ParseSupplement(supplementJSON) }

// ParseSupplement parses and validates a supplementary map.
func ParseSupplement(data []byte) (Supplement, error) {
	var s Supplement
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("supplement: %w", err)
	}
	for tld, e := range s {
		if !validLabel(tld) || tld != strings.ToLower(tld) {
			return nil, fmt.Errorf("supplement: invalid TLD %q", tld)
		}
		for _, raw := range e.URLs {
			if _, err := parseBase(raw); err != nil {
				return nil, fmt.Errorf("supplement %s: %w", tld, err)
			}
		}
		if !e.NoRegistrationDate && len(e.URLs) == 0 {
			return nil, fmt.Errorf("supplement %s: needs urls or no_registration_date", tld)
		}
	}
	return s, nil
}

// Bases returns the base URLs for tld, whether the registry publishes no registration date, and
// the known RDAP hosts (for the redirect policy).
func (s Supplement) Bases(tld string) ([]*url.URL, bool, bool) {
	e, ok := s[tld]
	if !ok {
		return nil, false, false
	}
	var out []*url.URL
	for _, raw := range e.URLs {
		if u, err := parseBase(raw); err == nil {
			out = append(out, u)
		}
	}
	return out, e.NoRegistrationDate, true
}

// validLabel checks one LDH label (A-labels allowed).
func validLabel(l string) bool {
	if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// NormalizeDomain lowercases and validates a domain name: at least two LDH labels, at most 253
// characters, an alphabetic or A-label TLD (so no IP literals).
func NormalizeDomain(d string) (string, error) {
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	if len(d) < 3 || len(d) > 253 {
		return "", errors.New("invalid domain")
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", errors.New("invalid domain")
	}
	for _, l := range labels {
		if !validLabel(l) {
			return "", errors.New("invalid domain")
		}
	}
	tld := labels[len(labels)-1]
	if !strings.HasPrefix(tld, "xn--") {
		for i := 0; i < len(tld); i++ {
			if tld[i] < 'a' || tld[i] > 'z' {
				return "", errors.New("invalid domain")
			}
		}
	}
	return d, nil
}

// HostLimiter is a token bucket per RDAP host plus a back-off after HTTP 429.
type HostLimiter struct {
	Rate    float64 // tokens per second
	Burst   float64
	MaxWait time.Duration
	Now     func() time.Time

	mu      sync.Mutex
	tokens  map[string]float64
	last    map[string]time.Time
	backoff map[string]time.Time
}

// ErrRateLimited means the per-host budget is exhausted or the host asked us to back off.
var ErrRateLimited = errors.New("rdap: rate limited")

// NewHostLimiter returns a limiter with rate tokens/s, burst and the longest acceptable wait.
func NewHostLimiter(rate, burst float64, maxWait time.Duration) *HostLimiter {
	return &HostLimiter{Rate: rate, Burst: burst, MaxWait: maxWait, Now: time.Now,
		tokens: map[string]float64{}, last: map[string]time.Time{}, backoff: map[string]time.Time{}}
}

// Wait takes a token for host, sleeping up to MaxWait (and never past ctx's deadline).
func (l *HostLimiter) Wait(ctx context.Context, host string) error {
	now := l.Now()
	l.mu.Lock()
	if until, ok := l.backoff[host]; ok {
		if now.Before(until) {
			l.mu.Unlock()
			return ErrRateLimited
		}
		delete(l.backoff, host)
	}
	tokens, seen := l.tokens[host]
	if !seen {
		tokens = l.Burst
	} else {
		tokens += now.Sub(l.last[host]).Seconds() * l.Rate
		if tokens > l.Burst {
			tokens = l.Burst
		}
	}
	tokens-- // reserve
	wait := time.Duration(0)
	if tokens < 0 {
		wait = time.Duration(-tokens / l.Rate * float64(time.Second))
	}
	deadline, hasDeadline := ctx.Deadline() // real time, unlike l.Now (which tests may fake)
	if wait > l.MaxWait || (hasDeadline && wait > time.Until(deadline)) {
		l.mu.Unlock()
		return ErrRateLimited
	}
	l.tokens[host], l.last[host] = tokens, now
	l.mu.Unlock()
	if wait == 0 {
		return nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// BackOff stops requests to host for d (capped at 15 minutes).
func (l *HostLimiter) BackOff(host string, d time.Duration) {
	if d <= 0 {
		d = time.Minute
	}
	if d > 15*time.Minute {
		d = 15 * time.Minute
	}
	l.mu.Lock()
	l.backoff[host] = l.Now().Add(d)
	l.mu.Unlock()
}

// publicIP reports whether ip is a globally routable unicast address.
func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 0.0.0.0/8, 100.64.0.0/10 (CGNAT), 192.0.0.0/24, 198.18.0.0/15, 240.0.0.0/4
		switch {
		case v4[0] == 0, v4[0] == 100 && v4[1]&0xc0 == 64, v4[0] == 192 && v4[1] == 0 && v4[2] == 0,
			v4[0] == 198 && v4[1]&0xfe == 18, v4[0] >= 240:
			return false
		}
	}
	return true
}

// guardedDialControl refuses connections to anything but public addresses on port 443.
func guardedDialControl(_, address string, _ syscall.RawConn) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if port != "443" {
		return errors.New("rdap: only port 443 is allowed")
	}
	if !publicIP(net.ParseIP(host)) {
		return errors.New("rdap: refusing a non-public address")
	}
	return nil
}

// NewHTTPClient returns the client used in production: HTTPS on port 443 to public addresses only,
// no proxy, TLS ≥ 1.2 with the system roots, short timeouts.
func NewHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 2 * time.Second, Control: guardedDialControl}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
	}}
}

// Client performs RDAP domain queries.
type Client struct {
	HTTP       *http.Client
	Limiter    *HostLimiter
	MaxBody    int64
	KnownHosts func(host string) bool // redirect targets must be RDAP hosts
	Now        func() time.Time
}

// Result of one registry query.
type Result struct {
	Status       string
	RegisteredOn int64 // Unix seconds, valid when Status is ok
	// Transient marks errors that say nothing about the registry (our own rate limit, the
	// caller's deadline); such results are not cached.
	Transient bool
}

// Registration asks one RDAP base URL for the registration date of domain.
func (c *Client) Registration(ctx context.Context, base *url.URL, domain string) Result {
	if err := c.Limiter.Wait(ctx, base.Hostname()); err != nil {
		return Result{Status: StatusError, Transient: true}
	}
	target := base.ResolveReference(&url.URL{Path: "domain/" + domain})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return Result{Status: StatusError}
	}
	req.Header.Set("Accept", "application/rdap+json, application/json;q=0.9")
	req.Header.Set("User-Agent", "zetru-lookup/1.0")
	client := *c.HTTP
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 || r.URL.Scheme != "https" || (r.URL.Port() != "" && r.URL.Port() != "443") ||
			c.KnownHosts == nil || !c.KnownHosts(r.URL.Hostname()) {
			return errors.New("rdap: redirect refused")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Status: StatusError, Transient: ctx.Err() != nil}
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return Result{Status: StatusUnknown}
	case resp.StatusCode == http.StatusTooManyRequests:
		retry, _ := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After")))
		c.Limiter.BackOff(base.Hostname(), time.Duration(retry)*time.Second)
		return Result{Status: StatusError}
	case resp.StatusCode != http.StatusOK:
		return Result{Status: StatusError}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.MaxBody+1))
	if err != nil || int64(len(data)) > c.MaxBody {
		return Result{Status: StatusError}
	}
	return parseDomainResponse(data, c.Now())
}

// parseDomainResponse extracts the "registration" event (RFC 9083 §4.5).
func parseDomainResponse(data []byte, now time.Time) Result {
	var obj struct {
		ObjectClassName string `json:"objectClassName"`
		Events          []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return Result{Status: StatusError}
	}
	if obj.ObjectClassName != "" && obj.ObjectClassName != "domain" {
		return Result{Status: StatusError}
	}
	for _, ev := range obj.Events {
		if ev.Action != "registration" {
			continue
		}
		t, ok := parseDate(ev.Date)
		earliest := time.Date(1985, 1, 1, 0, 0, 0, 0, time.UTC)
		if !ok || t.Before(earliest) || t.After(now.Add(24*time.Hour)) {
			return Result{Status: StatusUnknown}
		}
		return Result{Status: StatusOK, RegisteredOn: t.Unix()}
	}
	return Result{Status: StatusUnknown} // e.g. DENIC publishes no registration event
}

func parseDate(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, strings.TrimSpace(s)); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
