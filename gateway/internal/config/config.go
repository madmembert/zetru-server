// Package config holds the operator configuration written by `init` (server.json) and the
// size profiles of concept §3.5 and §11.4.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"zetru.app/gateway/internal/fsutil"
)

const fileName = "server.json"

// Server is the operator configuration (gateway-data/server.json).
type Server struct {
	Version int      `json:"version"`
	Name    string   `json:"name"`  // display name shown in the app's consent screen (≤ 40 chars)
	URLs    []string `json:"urls"`  // 1–3 base URLs the app tries in order
	Trust   string   `json:"trust"` // "pin_only" (self-hosted)
}

// Validate checks the configuration against the pairing payload rules (§4.2).
func (s Server) Validate() error {
	if err := ValidateName(s.Name); err != nil {
		return err
	}
	if len(s.URLs) < 1 || len(s.URLs) > 3 {
		return errors.New("between 1 and 3 URLs are required")
	}
	for _, raw := range s.URLs {
		if err := ValidateURL(raw); err != nil {
			return err
		}
	}
	if s.Trust != "pin_only" {
		return errors.New(`trust must be "pin_only" for a self-hosted server`)
	}
	return nil
}

// ValidateName checks the server display name: 1–40 characters, no control characters.
func ValidateName(name string) error {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 40 {
		return errors.New("the server name must be 1-40 characters")
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return errors.New("the server name must not contain control characters")
		}
	}
	return nil
}

// ValidateURL checks one base URL: https, a host, no user info, query or fragment.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid URL %q: use https://host[:port]", raw)
	}
	if u.Path != "" && u.Path != "/" {
		return fmt.Errorf("invalid URL %q: the base URL must not have a path", raw)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid port in %q", raw)
		}
	}
	return nil
}

// Hosts returns the host names and IP addresses of the URLs (for certificate SANs).
func (s Server) Hosts() []string {
	var out []string
	seen := map[string]bool{}
	for _, raw := range s.URLs {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		h := strings.Trim(u.Hostname(), "[]")
		if ip := net.ParseIP(h); ip != nil {
			h = ip.String()
		}
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

// Load reads server.json from dir.
func Load(dir string) (Server, error) {
	var s Server
	data, err := os.ReadFile(filepath.Join(dir, fileName))
	if err != nil {
		return s, fmt.Errorf("server configuration: %w (run init first)", err)
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return s, fmt.Errorf("server configuration: %w", err)
	}
	if s.Version != 1 {
		return s, fmt.Errorf("server configuration: unsupported version %d", s.Version)
	}
	return s, s.Validate()
}

// Save writes server.json to dir after validation.
func Save(dir string, s Server) error {
	s.Version = 1
	if err := s.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, fileName), data, 0o600)
}

// Profile holds the size-dependent defaults (§3.5, §11.4).
type Profile struct {
	Name              string
	AnalyzePerMinute  int   // analyze requests per device and minute
	DailyQuota        int   // analyze requests per device and UTC day
	URLCheckPerMinute int   // url/check requests per device and minute
	OtherPerMinute    int   // all other signed endpoints, per device and minute (not in §11.4)
	ReportsPerDay     int   // reports per device and day (§16 #18)
	Workers, Queue    int   // analyzer concurrency and queue (the gateway admits Workers+Queue)
	BodyBudget        int64 // bytes of analyze request bodies held in memory at once
	MaxMailBytes      int   // default maximum mail size
}

// ProfileFor returns the defaults of the "pi" or "vps" profile.
func ProfileFor(name string) (Profile, error) {
	switch name {
	case "", "pi":
		return Profile{Name: "pi", AnalyzePerMinute: 30, DailyQuota: 3000, URLCheckPerMinute: 60, OtherPerMinute: 30,
			ReportsPerDay: 50, Workers: 2, Queue: 8, BodyBudget: 96 << 20, MaxMailBytes: 20 << 20}, nil
	case "vps":
		return Profile{Name: "vps", AnalyzePerMinute: 60, DailyQuota: 10000, URLCheckPerMinute: 60, OtherPerMinute: 30,
			ReportsPerDay: 50, Workers: 4, Queue: 32, BodyBudget: 200 << 20, MaxMailBytes: 20 << 20}, nil
	}
	return Profile{}, fmt.Errorf("unknown profile %q (pi or vps)", name)
}
