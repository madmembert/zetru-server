// Package service implements GET /internal/v1/age (docs/server-internal-api.md): domain age via
// RDAP with a 30-day cache on the lookup-cache volume.
package service

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"zetru.app/lookup/internal/rdap"
)

// Cache lifetimes.
const (
	TTL      = 30 * 24 * time.Hour // ok and unknown results (§13.2, §14.2)
	ErrorTTL = 10 * time.Minute    // failed lookups are retried after this
	// BootstrapMaxAge: a cached bootstrap older than this is not used.
	BootstrapMaxAge = 30 * 24 * time.Hour
	requestBudget   = 2800 * time.Millisecond // the caller gives up after 3 s

	// Cache and concurrency bounds for a 128 MB container (GO-15). They hold at insert time, not
	// only when the cache is saved.
	DefaultMaxEntries    = 100_000
	DefaultMaxKeyBytes   = 16 << 20 // bytes of domain names in the cache
	DefaultMaxConcurrent = 32       // age lookups in progress; more get 503 busy
)

// Entry is a cached result: lookup-cache domain → {registered_on|null, fetched_at} (§13.2).
type Entry struct {
	RegisteredOn *int64 `json:"r"`
	Status       string `json:"s"`
	FetchedAt    int64  `json:"f"`
}

// Response is the JSON body of GET /internal/v1/age.
type Response struct {
	Domain       string `json:"domain"`
	RegisteredOn *int64 `json:"registered_on"`
	Status       string `json:"status"`
	Source       string `json:"source"`
}

// Options configure a Service.
type Options struct {
	CacheDir     string
	HTTP         *http.Client
	Limiter      *rdap.HostLimiter
	Supplement   rdap.Supplement
	BootstrapURL string
	Now          func() time.Time
	Log          *slog.Logger

	MaxEntries    int // default DefaultMaxEntries
	MaxKeyBytes   int // default DefaultMaxKeyBytes
	MaxConcurrent int // default DefaultMaxConcurrent
}

// Service answers age lookups.
type Service struct {
	opt    Options
	client *rdap.Client

	bmu       sync.RWMutex
	bootstrap *rdap.Bootstrap
	bfetched  time.Time

	cmu      sync.Mutex
	entries  map[string]Entry
	keyBytes int // sum of len(domain) over entries
	dirty    bool

	sem chan struct{} // bounds concurrent age lookups

	fmu      sync.Mutex
	inflight map[string]*call
}

type call struct {
	done chan struct{}
	resp Response
}

// New creates the service and loads the cache and a cached bootstrap from CacheDir.
func New(opt Options) (*Service, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Log == nil {
		opt.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opt.BootstrapURL == "" {
		opt.BootstrapURL = rdap.BootstrapURL
	}
	if opt.MaxEntries <= 0 {
		opt.MaxEntries = DefaultMaxEntries
	}
	if opt.MaxKeyBytes <= 0 {
		opt.MaxKeyBytes = DefaultMaxKeyBytes
	}
	if opt.MaxConcurrent <= 0 {
		opt.MaxConcurrent = DefaultMaxConcurrent
	}
	s := &Service{opt: opt, entries: map[string]Entry{}, inflight: map[string]*call{}, sem: make(chan struct{}, opt.MaxConcurrent)}
	s.client = &rdap.Client{HTTP: opt.HTTP, Limiter: opt.Limiter, MaxBody: 512 << 10, Now: opt.Now, KnownHosts: s.knownHost}
	if opt.CacheDir != "" {
		path := filepath.Join(opt.CacheDir, "rdap-cache.json")
		// A moved-aside copy from earlier versions holds queried domains beyond the 30-day
		// retention of §14.2 (GO-17); a corrupt cache is deleted, not moved aside.
		if err := os.Remove(path + ".corrupt"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if f, err := os.Open(path); err == nil {
			err = s.load(bufio.NewReaderSize(f, 64<<10))
			_ = f.Close()
			if err != nil {
				s.entries, s.keyBytes = map[string]Entry{}, 0
				if err := os.Remove(path); err != nil {
					return nil, err
				}
			}
		}
		if data, err := os.ReadFile(filepath.Join(opt.CacheDir, "bootstrap.json")); err == nil {
			var stored struct {
				FetchedAt int64           `json:"fetched_at"`
				Data      json.RawMessage `json:"data"`
			}
			if json.Unmarshal(data, &stored) == nil && opt.Now().Sub(time.Unix(stored.FetchedAt, 0)) < BootstrapMaxAge {
				if b, err := rdap.ParseBootstrap(stored.Data); err == nil {
					s.bootstrap, s.bfetched = b, time.Unix(stored.FetchedAt, 0)
				}
			}
		}
	}
	s.prune()
	return s, nil
}

func (s *Service) knownHost(host string) bool {
	s.bmu.RLock()
	defer s.bmu.RUnlock()
	if s.bootstrap != nil && s.bootstrap.HasHost(host) {
		return true
	}
	for tld := range s.opt.Supplement {
		bases, _, _ := s.opt.Supplement.Bases(tld)
		for _, b := range bases {
			if b.Hostname() == host {
				return true
			}
		}
	}
	return false
}

// RefreshBootstrap downloads the IANA bootstrap and stores it in the cache directory.
func (s *Service) RefreshBootstrap(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opt.BootstrapURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "zetru-lookup/1.0")
	client := *s.opt.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("bootstrap: unexpected status")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil || len(data) > 4<<20 {
		return errors.New("bootstrap: read failed or too large")
	}
	b, err := rdap.ParseBootstrap(data)
	if err != nil {
		return err
	}
	now := s.opt.Now()
	s.bmu.Lock()
	s.bootstrap, s.bfetched = b, now
	s.bmu.Unlock()
	if s.opt.CacheDir != "" {
		stored, _ := json.Marshal(struct {
			FetchedAt int64           `json:"fetched_at"`
			Data      json.RawMessage `json:"data"`
		}{now.Unix(), data})
		return writeAtomic(filepath.Join(s.opt.CacheDir, "bootstrap.json"), func(w *bufio.Writer) error {
			_, err := w.Write(stored)
			return err
		})
	}
	return nil
}

// BootstrapAge returns the age of the loaded bootstrap and whether one is loaded.
func (s *Service) BootstrapAge() (time.Duration, bool) {
	s.bmu.RLock()
	defer s.bmu.RUnlock()
	if s.bootstrap == nil {
		return 0, false
	}
	return s.opt.Now().Sub(s.bfetched), true
}

func (s *Service) fresh(e Entry) bool {
	ttl := TTL
	if e.Status == rdap.StatusError {
		ttl = ErrorTTL
	}
	return s.opt.Now().Sub(time.Unix(e.FetchedAt, 0)) < ttl
}

// Age returns the registration date of domain (already normalised).
func (s *Service) Age(ctx context.Context, domain string) Response {
	s.cmu.Lock()
	if e, ok := s.entries[domain]; ok && s.fresh(e) {
		s.cmu.Unlock()
		return Response{Domain: domain, RegisteredOn: e.RegisteredOn, Status: e.Status, Source: "cache"}
	}
	s.cmu.Unlock()

	// One upstream query per domain at a time; concurrent callers share its result.
	s.fmu.Lock()
	if c, ok := s.inflight[domain]; ok {
		s.fmu.Unlock()
		select {
		case <-c.done:
			return c.resp
		case <-ctx.Done():
			return Response{Domain: domain, Status: rdap.StatusError, Source: "rdap"}
		}
	}
	c := &call{done: make(chan struct{})}
	s.inflight[domain] = c
	s.fmu.Unlock()

	c.resp = s.resolve(ctx, domain)
	s.fmu.Lock()
	delete(s.inflight, domain)
	s.fmu.Unlock()
	close(c.done)
	return c.resp
}

func (s *Service) resolve(ctx context.Context, domain string) Response {
	tld := domain[strings.LastIndexByte(domain, '.')+1:]
	resp := Response{Domain: domain, Status: rdap.StatusError, Source: "rdap"}
	bases, noDate, supplemented := s.opt.Supplement.Bases(tld)
	switch {
	case supplemented && noDate:
		resp.Status = rdap.StatusUnknown // the registry publishes no date; nothing is queried
	default:
		if !supplemented {
			s.bmu.RLock()
			b := s.bootstrap
			s.bmu.RUnlock()
			if b == nil {
				return resp // no bootstrap yet: error, not cached
			}
			bases = b.Lookup(tld)
		}
		if len(bases) == 0 {
			resp.Status = rdap.StatusUnknown // no RDAP service for this TLD
			break
		}
		for i, base := range bases {
			if i == 2 {
				break
			}
			r := s.client.Registration(ctx, base, domain)
			resp.Status = r.Status
			if r.Status == rdap.StatusOK {
				on := r.RegisteredOn
				resp.RegisteredOn = &on
			}
			if r.Transient {
				return resp // not cached: says nothing about the registry
			}
			if r.Status != rdap.StatusError || ctx.Err() != nil {
				break
			}
		}
	}
	s.cmu.Lock()
	s.insertLocked(domain, Entry{RegisteredOn: resp.RegisteredOn, Status: resp.Status, FetchedAt: s.opt.Now().Unix()})
	s.cmu.Unlock()
	return resp
}

// insertLocked adds or replaces an entry. A new entry that would exceed a cap first triggers a
// prune, which drops expired entries and then the oldest down to 90 % of the caps; its O(n log n)
// cost is spread over the inserts that the freed 10 % allow (GO-15).
func (s *Service) insertLocked(domain string, e Entry) {
	if _, ok := s.entries[domain]; !ok {
		if len(s.entries)+1 > s.opt.MaxEntries || s.keyBytes+len(domain) > s.opt.MaxKeyBytes {
			s.pruneLocked(true)
		}
		s.keyBytes += len(domain)
	}
	s.entries[domain] = e
	s.dirty = true
}

func (s *Service) prune() {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	s.pruneLocked(false)
}

// pruneLocked drops expired entries and, when a cap is exceeded (or room is needed for one more
// entry), the oldest entries down to 90 % of the caps.
func (s *Service) pruneLocked(makeRoom bool) {
	for d, e := range s.entries {
		if !s.fresh(e) {
			s.deleteLocked(d)
		}
	}
	slack := 0
	if makeRoom {
		slack = 1
	}
	if len(s.entries)+slack <= s.opt.MaxEntries && s.keyBytes+slack*253 <= s.opt.MaxKeyBytes {
		return
	}
	type aged struct {
		d string
		f int64
	}
	all := make([]aged, 0, len(s.entries))
	for d, e := range s.entries {
		all = append(all, aged{d, e.FetchedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].f < all[j].f })
	for _, a := range all {
		if len(s.entries) <= s.opt.MaxEntries*9/10 && s.keyBytes <= s.opt.MaxKeyBytes*9/10 {
			break
		}
		s.deleteLocked(a.d)
	}
}

func (s *Service) deleteLocked(domain string) {
	if _, ok := s.entries[domain]; ok {
		delete(s.entries, domain)
		s.keyBytes -= len(domain)
		s.dirty = true
	}
}

// load reads a cache file (a JSON object domain -> Entry) entry by entry; invalid domain names are
// skipped and the caps apply while loading.
func (s *Service) load(r io.Reader) error {
	dec := json.NewDecoder(r)
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("cache: not a JSON object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		domain, _ := tok.(string)
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return err
		}
		if d, err := rdap.NormalizeDomain(domain); err == nil && d == domain && s.fresh(e) {
			s.insertLocked(domain, e) // New has not published the service yet: no lock needed
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return errors.New("cache: truncated")
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("cache: trailing data")
	}
	s.dirty = false
	return nil
}

// Save prunes and writes the cache if it changed. Only a list of the entries is copied under the
// lock; the JSON is streamed to the file.
func (s *Service) Save() error {
	type cached struct {
		domain string
		e      Entry
	}
	s.cmu.Lock()
	s.pruneLocked(false)
	if !s.dirty || s.opt.CacheDir == "" {
		s.cmu.Unlock()
		return nil
	}
	snap := make([]cached, 0, len(s.entries))
	for d, e := range s.entries {
		snap = append(snap, cached{d, e})
	}
	s.dirty = false
	s.cmu.Unlock()
	err := writeAtomic(filepath.Join(s.opt.CacheDir, "rdap-cache.json"), func(w *bufio.Writer) error {
		_ = w.WriteByte('{')
		for i, c := range snap {
			if i > 0 {
				_ = w.WriteByte(',')
			}
			k, _ := json.Marshal(c.domain)
			v, _ := json.Marshal(c.e)
			_, _ = w.Write(k)
			_ = w.WriteByte(':')
			if _, err := w.Write(v); err != nil {
				return err
			}
		}
		return w.WriteByte('}')
	})
	if err != nil {
		s.cmu.Lock()
		s.dirty = true
		s.cmu.Unlock()
		return err
	}
	return nil
}

// Len returns the number of cached entries.
func (s *Service) Len() int {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	return len(s.entries)
}

// writeAtomic writes a file via a temporary file, fsync and rename; write fills it through a
// buffered writer.
func writeAtomic(path string, write func(w *bufio.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	bw := bufio.NewWriterSize(tmp, 64<<10)
	if err := write(bw); err != nil {
		tmp.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// --- HTTP ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	data, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]map[string]string{"error": {"code": code, "message": message}})
}

// Handler serves GET /internal/v1/age and GET /healthz. Logs carry endpoint, status and duration
// bucket only, never the domain.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.opt.Now()
		status := s.serve(w, r)
		s.opt.Log.Info("request", "endpoint", endpointName(r), "status", status, "dur", bucket(s.opt.Now().Sub(start)))
	})
}

func endpointName(r *http.Request) string {
	switch r.URL.Path {
	case "/internal/v1/age", "/healthz":
		return r.Method + " " + r.URL.Path
	}
	return "unknown"
}

func bucket(d time.Duration) string {
	switch {
	case d < 100*time.Millisecond:
		return "<100ms"
	case d < time.Second:
		return "<1s"
	case d < 3*time.Second:
		return "<3s"
	}
	return ">=3s"
}

func (s *Service) serve(w http.ResponseWriter, r *http.Request) int {
	switch {
	case r.URL.Path == "/healthz" && r.Method == http.MethodGet:
		age, ok := s.BootstrapAge()
		writeJSON(w, 200, map[string]any{"status": "ok", "bootstrap": ok, "bootstrap_age_s": int64(age.Seconds()), "cached": s.Len()})
		return 200
	case r.URL.Path == "/internal/v1/age" && r.Method == http.MethodGet:
		q, err := url.ParseQuery(r.URL.RawQuery)
		values := q["domain"]
		if err != nil || len(values) != 1 {
			writeError(w, 400, "bad_request", "Exactly one domain parameter is required.")
			return 400
		}
		domain, err := rdap.NormalizeDomain(values[0])
		if err != nil {
			writeError(w, 400, "bad_request", "The domain is not a valid domain name.")
			return 400
		}
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			writeError(w, 503, "busy", "Too many lookups in progress.")
			return 503
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestBudget)
		defer cancel()
		writeJSON(w, 200, s.Age(ctx, domain))
		return 200
	}
	writeError(w, 404, "not_found", "Not found.")
	return 404
}
