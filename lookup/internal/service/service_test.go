package service

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"zetru.app/lookup/internal/rdap"
)

// memListener is an in-memory listener (the development sandbox forbids binding ports).
type memListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMemListener() *memListener {
	return &memListener{conns: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *memListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *memListener) Addr() net.Addr { return &net.TCPAddr{} }
func (l *memListener) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	s, c := net.Pipe()
	select {
	case l.conns <- s:
		return c, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

type fakeRegistry struct {
	calls sync.Map // path -> *int64
	delay time.Duration
}

func (f *fakeRegistry) count(path string) int64 {
	v, ok := f.calls.Load(path)
	if !ok {
		return 0
	}
	return atomic.LoadInt64(v.(*int64))
}

const bootstrapJSON = `{"version":"1.0","publication":"2026-11-01T00:00:00Z","services":[
 [["com","net"],["https://rdap.test/v1/"]],
 [["org"],["http://insecure.test/"]],
 [["de"],["https://rdap.denic.test/"]],
 [["example"],["https://redir.test/"]]]}`

func (f *fakeRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Host + r.URL.Path
	v, _ := f.calls.LoadOrStore(key, new(int64))
	atomic.AddInt64(v.(*int64), 1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	reg := func(date string) {
		w.Header().Set("Content-Type", "application/rdap+json")
		_, _ = w.Write([]byte(`{"objectClassName":"domain","ldhName":"x","events":[{"eventAction":"last changed","eventDate":"2020-01-01T00:00:00Z"},{"eventAction":"registration","eventDate":"` + date + `"}]}`))
	}
	switch key {
	case "data.iana.test/rdap/dns.json":
		_, _ = w.Write([]byte(bootstrapJSON))
	case "rdap.test/v1/domain/example.com", "rdap.test/v1/domain/same.com":
		reg("2001-02-03T04:05:06Z")
	case "rdap.test/v1/domain/fraction.com":
		reg("2026-11-17T10:00:00.123+01:00")
	case "rdap.test/v1/domain/nodate.com":
		_, _ = w.Write([]byte(`{"objectClassName":"domain","events":[{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}]}`))
	case "rdap.test/v1/domain/future.com":
		reg("2099-01-01T00:00:00Z")
	case "rdap.test/v1/domain/broken.com":
		w.WriteHeader(500)
	case "rdap.test/v1/domain/limited.com":
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	case "rdap.test/v1/domain/huge.com":
		_, _ = w.Write(bytes.Repeat([]byte(" "), 600<<10))
	case "rdap.test/v1/domain/redirok.com":
		http.Redirect(w, r, "https://rdap.test/v1/domain/example.com", http.StatusFound)
	case "redir.test/domain/x.example":
		http.Redirect(w, r, "https://evil.test/steal", http.StatusFound)
	case "rdap.test/v1/domain/insecure-redirect.com":
		http.Redirect(w, r, "http://rdap.test/v1/domain/example.com", http.StatusFound)
	default:
		w.WriteHeader(404)
	}
}

type env struct {
	svc   *Service
	reg   *fakeRegistry
	now   time.Time
	mu    sync.Mutex
	log   *bytes.Buffer
	dir   string
	httpc *http.Client
}

func (e *env) clock() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.now
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	e.now = e.now.Add(d)
	e.mu.Unlock()
}

func newEnv(t *testing.T, burst float64) *env {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		DNSNames:  []string{"rdap.test", "data.iana.test", "redir.test", "evil.test", "rdap.denic.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	ln := newMemListener()
	reg := &fakeRegistry{}
	srv := &http.Server{Handler: reg}
	go func() {
		_ = srv.Serve(tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}))
	}()
	t.Cleanup(func() { _ = srv.Close() })

	e := &env{reg: reg, now: time.Unix(1_800_000_000, 0), log: &bytes.Buffer{}, dir: t.TempDir()}
	e.httpc = &http.Client{Transport: &http.Transport{DialContext: ln.Dial, TLSClientConfig: &tls.Config{RootCAs: pool}}}
	limiter := rdap.NewHostLimiter(1, burst, 0)
	limiter.Now = e.clock
	supplement, err := rdap.DefaultSupplement()
	if err != nil {
		t.Fatal(err)
	}
	e.svc, err = New(Options{CacheDir: e.dir, HTTP: e.httpc, Limiter: limiter, Supplement: supplement,
		BootstrapURL: "https://data.iana.test/rdap/dns.json", Now: e.clock, Log: slog.New(slog.NewTextHandler(e.log, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) get(t *testing.T, query string) (int, Response) {
	t.Helper()
	rec := httptest.NewRecorder()
	e.svc.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/internal/v1/age?"+query, nil))
	var r Response
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return rec.Code, r
}

func TestAgeLookups(t *testing.T) {
	e := newEnv(t, 100)
	// No bootstrap yet: error, not cached.
	if _, r := e.get(t, "domain=example.com"); r.Status != "error" || e.svc.Len() != 0 {
		t.Fatalf("without bootstrap: %+v", r)
	}
	if err := e.svc.RefreshBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	code, r := e.get(t, "domain=example.com")
	if code != 200 || r.Status != "ok" || r.Source != "rdap" || r.RegisteredOn == nil || *r.RegisteredOn != 981173106 || r.Domain != "example.com" {
		t.Fatalf("example.com: %d %+v", code, r)
	}
	if _, r := e.get(t, "domain=EXAMPLE.com."); r.Source != "cache" || r.Status != "ok" {
		t.Fatalf("cache: %+v", r)
	}
	if n := e.reg.count("rdap.test/v1/domain/example.com"); n != 1 {
		t.Fatalf("upstream called %d times", n)
	}
	if _, r := e.get(t, "domain=fraction.com"); r.Status != "ok" || *r.RegisteredOn != time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC).Unix() {
		t.Fatalf("fractional date: %+v", r)
	}

	// Unknown cases: .de (supplementary map, no query), TLD without RDAP, http-only bootstrap
	// entry, 404, no registration event, implausible date.
	for _, d := range []string{"beispiel.de", "foo.xyz", "foo.org", "missing.com", "nodate.com", "future.com"} {
		if _, r := e.get(t, "domain="+d); r.Status != "unknown" || r.RegisteredOn != nil {
			t.Errorf("%s: %+v", d, r)
		}
	}
	if e.reg.count("rdap.denic.test/domain/beispiel.de") != 0 {
		t.Fatal(".de was queried although the registry publishes no date")
	}

	// Errors: 500 (cached for 10 minutes), oversize, redirect to a foreign host, redirect to http.
	for _, d := range []string{"broken.com", "huge.com", "x.example", "insecure-redirect.com"} {
		if _, r := e.get(t, "domain="+d); r.Status != "error" {
			t.Errorf("%s: %+v", d, r)
		}
	}
	if e.reg.count("evil.test/steal") != 0 {
		t.Fatal("redirect to a non-RDAP host was followed")
	}
	if _, r := e.get(t, "domain=redirok.com"); r.Status != "ok" {
		t.Fatalf("redirect within RDAP hosts: %+v", r)
	}
	e.get(t, "domain=broken.com")
	if n := e.reg.count("rdap.test/v1/domain/broken.com"); n != 1 {
		t.Fatalf("error not cached: %d calls", n)
	}
	e.advance(ErrorTTL + time.Second)
	e.get(t, "domain=broken.com")
	if n := e.reg.count("rdap.test/v1/domain/broken.com"); n != 2 {
		t.Fatalf("error cached too long: %d calls", n)
	}

	// 429: the host is backed off; other domains on it are not queried meanwhile and the result is
	// not cached.
	e.get(t, "domain=limited.com")
	if _, r := e.get(t, "domain=same.com"); r.Status != "error" || e.reg.count("rdap.test/v1/domain/same.com") != 0 {
		t.Fatalf("back-off ignored: %+v", r)
	}
	e.advance(121 * time.Second)
	if _, r := e.get(t, "domain=same.com"); r.Status != "ok" {
		t.Fatalf("after back-off: %+v", r)
	}

	// 30-day TTL.
	e.advance(TTL)
	if _, r := e.get(t, "domain=example.com"); r.Source != "rdap" {
		t.Fatalf("expired entry served: %+v", r)
	}

	// Invalid input.
	for _, q := range []string{"domain=", "domain=localhost", "domain=1.2.3.4", "domain=a..b", "domain=-a.com",
		"domain=ex%20ample.com", "domain=a.com&domain=b.com", "x=a.com", "domain=" + strings.Repeat("a", 64) + ".com",
		"domain=xn--bcher-kva.example%2F"} {
		if code, _ := e.get(t, q); code != 400 {
			t.Errorf("%q accepted (%d)", q, code)
		}
	}
	if code, r := e.get(t, "domain=xn--bcher-kva.ch"); code != 200 || r.Domain != "xn--bcher-kva.ch" {
		t.Fatalf("A-label rejected: %d", code)
	}

	// Logs never contain the queried domains.
	for _, d := range []string{"example", "broken", "beispiel", "limited"} {
		if strings.Contains(e.log.String(), d) {
			t.Fatalf("log contains %q:\n%s", d, e.log.String())
		}
	}
}

func TestPersistence(t *testing.T) {
	e := newEnv(t, 100)
	if err := e.svc.RefreshBootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.get(t, "domain=example.com")
	if err := e.svc.Save(); err != nil {
		t.Fatal(err)
	}
	again, err := New(Options{CacheDir: e.dir, HTTP: e.httpc, Limiter: rdap.NewHostLimiter(1, 5, 0), Now: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := again.BootstrapAge(); !ok {
		t.Fatal("bootstrap not loaded from the cache directory")
	}
	if r := again.Age(context.Background(), "example.com"); r.Source != "cache" || r.Status != "ok" {
		t.Fatalf("cache not persisted: %+v", r)
	}
}

func TestRateLimitAndSingleFlight(t *testing.T) {
	e := newEnv(t, 2)
	_ = e.svc.RefreshBootstrap(context.Background())
	e.get(t, "domain=example.com")
	e.get(t, "domain=same.com")
	// Burst of 2 per host used up: the third distinct domain is refused locally and not cached.
	if _, r := e.get(t, "domain=fraction.com"); r.Status != "error" || e.reg.count("rdap.test/v1/domain/fraction.com") != 0 {
		t.Fatalf("rate limit: %+v", r)
	}
	e.advance(2 * time.Second)
	if _, r := e.get(t, "domain=fraction.com"); r.Status != "ok" {
		t.Fatalf("transient error was cached: %+v", r)
	}

	f := newEnv(t, 100)
	_ = f.svc.RefreshBootstrap(context.Background())
	f.reg.delay = 100 * time.Millisecond
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := f.svc.Age(context.Background(), "example.com"); r.Status != "ok" {
				t.Error(r)
			}
		}()
	}
	wg.Wait()
	if n := f.reg.count("rdap.test/v1/domain/example.com"); n != 1 {
		t.Fatalf("concurrent lookups made %d upstream calls", n)
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, 5)
	rec := httptest.NewRecorder()
	e.svc.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	e.svc.Handler().ServeHTTP(rec, httptest.NewRequest("POST", "/internal/v1/age?domain=a.com", nil))
	if rec.Code != 404 {
		t.Fatalf("POST accepted: %d", rec.Code)
	}
}
