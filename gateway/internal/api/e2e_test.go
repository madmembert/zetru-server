package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"zetru.app/gateway/internal/campaign"
	"zetru.app/gateway/internal/config"
	"zetru.app/gateway/internal/keys"
	"zetru.app/gateway/internal/limits"
	"zetru.app/gateway/internal/registry"
	"zetru.app/gateway/internal/reqlog"
)

// ---------- test fixtures ----------

// Content that must never show up in any log.
const (
	secretSubject = "SECRET-SUBJECT-4711"
	secretSender  = "victim-sender@example-bank.test"
	secretDomain  = "evil.example-phish.test"
	secretAccount = "0123456789abcdef0123456789abcdef"
)

var testMail = []byte("From: Bank <" + secretSender + ">\r\nTo: user@example.test\r\nSubject: " + secretSubject +
	"\r\nMessage-ID: <a@b>\r\n\r\nPlease log in at https://" + secretDomain + "/login now.\r\n")

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// fakeAnalyzer implements the internal analyzer API (docs/server-internal-api.md).
type fakeAnalyzer struct {
	mu         sync.Mutex
	calls      int
	lastBody   []byte
	lastTenant string
	lastPolicy string
	mode       string // "", "busy", "timeout", "reset", "badsha", "badbands", "badsignal"
	bands      []string
	signals    []map[string]any
	urlCalls   int
}

func (f *fakeAnalyzer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	mode, bands, signals := f.mode, f.bands, f.signals
	f.mu.Unlock()
	switch r.URL.Path {
	case "/internal/healthz":
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok",
			"feeds": []map[string]any{{"id": "certpl", "age_s": 140, "stale": false}, {"id": "BAD ID", "age_s": 1, "stale": false}},
			"backends": []map[string]any{
				{"id": "rules", "enabled": true, "calibrated": false, "licence_notice": nil},
				{"id": "encoder", "enabled": true, "calibrated": true, "licence_notice": "MIT"},
			}})
	case "/internal/v1/url/check":
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.urlCalls++
		f.lastTenant, f.lastPolicy = r.Header.Get("X-Zetru-Tenant"), r.Header.Get("X-Zetru-Policy")
		f.mu.Unlock()
		var req urlCheckRequest
		_ = json.Unmarshal(body, &req)
		var results []map[string]any
		for _, it := range req.Items {
			hit := it.Host == "bad.example.test"
			res := map[string]any{"url_sha256": it.URLSHA256, "hit": hit, "signal": nil}
			if hit {
				res["signal"] = map[string]any{"id": "LINK_FEED_HIT", "fallback_severity": "danger", "evidence": map[string]any{"feed": "certpl"}}
			}
			results = append(results, res)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results, "feeds": []any{}})
	case "/internal/v1/analyze":
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls++
		f.lastBody, f.lastTenant, f.lastPolicy = body, r.Header.Get("X-Zetru-Tenant"), r.Header.Get("X-Zetru-Policy")
		f.mu.Unlock()
		switch mode {
		case "busy":
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"error":{"code":"busy","message":"x"}}`))
			return
		case "timeout":
			time.Sleep(400 * time.Millisecond)
		case "reset":
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		n := binary.BigEndian.Uint32(body[:4])
		var meta map[string]any
		_ = json.Unmarshal(body[4:4+n], &meta)
		sha := meta["mail_sha256"]
		if mode == "badsha" {
			sha = strings.Repeat("0", 64)
		}
		var b any = bands
		if mode == "badbands" {
			b = []string{"zz", "1"}
		}
		sigs := signals
		if sigs == nil {
			sigs = []map[string]any{}
		}
		if mode == "badsignal" {
			sigs = append(sigs, map[string]any{"id": "lower_case", "fallback_severity": "info"})
		}
		// A stale BULK_CAMPAIGN signal from the analyzer must be dropped by the gateway.
		sigs = append(sigs, map[string]any{"id": "BULK_CAMPAIGN_CONFIRMED", "fallback_severity": "danger"})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"schema": 1, "analysis_id": "5b0c5c1e-6f0b-4a53-9d0e-2a6f1f1f7c11", "mail_sha256": sha,
			"analyzed_at": 1795348800, "server_version": "1.0.0", "catalog_version": 1,
			"completeness": map[string]any{"parse": "ok", "auth": "ok", "urls": "ok", "attachments": "ok",
				"domain_age": "ok", "feeds": "ok", "classifier": "ok", "complete": true},
			"signals": sigs, "decisions": []any{}, "auth": map[string]any{"dkim": []any{}, "dmarc": nil},
			"feeds": []any{}, "campaign_bands": b, "fingerprint": map[string]any{"id": "forged"},
		})
	default:
		http.NotFound(w, r)
	}
}

type testEnv struct {
	t        *testing.T
	dir      string
	clockMu  sync.Mutex
	clock    time.Time
	reg      *registry.Registry
	mgr      *keys.Manager
	srv      *Server
	base     string
	ln       *memListener
	client   *http.Client
	sid      ed25519.PublicKey
	analyzer *fakeAnalyzer
	reqLog   *syncBuffer
	errLog   *syncBuffer
	tenant   registry.Tenant
}

func (e *testEnv) now() time.Time {
	e.clockMu.Lock()
	defer e.clockMu.Unlock()
	return e.clock
}

func (e *testEnv) advance(d time.Duration) {
	e.clockMu.Lock()
	e.clock = e.clock.Add(d)
	e.clockMu.Unlock()
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	e := &testEnv{t: t, dir: t.TempDir(), clock: time.Now(), analyzer: &fakeAnalyzer{bands: []string{"1111", "2222", "3333", "4444"}},
		reqLog: &syncBuffer{}, errLog: &syncBuffer{}}
	if err := keys.Init(e.dir, []string{"127.0.0.1"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	var err error
	if e.mgr, err = keys.NewManager(e.dir); err != nil {
		t.Fatal(err)
	}
	e.sid = e.mgr.Material().Identity.Public().(ed25519.PublicKey)
	if e.reg, err = registry.Open(e.dir, e.now); err != nil {
		t.Fatal(err)
	}
	if e.tenant, err = e.reg.CreateTenant("home"); err != nil {
		t.Fatal(err)
	}
	counters, _ := campaign.Open("", e.mgr.Material().Fingerprint, e.now)
	quota, _ := limits.OpenQuota("", e.now)
	// The sandbox this was developed in forbids binding TCP ports, so both servers run on in-memory
	// listeners (net.Pipe); TLS and HTTP run unchanged on top.
	analyzerLn := newMemListener()
	as := &http.Server{Handler: e.analyzer}
	go func() { _ = as.Serve(analyzerLn) }()
	t.Cleanup(func() { _ = as.Close() })
	profile, _ := config.ProfileFor("pi")
	e.srv = New(Options{Profile: profile, ServerName: "Test server", AnalyzerURL: "http://analyzer.test:8081", Registry: e.reg,
		Keys: e.mgr, Campaign: counters, Quota: quota, RequestLog: reqlog.NewWriterLogger(e.reqLog),
		ErrorLog: slog.New(slog.NewTextHandler(e.errLog, nil)), Now: e.now, AnalyzeTimeout: 200 * time.Millisecond,
		HTTPClient: &http.Client{Transport: &http.Transport{DialContext: analyzerLn.Dial}}})

	// The gateway serves real TLS 1.3 with the production TLS settings; the client pins the key.
	e.ln = newMemListener()
	hs := &http.Server{Handler: e.srv, ErrorLog: ServerErrorLog(slog.New(slog.NewTextHandler(e.errLog, nil)))}
	go func() { _ = hs.Serve(tls.NewListener(e.ln, TLSConfig(e.mgr.GetCertificate))) }()
	t.Cleanup(func() { _ = hs.Close() })
	e.base = "https://gateway.test:8443"
	e.client = pinnedClient(e.ln, e.mgr.Material().PinSet.Pins, tls.VersionTLS13)
	return e
}

// memListener is an in-memory net.Listener; Dial hands one end of a net.Pipe to Accept.
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

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr { return memAddr{} }

func (l *memListener) Dial(ctx context.Context, _, _ string) (net.Conn, error) {
	server, client := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

func pinnedClient(ln *memListener, pins []string, maxVersion uint16) *http.Client {
	allowed := map[string]bool{}
	for _, p := range pins {
		allowed[p] = true
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: ln.Dial, TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, MaxVersion: maxVersion,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			if !allowed[base64.StdEncoding.EncodeToString(sum[:])] {
				return errors.New("pin mismatch")
			}
			return nil
		},
	}}}
}

// ---------- client side of the protocol, written from concept §4.4/§4.5 ----------

type device struct {
	id  string
	key *ecdsa.PrivateKey
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := k.PublicKey.Bytes()
	return k, base64.StdEncoding.EncodeToString(raw)
}

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type reqOpts struct {
	nonce       string
	timestamp   int64
	signer      *ecdsa.PrivateKey
	hashBody    []byte // hash this instead of the real body
	deviceID    string
	contentType string
}

type result struct {
	status int
	body   []byte
	header http.Header
}

func (r result) code() string {
	var e struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	_ = json.Unmarshal(r.body, &e)
	return e.Error.Code
}

// do sends a signed request and always checks the response signature against the request nonce.
func (e *testEnv) do(d device, method, path string, body []byte, o reqOpts) result {
	e.t.Helper()
	if o.nonce == "" {
		o.nonce = newNonce()
	}
	if o.timestamp == 0 {
		o.timestamp = e.now().Unix()
	}
	if o.signer == nil {
		o.signer = d.key
	}
	if o.deviceID == "" {
		o.deviceID = d.id
	}
	hashed := body
	if o.hashBody != nil {
		hashed = o.hashBody
	}
	sum := sha256.Sum256(hashed)
	contentHash := hex.EncodeToString(sum[:])
	ts := strconv.FormatInt(o.timestamp, 10)
	canonical := "ZETRU1\n" + method + "\n" + path + "\n" + ts + "\n" + o.nonce + "\n" + contentHash
	digest := sha256.Sum256([]byte(canonical))
	sig, err := ecdsa.SignASN1(rand.Reader, o.signer, digest[:])
	if err != nil {
		e.t.Fatal(err)
	}
	req, _ := http.NewRequest(method, e.base+path, bytes.NewReader(body))
	req.Header.Set("Zetru-Device", o.deviceID)
	req.Header.Set("Zetru-Timestamp", ts)
	req.Header.Set("Zetru-Nonce", o.nonce)
	req.Header.Set("Zetru-Content-SHA256", contentHash)
	req.Header.Set("Zetru-Signature", base64.StdEncoding.EncodeToString(sig))
	if o.contentType != "" {
		req.Header.Set("Content-Type", o.contentType)
	}
	// A request whose nonce is not 16 bytes of base64url gets a response signed over the empty
	// nonce (DECISIONS.md).
	respNonce := o.nonce
	if raw, err := base64.RawURLEncoding.DecodeString(o.nonce); err != nil || len(raw) != 16 {
		respNonce = ""
	}
	return e.send(req, respNonce)
}

func (e *testEnv) send(req *http.Request, nonce string) result {
	e.t.Helper()
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	sig, _ := base64.StdEncoding.DecodeString(resp.Header.Get("Zetru-Signature"))
	sum := sha256.Sum256(body)
	msg := "ZETRU1-RESP\n" + nonce + "\n" + strconv.Itoa(resp.StatusCode) + "\n" + hex.EncodeToString(sum[:])
	if !ed25519.Verify(e.sid, []byte(msg), sig) {
		e.t.Fatalf("%s %s: response signature invalid (status %d)", req.Method, req.URL.Path, resp.StatusCode)
	}
	if len(body) > MaxResponseBytes {
		e.t.Fatalf("response larger than 256 KB")
	}
	return result{status: resp.StatusCode, body: body, header: resp.Header}
}

func (e *testEnv) enroll(label string) device {
	e.t.Helper()
	token, _, err := e.reg.CreateEnrolmentToken(e.tenant.ID, registry.TokenTTL)
	if err != nil {
		e.t.Fatal(err)
	}
	key, pub := newKey(e.t)
	res := e.enrollRaw(map[string]any{"token": token, "device_public_key": pub, "device_label": label,
		"app_version": "1.0 (42)", "platform": "ios"}, newNonce())
	if res.status != 200 {
		e.t.Fatalf("enroll: %d %s", res.status, res.body)
	}
	var out struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(res.body, &out)
	return device{id: out.DeviceID, key: key}
}

func (e *testEnv) enrollRaw(body map[string]any, nonce string) result {
	data, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.base+"/v1/enroll", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if nonce != "" {
		req.Header.Set("Zetru-Nonce", nonce)
	}
	return e.send(req, nonce)
}

func analyzeBody(t *testing.T, mail []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	sum := sha256.Sum256(mail)
	meta := map[string]any{"schema": 1, "mail_sha256": hex.EncodeToString(sum[:]), "account_ref": secretAccount,
		"received_at": 1795348700, "mode": "auto", "locale": "de", "catalog_version": 1,
		"qr_payloads": []string{"https://" + secretDomain + "/qr"}, "ocr_text": "scan me"}
	if mutate != nil {
		mutate(meta)
	}
	metaJSON, _ := json.Marshal(meta)
	body := make([]byte, 4, 4+len(metaJSON)+len(mail))
	binary.BigEndian.PutUint32(body, uint32(len(metaJSON)))
	return append(append(body, metaJSON...), mail...)
}

func (e *testEnv) analyze(d device, mail []byte, o reqOpts) result {
	e.t.Helper()
	if o.contentType == "" {
		o.contentType = AnalyzeContentType
	}
	return e.do(d, "POST", "/v1/analyze", analyzeBody(e.t, mail, nil), o)
}

func expect(t *testing.T, name string, r result, status int, code string) {
	t.Helper()
	if r.status != status || r.code() != code {
		t.Fatalf("%s: got %d %q (%s), want %d %q", name, r.status, r.code(), r.body, status, code)
	}
}

// ---------- tests ----------

func TestHealthzAndUnknownRoutesAreSigned(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("GET", e.base+"/healthz", nil)
	r := e.send(req, "") // no nonce: signed over the empty nonce
	if r.status != 200 || string(r.body) != `{"status":"ok"}` {
		t.Fatalf("healthz: %d %s", r.status, r.body)
	}
	n := newNonce()
	req, _ = http.NewRequest("GET", e.base+"/v2/nothing", nil)
	req.Header.Set("Zetru-Nonce", n)
	expect(t, "unknown route", e.send(req, n), 404, "not_found")
	req, _ = http.NewRequest("PUT", e.base+"/v1/analyze", nil)
	expect(t, "wrong method", e.send(req, ""), 404, "not_found")
}

func TestTLS13Only(t *testing.T) {
	e := newEnv(t)
	old := pinnedClient(e.ln, e.mgr.Material().PinSet.Pins, tls.VersionTLS12)
	if _, err := old.Get(e.base + "/healthz"); err == nil {
		t.Fatal("TLS 1.2 handshake succeeded")
	}
	wrongPin := pinnedClient(e.ln, []string{base64.StdEncoding.EncodeToString(make([]byte, 32))}, tls.VersionTLS13)
	if _, err := wrongPin.Get(e.base + "/healthz"); err == nil {
		t.Fatal("client with a wrong pin connected")
	}
}

func TestEnrollment(t *testing.T) {
	e := newEnv(t)
	token, _, _ := e.reg.CreateEnrolmentToken(e.tenant.ID, registry.TokenTTL)
	_, pub := newKey(t)
	good := map[string]any{"token": token, "device_public_key": pub, "device_label": "Max's iPhone", "app_version": "1.0", "platform": "ios"}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for key, val := range good {
			m[key] = val
		}
		m[k] = v
		return m
	}
	expect(t, "android", e.enrollRaw(with("platform", "android"), ""), 400, "bad_request")
	_, der := newKey(t)
	expect(t, "short key", e.enrollRaw(with("device_public_key", der[:40]), ""), 400, "bad_request")
	expect(t, "long label", e.enrollRaw(with("device_label", strings.Repeat("x", 41)), ""), 400, "bad_request")
	expect(t, "unknown token", e.enrollRaw(with("token", "AAAAAAAAAAAAAAAAAAAAAA"), ""), 403, "forbidden")
	e.advance(time.Minute) // enrolment is limited to 5 attempts per minute and source address

	nonce := newNonce()
	r := e.enrollRaw(good, nonce)
	if r.status != 200 {
		t.Fatalf("enroll: %d %s", r.status, r.body)
	}
	var out struct {
		DeviceID string     `json:"device_id"`
		TenantID string     `json:"tenant_id"`
		Server   serverInfo `json:"server"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil || !registry.ValidUUID(out.DeviceID) || out.TenantID != e.tenant.ID {
		t.Fatalf("enroll response %s", r.body)
	}
	if out.Server.Name != "Test server" || len(out.Server.PinSet.Pins) != 2 || !keys.VerifyPinSet(e.sid, out.Server.PinSet) {
		t.Fatalf("server info in enroll response: %+v", out.Server)
	}
	if out.Server.Limits.MaxMailBytes != 20<<20 || out.Server.Limits.RatePerMinute != 30 || out.Server.Limits.DailyQuota != 3000 {
		t.Fatalf("limits: %+v", out.Server.Limits)
	}
	expect(t, "token reuse", e.enrollRaw(good, ""), 409, "token_used")

	short, _, _ := e.reg.CreateEnrolmentToken(e.tenant.ID, time.Minute)
	e.advance(2 * time.Minute)
	expect(t, "expired token", e.enrollRaw(with("token", short), ""), 410, "token_expired")

	// 5 attempts per minute per source address.
	e.advance(time.Minute)
	for i := 0; i < 5; i++ {
		e.enrollRaw(with("token", "AAAAAAAAAAAAAAAAAAAAAA"), "")
	}
	r = e.enrollRaw(good, "")
	expect(t, "enroll rate limit", r, 429, "rate_limited")
	if r.header.Get("Retry-After") == "" {
		t.Fatal("Retry-After missing")
	}
}

func TestServerInfoAndPinSet(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	r := e.do(d, "GET", "/v1/server/info", nil, reqOpts{})
	if r.status != 200 {
		t.Fatalf("server info %d %s", r.status, r.body)
	}
	var info serverInfo
	_ = json.Unmarshal(r.body, &info)
	if len(info.APIVersions) != 1 || info.APIVersions[0] != "v1" || info.Version == "" {
		t.Fatalf("info %s", r.body)
	}
	// Backends: the analyzer reports rules and encoder; the tenant policy enables only rules.
	if len(info.Backends) != 2 || !info.Backends[0].Enabled || info.Backends[1].Enabled {
		t.Fatalf("backends %+v", info.Backends)
	}
	if len(info.Feeds) != 1 || info.Feeds[0].ID != "certpl" {
		t.Fatalf("feeds %+v (invalid feed IDs must be dropped)", info.Feeds)
	}
	// A planned rotation shows up as a signed pin set with three pins.
	if err := keys.StartRotation(e.dir, nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.mgr.Refresh(false); err != nil {
		t.Fatal(err)
	}
	r = e.do(d, "GET", "/v1/server/info", nil, reqOpts{})
	_ = json.Unmarshal(r.body, &info)
	if info.PinSet.Seq != 2 || len(info.PinSet.Pins) != 3 || !keys.VerifyPinSet(e.sid, info.PinSet) {
		t.Fatalf("rotated pin set %+v", info.PinSet)
	}
}

func TestRequestVerification(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")

	// Valid request.
	nonce := newNonce()
	r := e.analyze(d, testMail, reqOpts{nonce: nonce})
	if r.status != 200 {
		t.Fatalf("analyze: %d %s", r.status, r.body)
	}
	// Replay of the same nonce.
	expect(t, "replay", e.analyze(d, testMail, reqOpts{nonce: nonce}), 401, "replayed_nonce")
	// Timestamps outside ±120 s.
	expect(t, "stale", e.analyze(d, testMail, reqOpts{timestamp: e.now().Unix() - 121}), 401, "stale_timestamp")
	expect(t, "future", e.analyze(d, testMail, reqOpts{timestamp: e.now().Unix() + 121}), 401, "stale_timestamp")
	// Signature by another key; the nonce of a failed request is released, so the genuine request
	// with the same nonce still succeeds afterwards.
	other, _ := newKey(t)
	n2 := newNonce()
	expect(t, "bad signature", e.analyze(d, testMail, reqOpts{nonce: n2, signer: other}), 401, "bad_signature")
	if r := e.analyze(d, testMail, reqOpts{nonce: n2}); r.status != 200 {
		t.Fatalf("nonce of a rejected request stayed blocked: %d %s", r.status, r.body)
	}
	// Body-hash mismatch (headers and signature cover a different body).
	expect(t, "body hash", e.analyze(d, testMail, reqOpts{hashBody: []byte("other body")}), 401, "bad_signature")
	// Unknown device.
	expect(t, "unknown device", e.analyze(d, testMail, reqOpts{deviceID: registry.NewID()}), 401, "unknown_device")
	expect(t, "malformed device", e.analyze(d, testMail, reqOpts{deviceID: "x"}), 401, "unknown_device")
	// Malformed nonce.
	r = e.analyze(d, testMail, reqOpts{nonce: "short"})
	if r.status != 400 || r.code() != "bad_request" {
		t.Fatalf("bad nonce: %d %s", r.status, r.body)
	}
	// Revoked device.
	if err := e.reg.Revoke(d.id); err != nil {
		t.Fatal(err)
	}
	expect(t, "revoked", e.analyze(d, testMail, reqOpts{}), 401, "device_revoked")

	// Exactly two analyses reached the analyzer.
	if e.analyzer.calls != 2 {
		t.Fatalf("analyzer called %d times", e.analyzer.calls)
	}
}

func TestAnalyzeForwardingAndFraming(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	body := analyzeBody(t, testMail, nil)
	r := e.do(d, "POST", "/v1/analyze", body, reqOpts{contentType: AnalyzeContentType})
	if r.status != 200 {
		t.Fatalf("analyze %d %s", r.status, r.body)
	}
	if !bytes.Equal(e.analyzer.lastBody, body) || e.analyzer.lastTenant != e.tenant.ID {
		t.Fatal("analyzer did not receive the exact body and tenant")
	}
	policyJSON, err := base64.URLEncoding.DecodeString(e.analyzer.lastPolicy)
	if err != nil || string(policyJSON) != `{"backends":["rules"],"max_mail_bytes":20971520}` {
		t.Fatalf("policy header %q -> %s", e.analyzer.lastPolicy, policyJSON)
	}
	var resp map[string]json.RawMessage
	_ = json.Unmarshal(r.body, &resp)
	if _, leaked := resp["campaign_bands"]; leaked {
		t.Fatal("campaign_bands leaked to the client")
	}
	var fp struct {
		ID            string `json:"id"`
		SeenDevices7d int    `json:"seen_devices_7d"`
		Reports       int    `json:"reports"`
	}
	if json.Unmarshal(resp["fingerprint"], &fp) != nil || len(fp.ID) != 32 || fp.SeenDevices7d != 1 || fp.Reports != 0 {
		t.Fatalf("fingerprint %s", resp["fingerprint"])
	}
	if strings.Contains(string(resp["signals"]), "BULK_CAMPAIGN") {
		t.Fatal("analyzer-supplied BULK_CAMPAIGN signal passed through")
	}

	// Framing errors.
	cases := map[string][]byte{
		"empty body":        {},
		"meta length 0":     append([]byte{0, 0, 0, 0}, testMail...),
		"meta length 65537": append([]byte{0, 1, 0, 1}, bytes.Repeat([]byte("x"), 65537)...),
		"truncated meta":    append([]byte{0, 0, 1, 0}, []byte(`{"schema":1}`)...),
		"no mail":           analyzeBody(t, nil, nil),
		"sha mismatch":      analyzeBody(t, testMail, func(m map[string]any) { m["mail_sha256"] = strings.Repeat("a", 64) }),
		"bad mode":          analyzeBody(t, testMail, func(m map[string]any) { m["mode"] = "always" }),
		"bad locale":        analyzeBody(t, testMail, func(m map[string]any) { m["locale"] = "fr" }),
		"schema 2":          analyzeBody(t, testMail, func(m map[string]any) { m["schema"] = 2 }),
		"missing ref":       analyzeBody(t, testMail, func(m map[string]any) { delete(m, "account_ref") }),
		"too many qr":       analyzeBody(t, testMail, func(m map[string]any) { m["qr_payloads"] = []string{"a", "b", "c", "d", "e", "f"} }),
		"long ocr":          analyzeBody(t, testMail, func(m map[string]any) { m["ocr_text"] = strings.Repeat("ä", 4001) }),
		"meta not json":     append([]byte{0, 0, 0, 3}, []byte("abc"+string(testMail))...),
	}
	calls := e.analyzer.calls
	for name, b := range cases {
		expect(t, name, e.do(d, "POST", "/v1/analyze", b, reqOpts{contentType: AnalyzeContentType}), 400, "bad_request")
	}
	expect(t, "content type", e.do(d, "POST", "/v1/analyze", body, reqOpts{contentType: "application/json"}), 415, "unsupported_media_type")
	if e.analyzer.calls != calls {
		t.Fatal("malformed requests reached the analyzer")
	}
}

func TestOversizeMail(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	p := e.tenant.Policy
	p.MaxMailBytes = 2048
	if err := e.reg.SetPolicy(e.tenant.ID, p); err != nil {
		t.Fatal(err)
	}
	big := append(append([]byte{}, testMail...), bytes.Repeat([]byte("A"), 4096)...)
	// The body exceeds 4 + 65,536 + 2,048 only with a large meta; the mail limit itself is checked too.
	expect(t, "oversize mail", e.analyze(d, big, reqOpts{}), 413, "mail_too_large")
	huge := bytes.Repeat([]byte("B"), 70_000)
	expect(t, "oversize body", e.analyze(d, huge, reqOpts{}), 413, "mail_too_large")
	if e.analyzer.calls != 0 {
		t.Fatal("oversize mail reached the analyzer")
	}
	if r := e.analyze(d, testMail, reqOpts{}); r.status != 200 {
		t.Fatalf("small mail rejected: %d", r.status)
	}
}

func TestRateLimitAndQuota(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	for i := 0; i < 30; i++ {
		if r := e.analyze(d, testMail, reqOpts{}); r.status != 200 {
			t.Fatalf("request %d: %d %s", i, r.status, r.body)
		}
	}
	r := e.analyze(d, testMail, reqOpts{})
	expect(t, "rate limit", r, 429, "rate_limited")
	if r.header.Get("Retry-After") != "2" {
		t.Fatalf("Retry-After %q, want 2 (30 per minute)", r.header.Get("Retry-After"))
	}
	// url/check has its own bucket.
	item := map[string]any{"items": []map[string]any{{"host": "good.example.test", "url_sha256": strings.Repeat("b", 64)}}}
	body, _ := json.Marshal(item)
	if r := e.do(d, "POST", "/v1/url/check", body, reqOpts{}); r.status != 200 {
		t.Fatalf("url/check limited by the analyze bucket: %d", r.status)
	}

	// Daily quota from the tenant policy.
	e2 := newEnv(t)
	p := e2.tenant.Policy
	p.DailyQuota = 3
	_ = e2.reg.SetPolicy(e2.tenant.ID, p)
	d2 := e2.enroll("iPad")
	for i := 0; i < 3; i++ {
		if r := e2.analyze(d2, testMail, reqOpts{}); r.status != 200 {
			t.Fatalf("quota request %d: %d", i, r.status)
		}
	}
	r = e2.analyze(d2, testMail, reqOpts{})
	expect(t, "quota", r, 429, "quota_exceeded")
	if secs, _ := strconv.Atoi(r.header.Get("Retry-After")); secs < 1 || secs > 86400 {
		t.Fatalf("quota Retry-After %q", r.header.Get("Retry-After"))
	}
	// A busy analyzer does not consume quota.
	e3 := newEnv(t)
	p = e3.tenant.Policy
	p.DailyQuota = 1
	_ = e3.reg.SetPolicy(e3.tenant.ID, p)
	d3 := e3.enroll("iPad")
	e3.analyzer.mode = "busy"
	r = e3.analyze(d3, testMail, reqOpts{})
	expect(t, "busy", r, 503, "busy")
	if r.header.Get("Retry-After") != "7" {
		t.Fatalf("analyzer Retry-After not passed on: %q", r.header.Get("Retry-After"))
	}
	e3.analyzer.mode = ""
	if r := e3.analyze(d3, testMail, reqOpts{}); r.status != 200 {
		t.Fatalf("quota consumed by a busy response: %d", r.status)
	}
}

func TestAnalyzerFailures(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	for mode, want := range map[string][2]any{
		"timeout":   {504, "analysis_timeout"},
		"reset":     {503, "analyzer_unavailable"},
		"badsha":    {503, "analyzer_unavailable"},
		"badsignal": {503, "analyzer_unavailable"},
	} {
		e.analyzer.mu.Lock()
		e.analyzer.mode = mode
		e.analyzer.mu.Unlock()
		r := e.analyze(d, testMail, reqOpts{})
		expect(t, mode, r, want[0].(int), want[1].(string))
		if r.status == 503 && r.header.Get("Retry-After") != "30" {
			t.Fatalf("%s: Retry-After %q", mode, r.header.Get("Retry-After"))
		}
	}
	// Invalid campaign bands only drop the fingerprint.
	e.analyzer.mu.Lock()
	e.analyzer.mode = "badbands"
	e.analyzer.mu.Unlock()
	r := e.analyze(d, testMail, reqOpts{})
	var resp map[string]json.RawMessage
	_ = json.Unmarshal(r.body, &resp)
	if r.status != 200 || string(resp["fingerprint"]) != "null" {
		t.Fatalf("bad bands: %d %s", r.status, resp["fingerprint"])
	}
}

func signalIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var resp struct {
		Signals []struct {
			ID       string         `json:"id"`
			Severity string         `json:"fallback_severity"`
			Evidence map[string]int `json:"evidence"`
		} `json:"signals"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range resp.Signals {
		ids = append(ids, s.ID+":"+s.Severity)
	}
	return ids
}

func TestCampaignSignalsAndReports(t *testing.T) {
	e := newEnv(t)
	var devices []device
	for i := 0; i < 5; i++ {
		devices = append(devices, e.enroll(fmt.Sprintf("device %d", i)))
	}
	var last result
	for i, d := range devices {
		last = e.analyze(d, testMail, reqOpts{})
		ids := signalIDs(t, last.body)
		if i < 4 && len(ids) != 0 {
			t.Fatalf("signal after %d devices: %v", i+1, ids)
		}
	}
	if ids := signalIDs(t, last.body); len(ids) != 1 || ids[0] != "BULK_CAMPAIGN_SEEN:info" {
		t.Fatalf("5 devices: %v", ids)
	}
	var resp struct {
		Fingerprint struct {
			ID            string `json:"id"`
			SeenDevices7d int    `json:"seen_devices_7d"`
			Reports       int    `json:"reports"`
		} `json:"fingerprint"`
	}
	_ = json.Unmarshal(last.body, &resp)
	if resp.Fingerprint.SeenDevices7d != 5 {
		t.Fatalf("seen bucket %d", resp.Fingerprint.SeenDevices7d)
	}

	sum := sha256.Sum256(testMail)
	report := func(d device, fp, verdict string, mail [32]byte) result {
		b, _ := json.Marshal(map[string]any{"fingerprint_id": fp, "mail_sha256": hex.EncodeToString(mail[:]),
			"verdict": verdict, "account_ref": secretAccount})
		return e.do(d, "POST", "/v1/report", b, reqOpts{})
	}
	other := sha256.Sum256([]byte("never analysed"))
	expect(t, "report without analysis", report(devices[0], resp.Fingerprint.ID, "phishing", other), 404, "not_found")
	expect(t, "report with wrong fingerprint", report(devices[0], strings.Repeat("0", 32), "phishing", sum), 404, "not_found")
	if r := report(devices[0], resp.Fingerprint.ID, "phishing", sum); r.status != 204 || len(r.body) != 0 {
		t.Fatalf("report: %d %s", r.status, r.body)
	}
	if r := report(devices[0], resp.Fingerprint.ID, "phishing", sum); r.status != 204 {
		t.Fatalf("duplicate report: %d", r.status)
	}
	expect(t, "bad verdict", report(devices[0], resp.Fingerprint.ID, "maybe", sum), 400, "bad_request")

	// One report by a device of the same tenant: caution for everyone in the tenant.
	r := e.analyze(devices[1], testMail, reqOpts{})
	if ids := signalIDs(t, r.body); len(ids) != 1 || ids[0] != "BULK_CAMPAIGN_REPORTED:caution" {
		t.Fatalf("after report: %v", ids)
	}
	_ = json.Unmarshal(r.body, &resp)
	if resp.Fingerprint.Reports != 1 {
		t.Fatalf("reports bucket %d", resp.Fingerprint.Reports)
	}
}

func TestDevicesRotateRevokeAndTenantDeletion(t *testing.T) {
	e := newEnv(t)
	a := e.enroll("iPhone")
	b := e.enroll("iPad")
	r := e.do(a, "GET", "/v1/devices", nil, reqOpts{})
	var list struct {
		Devices []deviceEntry `json:"devices"`
	}
	_ = json.Unmarshal(r.body, &list)
	if r.status != 200 || len(list.Devices) != 2 || !list.Devices[0].Current || list.Devices[1].Current ||
		list.Devices[1].Label != "iPad" || len(list.Devices[0].LastSeenDay) != 10 {
		t.Fatalf("devices %d %s", r.status, r.body)
	}

	// Rotation: signed with the old key; afterwards only the new key works.
	newPriv, newPub := newKey(t)
	body, _ := json.Marshal(map[string]string{"new_public_key": newPub})
	if r := e.do(a, "POST", "/v1/devices/rotate", body, reqOpts{}); r.status != 204 {
		t.Fatalf("rotate %d %s", r.status, r.body)
	}
	expect(t, "old key after rotation", e.do(a, "GET", "/v1/devices", nil, reqOpts{}), 401, "bad_signature")
	a.key = newPriv
	if r := e.do(a, "GET", "/v1/devices", nil, reqOpts{}); r.status != 200 {
		t.Fatalf("new key rejected: %d", r.status)
	}
	bad, _ := json.Marshal(map[string]string{"new_public_key": "AAAA"})
	expect(t, "rotate to garbage", e.do(a, "POST", "/v1/devices/rotate", bad, reqOpts{}), 400, "bad_request")

	// A device of another tenant cannot be revoked (and is not revealed).
	otherTenant, _ := e.reg.CreateTenant("office")
	tok, _, _ := e.reg.CreateEnrolmentToken(otherTenant.ID, registry.TokenTTL)
	_, pk := newKey(t)
	foreign, err := e.reg.Enroll(tok, pk, "office mac")
	if err != nil {
		t.Fatal(err)
	}
	expect(t, "foreign revoke", e.do(a, "DELETE", "/v1/devices/"+foreign.ID, nil, reqOpts{}), 404, "not_found")
	expect(t, "malformed id", e.do(a, "DELETE", "/v1/devices/abc", nil, reqOpts{}), 404, "not_found")
	if r := e.do(a, "DELETE", "/v1/devices/"+b.id, nil, reqOpts{}); r.status != 204 {
		t.Fatalf("revoke %d", r.status)
	}
	expect(t, "revoked device", e.do(b, "GET", "/v1/devices", nil, reqOpts{}), 401, "device_revoked")

	// Tenant deletion removes the tenant, its devices and its counters.
	e.analyze(a, testMail, reqOpts{})
	if _, tb, refs, _ := e.srv.opt.Campaign.Stats(); tb == 0 || refs == 0 {
		t.Fatal("expected tenant counters before deletion")
	}
	if r := e.do(a, "DELETE", "/v1/tenant", nil, reqOpts{}); r.status != 204 {
		t.Fatalf("delete tenant %d", r.status)
	}
	expect(t, "deleted tenant", e.do(a, "GET", "/v1/devices", nil, reqOpts{}), 401, "unknown_device")
	if _, tb, refs, _ := e.srv.opt.Campaign.Stats(); tb != 0 || refs != 0 {
		t.Fatal("tenant counters survived deletion")
	}
	if _, err := e.reg.Tenant(otherTenant.ID); err != nil {
		t.Fatal("other tenant deleted")
	}
}

func TestURLCheck(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("iPhone")
	body, _ := json.Marshal(map[string]any{"items": []map[string]any{
		{"host": "bad.example.test", "url_sha256": strings.Repeat("a", 64)},
		{"host": "good.example.test", "url_sha256": strings.Repeat("b", 64)},
	}})
	r := e.do(d, "POST", "/v1/url/check", body, reqOpts{})
	var out struct {
		Results []struct {
			URLSHA256 string          `json:"url_sha256"`
			Hit       bool            `json:"hit"`
			Signal    json.RawMessage `json:"signal"`
		} `json:"results"`
	}
	if r.status != 200 || json.Unmarshal(r.body, &out) != nil || len(out.Results) != 2 || !out.Results[0].Hit || out.Results[1].Hit {
		t.Fatalf("url check %d %s", r.status, r.body)
	}
	if e.analyzer.lastTenant != e.tenant.ID {
		t.Fatal("tenant header missing on url/check")
	}
	for name, items := range map[string]any{
		"no items":  []any{},
		"11 items":  make([]map[string]string, 11),
		"bad hash":  []map[string]string{{"host": "a.test", "url_sha256": "xyz"}},
		"uppercase": []map[string]string{{"host": "A.TEST", "url_sha256": strings.Repeat("a", 64)}},
		"path":      []map[string]string{{"host": "a.test/x", "url_sha256": strings.Repeat("a", 64)}},
	} {
		b, _ := json.Marshal(map[string]any{"items": items})
		expect(t, name, e.do(d, "POST", "/v1/url/check", b, reqOpts{}), 400, "bad_request")
	}
}

// TestLogsContainNoRequestData runs a full session and then checks every log line (§11.5).
func TestLogsContainNoRequestData(t *testing.T) {
	e := newEnv(t)
	d := e.enroll("Secret Label Device")
	e.analyze(d, testMail, reqOpts{})
	e.analyze(d, testMail, reqOpts{signer: d.key, hashBody: []byte("x")})
	sum := sha256.Sum256(testMail)
	rb, _ := json.Marshal(map[string]any{"fingerprint_id": strings.Repeat("c", 32), "mail_sha256": hex.EncodeToString(sum[:]),
		"verdict": "phishing", "account_ref": secretAccount})
	e.do(d, "POST", "/v1/report", rb, reqOpts{})
	ub, _ := json.Marshal(map[string]any{"items": []map[string]any{{"host": secretDomain, "url_sha256": strings.Repeat("d", 64)}}})
	e.do(d, "POST", "/v1/url/check", ub, reqOpts{})
	e.analyzer.mode = "badsha"
	e.analyze(d, testMail, reqOpts{})
	e.analyzer.mode = "badbands"
	e.analyze(d, testMail, reqOpts{})

	logs := e.reqLog.String() + e.errLog.String()
	if !strings.Contains(e.reqLog.String(), `"endpoint":"POST /v1/analyze"`) || !strings.Contains(e.reqLog.String(), d.id) {
		t.Fatalf("request log incomplete:\n%s", e.reqLog.String())
	}
	forbidden := []string{secretSubject, secretSender, secretDomain, secretAccount, "example-bank", "Secret Label",
		hex.EncodeToString(sum[:]), "pipe", "mem", strings.Repeat("d", 64), "1111", d.key.X.String()[:12]}
	for _, f := range forbidden {
		if strings.Contains(logs, f) {
			t.Errorf("log contains request data %q:\n%s", f, logs)
		}
	}
	// Every request line has exactly the fields of §11.5.
	for _, line := range strings.Split(strings.TrimSpace(e.reqLog.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line not JSON: %s", line)
		}
		for k := range m {
			switch k {
			case "ts", "endpoint", "tenant", "device", "status", "code", "dur", "size":
			default:
				t.Fatalf("unexpected log field %q", k)
			}
		}
	}
}
