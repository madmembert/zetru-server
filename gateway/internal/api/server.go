// Package api serves the public API of concept §11 (endpoints §11.1/§11.3, framing §11.2, limits
// §11.4, logging §11.5, errors §11.6) with the request verification of §4.4 and the response
// signatures of §4.5.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"zetru.app/gateway/internal/auth"
	"zetru.app/gateway/internal/campaign"
	"zetru.app/gateway/internal/config"
	"zetru.app/gateway/internal/keys"
	"zetru.app/gateway/internal/limits"
	"zetru.app/gateway/internal/registry"
	"zetru.app/gateway/internal/reqlog"
)

// AnalyzeContentType is the media type of POST /v1/analyze (§11.2).
const AnalyzeContentType = "application/vnd.zetru.analyze.v1"

// Size limits.
const (
	MaxMetaBytes        = 65_536
	MaxResponseBytes    = 256 * 1024 // §11.4
	maxAnalyzerResponse = MaxResponseBytes + 4096
	enrollBodyLimit     = 8 << 10
	smallBodyLimit      = 4 << 10
	urlCheckBodyLimit   = 16 << 10
	enrollPerMinute     = 5 // §4.4, per source address
)

// KeySource provides the live key material (keys.Manager in production).
type KeySource interface {
	Material() *keys.Material
}

// Options configure a Server.
type Options struct {
	Profile         config.Profile
	ServerName      string
	Version         string
	AnalyzerURL     string
	Registry        *registry.Registry
	Keys            KeySource
	Campaign        *campaign.Store
	Quota           *limits.Quota
	RequestLog      *reqlog.Logger
	ErrorLog        *slog.Logger
	Now             func() time.Time
	HTTPClient      *http.Client  // client for the analyzer (nil = default without proxy)
	AnalyzeTimeout  time.Duration // gateway-side timeout for one analysis (default 22 s)
	URLCheckTimeout time.Duration // default 5 s
}

// Server implements http.Handler.
type Server struct {
	opt        Options
	nonces     *auth.NonceCache
	rate       *limits.RateLimiter
	enrollRate *limits.RateLimiter
	inflight   chan struct{}
	budget     *byteBudget
	health     healthCache
}

// New creates a server.
func New(opt Options) *Server {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Version == "" {
		opt.Version = "1.0.0"
	}
	if opt.AnalyzeTimeout == 0 {
		opt.AnalyzeTimeout = 22 * time.Second
	}
	if opt.URLCheckTimeout == 0 {
		opt.URLCheckTimeout = 5 * time.Second
	}
	if opt.HTTPClient == nil {
		opt.HTTPClient = &http.Client{Transport: &http.Transport{
			Proxy:               nil,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     60 * time.Second,
			DisableCompression:  true,
			DialContext:         (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		}}
	}
	if opt.RequestLog == nil {
		opt.RequestLog = reqlog.Discard()
	}
	if opt.ErrorLog == nil {
		opt.ErrorLog = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	opt.AnalyzerURL = strings.TrimRight(opt.AnalyzerURL, "/")
	return &Server{
		opt:        opt,
		nonces:     auth.NewNonceCache(opt.Now, 0),
		rate:       limits.NewRateLimiter(opt.Now, 0),
		enrollRate: limits.NewRateLimiter(opt.Now, 50_000),
		inflight:   make(chan struct{}, opt.Profile.Workers+opt.Profile.Queue),
		budget:     &byteBudget{total: opt.Profile.BodyBudget},
	}
}

// Maintain runs the periodic housekeeping until ctx ends; it saves counters on exit.
func (s *Server) Maintain(ctx context.Context, saveEvery time.Duration) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	lastSave := s.opt.Now()
	for {
		select {
		case <-ctx.Done():
			s.SaveState()
			return
		case <-tick.C:
		}
		s.nonces.Prune()
		s.rate.Prune()
		s.enrollRate.Prune()
		if err := s.opt.Registry.Refresh(); err != nil {
			s.opt.ErrorLog.Error("registry reload failed; serving the previous state", "class", "registry")
		}
		if s.opt.Now().Sub(lastSave) >= saveEvery {
			lastSave = s.opt.Now()
			s.SaveState()
		}
	}
}

// SaveState drops data of deleted tenants and devices, then persists counters and quotas.
func (s *Server) SaveState() {
	tenants, devices := s.opt.Registry.IDs()
	s.opt.Campaign.Retain(tenants)
	s.opt.Quota.Retain(func(key string) bool {
		_, id, _ := strings.Cut(key, "|")
		return devices[id]
	})
	if err := s.opt.Campaign.Save(); err != nil {
		s.opt.ErrorLog.Error("saving campaign counters failed", "class", "storage")
	}
	if err := s.opt.Quota.Save(); err != nil {
		s.opt.ErrorLog.Error("saving quota counters failed", "class", "storage")
	}
}

// --- responses ---

var errorMessages = map[string]string{
	"bad_request":            "The request is malformed.",
	"unknown_device":         "This device is not registered.",
	"bad_signature":          "The request signature is invalid.",
	"stale_timestamp":        "The request timestamp is outside the accepted window.",
	"replayed_nonce":         "The request nonce was already used.",
	"device_revoked":         "This device has been revoked.",
	"forbidden":              "This action is not allowed.",
	"not_found":              "Not found.",
	"token_used":             "The enrolment token was already used.",
	"token_expired":          "The enrolment token has expired.",
	"mail_too_large":         "The mail exceeds the maximum size.",
	"unsupported_media_type": "The content type is not supported.",
	"rate_limited":           "Too many requests.",
	"quota_exceeded":         "The daily quota is exhausted.",
	"busy":                   "The server is busy.",
	"analyzer_unavailable":   "The analysis service is unavailable.",
	"analysis_timeout":       "The analysis timed out.",
}

var errorStatus = map[string]int{
	"bad_request": 400, "unknown_device": 401, "bad_signature": 401, "stale_timestamp": 401,
	"replayed_nonce": 401, "device_revoked": 401, "forbidden": 403, "not_found": 404, "token_used": 409,
	"token_expired": 410, "mail_too_large": 413, "unsupported_media_type": 415, "rate_limited": 429,
	"quota_exceeded": 429, "busy": 503, "analyzer_unavailable": 503, "analysis_timeout": 504,
}

type response struct {
	status     int
	body       []byte
	retryAfter time.Duration
	code       string
}

func jsonResponse(status int, v any) response {
	data, err := json.Marshal(v)
	if err != nil {
		return errorResponse("busy")
	}
	return response{status: status, body: data}
}

func noContent() response { return response{status: http.StatusNoContent} }

func errorResponse(code string) response {
	status, ok := errorStatus[code]
	if !ok {
		code, status = "busy", 503
	}
	body, _ := json.Marshal(map[string]map[string]string{"error": {"code": code, "message": errorMessages[code]}})
	r := response{status: status, body: body, code: code}
	if status == 503 {
		r.retryAfter = 30 * time.Second // §11.6 default
	}
	return r
}

func retryResponse(code string, wait time.Duration) response {
	r := errorResponse(code)
	r.retryAfter = wait
	return r
}

// write sends a response signed with the server identity key over the request nonce (§4.5).
func (s *Server) write(w http.ResponseWriter, nonce string, resp response) {
	body := resp.body
	if resp.status == http.StatusNoContent {
		body = nil
	}
	h := w.Header()
	h.Set(auth.HeaderSignature, auth.ResponseSigner{Key: s.opt.Keys.Material().Identity}.Sign(nonce, resp.status, body))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	if resp.retryAfter > 0 {
		h.Set("Retry-After", strconv.Itoa(int(math.Ceil(resp.retryAfter.Seconds()))))
	}
	if resp.status != http.StatusNoContent {
		h.Set("Content-Type", "application/json")
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	w.WriteHeader(resp.status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

// reqCtx collects what the request log may contain.
type reqCtx struct {
	endpoint string
	tenantID string
	deviceID string
	bodySize int64
}

// ServeHTTP routes, answers and logs one request.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := s.opt.Now()
	rc := &reqCtx{endpoint: "unknown"}
	nonce := r.Header.Get(auth.HeaderNonce)
	if !auth.ValidNonce(nonce) {
		nonce = "" // responses to requests without a usable nonce are signed over an empty nonce
	}
	var resp response
	func() {
		defer func() {
			if p := recover(); p != nil {
				s.opt.ErrorLog.Error("handler panic", "class", "panic", "stack", string(debug.Stack()))
				resp = errorResponse("busy")
			}
		}()
		resp = s.route(r, rc)
	}()
	s.write(w, nonce, resp)
	s.opt.RequestLog.Log(reqlog.Entry{Time: start, Endpoint: rc.endpoint, Tenant: rc.tenantID, Device: rc.deviceID,
		Status: resp.status, Code: resp.code, Duration: s.opt.Now().Sub(start), BodySize: rc.bodySize})
}

func (s *Server) route(r *http.Request, rc *reqCtx) response {
	path, method := r.URL.Path, r.Method
	switch {
	case path == "/healthz" && method == http.MethodGet:
		rc.endpoint = "GET /healthz"
		return jsonResponse(200, map[string]string{"status": "ok"})
	case path == "/v1/enroll" && method == http.MethodPost:
		rc.endpoint = "POST /v1/enroll"
		return s.handleEnroll(r, rc)
	case path == "/v1/server/info" && method == http.MethodGet:
		rc.endpoint = "GET /v1/server/info"
		return s.handleServerInfo(r, rc)
	case path == "/v1/analyze" && method == http.MethodPost:
		rc.endpoint = "POST /v1/analyze"
		return s.handleAnalyze(r, rc)
	case path == "/v1/url/check" && method == http.MethodPost:
		rc.endpoint = "POST /v1/url/check"
		return s.handleURLCheck(r, rc)
	case path == "/v1/report" && method == http.MethodPost:
		rc.endpoint = "POST /v1/report"
		return s.handleReport(r, rc)
	case path == "/v1/devices" && method == http.MethodGet:
		rc.endpoint = "GET /v1/devices"
		return s.handleDevices(r, rc)
	case path == "/v1/devices/rotate" && method == http.MethodPost:
		rc.endpoint = "POST /v1/devices/rotate"
		return s.handleRotate(r, rc)
	case strings.HasPrefix(path, "/v1/devices/") && method == http.MethodDelete:
		rc.endpoint = "DELETE /v1/devices/{device_id}"
		return s.handleRevoke(r, rc, strings.TrimPrefix(path, "/v1/devices/"))
	case path == "/v1/tenant" && method == http.MethodDelete:
		rc.endpoint = "DELETE /v1/tenant"
		return s.handleDeleteTenant(r, rc)
	}
	return errorResponse("not_found")
}

// --- authentication (§4.4) ---

// authed is the outcome of a successful authentication.
type authed struct {
	device  registry.Device
	tenant  registry.Tenant
	body    []byte
	release func()
}

// authenticate runs the checks of §4.4 in their order: device exists and is not revoked →
// timestamp within ±120 s → nonce not replayed → body hash matches → signature valid → rate limit.
// The daily quota (analyze only) is checked by the handler right after. maxBody bounds the body
// (for analyze it is derived from the tenant's max_mail_bytes); analyze requests also take a slot
// of the in-flight limit and of the body memory budget before their body is read.
func (s *Server) authenticate(r *http.Request, rc *reqCtx, class string, maxBody int64, analyze bool) (*authed, *response) {
	fail := func(code string) (*authed, *response) {
		resp := errorResponse(code)
		return nil, &resp
	}
	deviceID := r.Header.Get(auth.HeaderDevice)
	if !registry.ValidUUID(deviceID) {
		return fail("unknown_device")
	}
	device, err := s.opt.Registry.Device(deviceID)
	switch {
	case errors.Is(err, registry.ErrRevoked):
		rc.deviceID, rc.tenantID = device.ID, device.TenantID
		return fail("device_revoked")
	case err != nil:
		return fail("unknown_device")
	}
	tenant, err := s.opt.Registry.Tenant(device.TenantID)
	if err != nil {
		return fail("unknown_device")
	}
	rc.deviceID, rc.tenantID = device.ID, tenant.ID
	if analyze {
		maxBody = int64(4 + MaxMetaBytes + s.effective(tenant).maxMail)
	}

	timestamp := r.Header.Get(auth.HeaderTimestamp)
	if err := auth.CheckTimestamp(timestamp, s.opt.Now()); err != nil {
		return fail("stale_timestamp")
	}
	nonce := r.Header.Get(auth.HeaderNonce)
	if !auth.ValidNonce(nonce) {
		return fail("bad_request")
	}
	if err := s.nonces.Reserve(device.ID, nonce); err != nil {
		if errors.Is(err, auth.ErrNonceCacheFull) {
			resp := retryResponse("rate_limited", 30*time.Second)
			return nil, &resp
		}
		return fail("replayed_nonce")
	}
	// From here on, a failure releases the nonce: only authenticated requests keep theirs.
	release := func() {}
	failAfterNonce := func(resp response) (*authed, *response) {
		s.nonces.Release(device.ID, nonce)
		release()
		return nil, &resp
	}
	contentHash := r.Header.Get(auth.HeaderContent)
	if !auth.ValidContentHash(contentHash) {
		return failAfterNonce(errorResponse("bad_request"))
	}
	tooLarge := "bad_request"
	if analyze {
		tooLarge = "mail_too_large"
	}
	if r.ContentLength > maxBody {
		return failAfterNonce(errorResponse(tooLarge))
	}
	if analyze {
		select {
		case s.inflight <- struct{}{}:
		default:
			return failAfterNonce(errorResponse("busy"))
		}
		reserve := maxBody
		if r.ContentLength >= 0 {
			reserve = r.ContentLength
		}
		if !s.budget.acquire(reserve) {
			<-s.inflight
			return failAfterNonce(errorResponse("busy"))
		}
		release = func() {
			s.budget.release(reserve)
			<-s.inflight
		}
	}
	body, sum, err := readBody(r.Body, r.ContentLength, maxBody)
	rc.bodySize = int64(len(body))
	if errors.Is(err, errTooLarge) {
		return failAfterNonce(errorResponse(tooLarge))
	}
	if err != nil {
		return failAfterNonce(errorResponse("bad_request"))
	}
	if !strings.EqualFold(hex.EncodeToString(sum), contentHash) {
		return failAfterNonce(errorResponse("bad_signature"))
	}
	pub, err := auth.ParseDevicePublicKey(device.PublicKey)
	if err != nil {
		return failAfterNonce(errorResponse("bad_signature"))
	}
	target := r.RequestURI
	if !strings.HasPrefix(target, "/") {
		return failAfterNonce(errorResponse("bad_request"))
	}
	canonical := auth.CanonicalString(r.Method, target, timestamp, nonce, contentHash)
	if err := auth.VerifySignature(pub, canonical, r.Header.Get(auth.HeaderSignature)); err != nil {
		return failAfterNonce(errorResponse("bad_signature"))
	}
	// Authenticated. Rate limits now apply; the nonce stays recorded.
	perMinute := s.opt.Profile.OtherPerMinute
	switch class {
	case "analyze":
		perMinute = s.effective(tenant).rate
	case "url":
		perMinute = s.opt.Profile.URLCheckPerMinute
	}
	if ok, wait := s.rate.Allow(device.ID+"|"+class, perMinute); !ok {
		release()
		resp := retryResponse("rate_limited", wait)
		return nil, &resp
	}
	if err := s.opt.Registry.TouchLastSeen(device.ID, s.opt.Now()); err != nil {
		s.opt.ErrorLog.Error("updating last_seen_day failed", "class", "registry")
	}
	return &authed{device: device, tenant: tenant, body: body, release: release}, nil
}

var errTooLarge = errors.New("body too large")

// readBody reads at most limit bytes and hashes them on the way.
func readBody(r io.Reader, contentLength, limit int64) ([]byte, []byte, error) {
	h := sha256.New()
	var buf []byte
	if contentLength >= 0 {
		buf = make([]byte, contentLength)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, nil, err
		}
		// A body longer than its Content-Length is cut off by net/http; nothing more to check.
		h.Write(buf)
		return buf, h.Sum(nil), nil
	}
	data, err := io.ReadAll(io.LimitReader(io.TeeReader(r, h), limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(data)) > limit {
		return data, nil, errTooLarge
	}
	return data, h.Sum(nil), nil
}

// byteBudget bounds the memory held by analyze request bodies (a 256 MB container cannot hold
// many 20 MB mails at once).
type byteBudget struct {
	mu    sync.Mutex
	total int64
	used  int64
}

func (b *byteBudget) acquire(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.total {
		return false
	}
	b.used += n
	return true
}

func (b *byteBudget) release(n int64) {
	b.mu.Lock()
	b.used -= n
	b.mu.Unlock()
}

// effectiveLimits are a tenant's limits: policy values, falling back to the profile.
type effectiveLimits struct {
	backends []string
	maxMail  int
	rate     int
	quota    int
	cross    bool
}

func (s *Server) effective(t registry.Tenant) effectiveLimits {
	e := effectiveLimits{backends: t.Policy.Backends, maxMail: t.Policy.MaxMailBytes, rate: t.Policy.RatePerMinute,
		quota: t.Policy.DailyQuota, cross: t.Policy.CrossTenantCounting}
	if e.backends == nil {
		e.backends = []string{}
	}
	if e.maxMail == 0 {
		e.maxMail = s.opt.Profile.MaxMailBytes
	}
	if e.rate == 0 {
		e.rate = s.opt.Profile.AnalyzePerMinute
	}
	if e.quota == 0 {
		e.quota = s.opt.Profile.DailyQuota
	}
	return e
}

// decodeJSON decodes a JSON object into v; unknown fields are ignored (additive changes), trailing
// data is rejected.
func decodeJSON(body []byte, v any) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(v); err != nil {
		return false
	}
	var extra json.RawMessage
	return dec.Decode(&extra) == io.EOF
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
