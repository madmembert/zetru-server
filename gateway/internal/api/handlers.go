package api

import (
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"zetru.app/gateway/internal/auth"
	"zetru.app/gateway/internal/campaign"
	"zetru.app/gateway/internal/keys"
	"zetru.app/gateway/internal/registry"
)

var (
	hex64     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex32     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	tokenChar = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	hostChars = regexp.MustCompile(`^[a-z0-9._:\[\]-]{1,253}$`)
	printable = regexp.MustCompile(`^[\x20-\x7e]{0,32}$`)
)

// --- enrolment (§4.2 step 4, §11.3) ---

type enrollRequest struct {
	Token           string `json:"token"`
	DevicePublicKey string `json:"device_public_key"`
	DeviceLabel     string `json:"device_label"`
	AppVersion      string `json:"app_version"`
	Platform        string `json:"platform"`
}

func validLabel(label string) bool {
	if !utf8.ValidString(label) || utf8.RuneCountInString(label) > 40 {
		return false
	}
	for _, c := range label {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func (s *Server) handleEnroll(r *http.Request, rc *reqCtx) response {
	// 5 attempts per minute per source address; the address lives only in this in-memory table.
	if ok, wait := s.enrollRate.Allow("enroll|"+remoteHost(r), enrollPerMinute); !ok {
		return retryResponse("rate_limited", wait)
	}
	if r.ContentLength > enrollBodyLimit {
		return errorResponse("bad_request")
	}
	body, _, err := readBody(r.Body, r.ContentLength, enrollBodyLimit)
	rc.bodySize = int64(len(body))
	if err != nil {
		return errorResponse("bad_request")
	}
	var req enrollRequest
	if !decodeJSON(body, &req) || !tokenChar.MatchString(req.Token) || !validLabel(req.DeviceLabel) ||
		!printable.MatchString(req.AppVersion) || req.AppVersion == "" || req.Platform != "ios" {
		return errorResponse("bad_request")
	}
	if _, err := auth.ParseDevicePublicKey(req.DevicePublicKey); err != nil {
		return errorResponse("bad_request")
	}
	device, err := s.opt.Registry.Enroll(req.Token, req.DevicePublicKey, req.DeviceLabel)
	switch {
	case errors.Is(err, registry.ErrTokenUsed):
		return errorResponse("token_used")
	case errors.Is(err, registry.ErrTokenExpired):
		return errorResponse("token_expired")
	case errors.Is(err, registry.ErrTokenUnknown):
		return errorResponse("forbidden")
	case err != nil:
		s.opt.ErrorLog.Error("enrolment failed", "class", "registry")
		return errorResponse("busy")
	}
	tenant, err := s.opt.Registry.Tenant(device.TenantID)
	if err != nil {
		return errorResponse("forbidden")
	}
	rc.deviceID, rc.tenantID = device.ID, tenant.ID
	return jsonResponse(200, map[string]any{
		"device_id": device.ID,
		"tenant_id": tenant.ID,
		"server":    s.serverInfo(tenant),
	})
}

// --- server info (§11.3) ---

type limitsInfo struct {
	MaxMailBytes  int `json:"max_mail_bytes"`
	RatePerMinute int `json:"rate_per_minute"`
	DailyQuota    int `json:"daily_quota"`
}

type serverInfo struct {
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	APIVersions []string      `json:"api_versions"`
	Limits      limitsInfo    `json:"limits"`
	Backends    []backendInfo `json:"backends"`
	Feeds       []feedState   `json:"feeds"`
	PinSet      keys.PinSet   `json:"pin_set"`
}

func (s *Server) serverInfo(tenant registry.Tenant) serverInfo {
	e := s.effective(tenant)
	backends, feeds, ok := s.analyzerHealth()
	enabled := map[string]bool{}
	for _, b := range e.backends {
		enabled[b] = true
	}
	outBackends := []backendInfo{}
	if ok {
		for _, b := range backends {
			b.Enabled = b.Enabled && enabled[b.ID]
			outBackends = append(outBackends, b)
		}
	} else {
		for _, id := range e.backends { // analyzer unreachable: listed, but not usable right now
			outBackends = append(outBackends, backendInfo{ID: id})
		}
	}
	if feeds == nil {
		feeds = []feedState{}
	}
	return serverInfo{
		Name: s.opt.ServerName, Version: s.opt.Version, APIVersions: []string{"v1"},
		Limits:   limitsInfo{MaxMailBytes: e.maxMail, RatePerMinute: e.rate, DailyQuota: e.quota},
		Backends: outBackends, Feeds: feeds, PinSet: s.opt.Keys.Material().PinSet,
	}
}

func (s *Server) handleServerInfo(r *http.Request, rc *reqCtx) response {
	a, fail := s.authenticate(r, rc, "other", smallBodyLimit, false)
	if fail != nil {
		return *fail
	}
	defer a.release()
	return jsonResponse(200, s.serverInfo(a.tenant))
}

// --- url check (§11.3) ---

type urlCheckItem struct {
	Host      string `json:"host"`
	URLSHA256 string `json:"url_sha256"`
}

type urlCheckRequest struct {
	Items []urlCheckItem `json:"items"`
}

func (s *Server) handleURLCheck(r *http.Request, rc *reqCtx) response {
	a, fail := s.authenticate(r, rc, "url", urlCheckBodyLimit, false)
	if fail != nil {
		return *fail
	}
	defer a.release()
	var req urlCheckRequest
	if !decodeJSON(a.body, &req) || len(req.Items) < 1 || len(req.Items) > 10 {
		return errorResponse("bad_request")
	}
	for _, it := range req.Items {
		if !hostChars.MatchString(it.Host) || !hex64.MatchString(it.URLSHA256) {
			return errorResponse("bad_request")
		}
	}
	return s.forwardURLCheck(r, a, req)
}

// --- report (§11.3) ---

type reportRequest struct {
	FingerprintID string `json:"fingerprint_id"`
	MailSHA256    string `json:"mail_sha256"`
	Verdict       string `json:"verdict"`
	AccountRef    string `json:"account_ref"`
}

func (s *Server) handleReport(r *http.Request, rc *reqCtx) response {
	a, fail := s.authenticate(r, rc, "other", smallBodyLimit, false)
	if fail != nil {
		return *fail
	}
	defer a.release()
	var req reportRequest
	if !decodeJSON(a.body, &req) || !hex32.MatchString(req.FingerprintID) || !hex64.MatchString(req.MailSHA256) ||
		!hex32.MatchString(req.AccountRef) || (req.Verdict != "phishing" && req.Verdict != "spam" && req.Verdict != "legit") {
		return errorResponse("bad_request")
	}
	key := "report|" + a.device.ID
	if ok, wait := s.opt.Quota.Take(key, s.opt.Profile.ReportsPerDay); !ok {
		return retryResponse("quota_exceeded", wait)
	}
	duplicate, err := s.opt.Campaign.Report(a.tenant.ID, a.device.ID, s.effective(a.tenant).cross,
		req.FingerprintID, req.MailSHA256, req.Verdict)
	if errors.Is(err, campaign.ErrNotFound) {
		s.opt.Quota.Refund(key)
		return errorResponse("not_found")
	}
	if err != nil {
		s.opt.Quota.Refund(key)
		return errorResponse("bad_request")
	}
	if duplicate {
		s.opt.Quota.Refund(key)
	}
	return noContent()
}

// --- devices (§11.3, §4.6) ---

type deviceEntry struct {
	DeviceID    string `json:"device_id"`
	Label       string `json:"label"`
	CreatedAt   int64  `json:"created_at"`
	LastSeenDay string `json:"last_seen_day"`
	Current     bool   `json:"current"`
}

func (s *Server) handleDevices(r *http.Request, rc *reqCtx) response {
	a, fail := s.authenticate(r, rc, "other", smallBodyLimit, false)
	if fail != nil {
		return *fail
	}
	defer a.release()
	list := []deviceEntry{}
	for _, d := range s.opt.Registry.Devices(a.tenant.ID) {
		if d.Revoked() {
			continue
		}
		list = append(list, deviceEntry{DeviceID: d.ID, Label: d.Label, CreatedAt: d.CreatedAt,
			LastSeenDay: d.LastSeenDay, Current: d.ID == a.device.ID})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt < list[j].CreatedAt })
	return jsonResponse(200, map[string]any{"devices": list})
}

func (s *Server) handleRotate(r *http.Request, rc *reqCtx) response {
	a, fail := s.authenticate(r, rc, "other", smallBodyLimit, false)
	if fail != nil {
		return *fail
	}
	defer a.release()
	var req struct {
		NewPublicKey string `json:"new_public_key"`
	}
	if !decodeJSON(a.body, &req) {
		return errorResponse("bad_request")
	}
	if _, err := auth.ParseDevicePublicKey(req.NewPublicKey); err != nil {
		return errorResponse("bad_request")
	}
	if err := s.opt.Registry.RotateKey(a.device.ID, req.NewPublicKey); err != nil {
		if errors.Is(err, registry.ErrRevoked) {
			return errorResponse("device_revoked")
		}
		s.opt.ErrorLog.Error("device key rotation failed", "class", "registry")
		return errorResponse("busy")
	}
	return noContent()
}

func (s *Server) handleRevoke(r *http.Request, rc *reqCtx, target string) response {
	a, fail := s.authenticate(r, rc, "other", smallBodyLimit, false)
	if fail != nil {
		return *fail
	}
	defer a.release()
	if !registry.ValidUUID(target) {
		return errorResponse("not_found")
	}
	if err := s.opt.Registry.RevokeInTenant(a.tenant.ID, target); err != nil {
		if errors.Is(err, registry.ErrUnknownDevice) {
			return errorResponse("not_found") // includes devices of other tenants
		}
		s.opt.ErrorLog.Error("device revocation failed", "class", "registry")
		return errorResponse("busy")
	}
	return noContent()
}

func (s *Server) handleDeleteTenant(r *http.Request, rc *reqCtx) response {
	a, fail := s.authenticate(r, rc, "other", smallBodyLimit, false)
	if fail != nil {
		return *fail
	}
	defer a.release()
	devices := map[string]bool{}
	for _, d := range s.opt.Registry.Devices(a.tenant.ID) {
		devices[d.ID] = true
	}
	if err := s.opt.Registry.DeleteTenant(a.tenant.ID); err != nil {
		s.opt.ErrorLog.Error("tenant deletion failed", "class", "registry")
		return errorResponse("busy")
	}
	s.opt.Campaign.PurgeTenant(a.tenant.ID)
	s.opt.Quota.Retain(func(key string) bool {
		_, id, _ := strings.Cut(key, "|")
		return !devices[id]
	})
	if err := s.opt.Campaign.Save(); err != nil {
		s.opt.ErrorLog.Error("saving campaign counters failed", "class", "storage")
	}
	if err := s.opt.Quota.Save(); err != nil {
		s.opt.ErrorLog.Error("saving quota counters failed", "class", "storage")
	}
	return noContent()
}

// --- analyze (§11.2) ---

func (s *Server) handleAnalyze(r *http.Request, rc *reqCtx) response {
	// The body limit (4 + meta + the tenant's max_mail_bytes) is set inside authenticate once the
	// tenant is known.
	a, fail := s.authenticate(r, rc, "analyze", 0, true)
	if fail != nil {
		return *fail
	}
	defer a.release()
	e := s.effective(a.tenant)
	key := "analyze|" + a.device.ID
	if ok, wait := s.opt.Quota.Take(key, e.quota); !ok {
		return retryResponse("quota_exceeded", wait)
	}
	if !contentTypeIs(r.Header.Get("Content-Type"), AnalyzeContentType) {
		return errorResponse("unsupported_media_type")
	}
	meta, code := parseAnalyzeBody(a.body, e.maxMail)
	if code != "" {
		return errorResponse(code)
	}
	resp, refund := s.forwardAnalyze(r, a, e, meta)
	if refund {
		s.opt.Quota.Refund(key)
	}
	return resp
}
