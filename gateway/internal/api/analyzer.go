package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"zetru.app/gateway/internal/campaign"
)

// --- framing (§11.2) ---

type analyzeMeta struct {
	Schema         *int     `json:"schema"`
	MailSHA256     *string  `json:"mail_sha256"`
	AccountRef     *string  `json:"account_ref"`
	ReceivedAt     *int64   `json:"received_at"`
	Mode           *string  `json:"mode"`
	Locale         *string  `json:"locale"`
	CatalogVersion *int     `json:"catalog_version"`
	QRPayloads     []string `json:"qr_payloads"`
	OCRText        *string  `json:"ocr_text"`
}

func contentTypeIs(header, want string) bool {
	mt, _, err := mime.ParseMediaType(header)
	return err == nil && mt == want
}

// parseAnalyzeBody validates the framing and the meta JSON. It returns an API error code or "".
func parseAnalyzeBody(body []byte, maxMail int) (analyzeMeta, string) {
	var meta analyzeMeta
	if len(body) < 4 {
		return meta, "bad_request"
	}
	n := uint64(binary.BigEndian.Uint32(body[:4]))
	if n < 1 || n > MaxMetaBytes || uint64(len(body)) < 4+n {
		return meta, "bad_request"
	}
	metaBytes, mail := body[4:4+n], body[4+n:]
	if len(mail) < 1 {
		return meta, "bad_request"
	}
	if len(mail) > maxMail {
		return meta, "mail_too_large"
	}
	if !utf8.Valid(metaBytes) || !decodeJSON(metaBytes, &meta) {
		return meta, "bad_request"
	}
	switch {
	case meta.Schema == nil || *meta.Schema != 1,
		meta.MailSHA256 == nil || !hex64.MatchString(*meta.MailSHA256),
		meta.AccountRef == nil || !hex32.MatchString(*meta.AccountRef),
		meta.ReceivedAt != nil && *meta.ReceivedAt < 0,
		meta.Mode == nil || (*meta.Mode != "auto" && *meta.Mode != "confirm" && *meta.Mode != "manual"),
		meta.Locale == nil || (*meta.Locale != "de" && *meta.Locale != "en"),
		meta.CatalogVersion == nil || *meta.CatalogVersion < 1,
		len(meta.QRPayloads) > 5,
		meta.OCRText != nil && utf8.RuneCountInString(*meta.OCRText) > 4000:
		return meta, "bad_request"
	}
	for _, p := range meta.QRPayloads {
		if utf8.RuneCountInString(p) > 2048 {
			return meta, "bad_request"
		}
	}
	sum := sha256.Sum256(mail)
	if hex.EncodeToString(sum[:]) != *meta.MailSHA256 {
		return meta, "bad_request"
	}
	return meta, ""
}

// --- forwarding (docs/server-internal-api.md) ---

// policyHeader is X-Zetru-Policy: base64url (padded) of {"backends": [...], "max_mail_bytes": n}.
func policyHeader(e effectiveLimits) string {
	data, _ := json.Marshal(struct {
		Backends     []string `json:"backends"`
		MaxMailBytes int      `json:"max_mail_bytes"`
	}{e.backends, e.maxMail})
	return base64.URLEncoding.EncodeToString(data)
}

// analyzerError maps a non-200 analyzer answer or a transport failure to an API response and
// reports whether the quota unit should be refunded (the mail was not analysed).
func analyzerError(ctx context.Context, status int, retryAfter string, err error) (response, bool) {
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errorResponse("analysis_timeout"), false
		}
		return errorResponse("analyzer_unavailable"), true
	}
	switch status {
	case http.StatusServiceUnavailable:
		resp := errorResponse("busy")
		if n, err := strconv.Atoi(strings.TrimSpace(retryAfter)); err == nil && n >= 1 && n <= 3600 {
			resp.retryAfter = time.Duration(n) * time.Second
		}
		return resp, true
	case http.StatusGatewayTimeout:
		return errorResponse("analysis_timeout"), false
	case http.StatusBadRequest:
		return errorResponse("bad_request"), false
	}
	return errorResponse("analyzer_unavailable"), true
}

func (s *Server) post(ctx context.Context, path, contentType string, body []byte, tenantID string, e effectiveLimits) (int, string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.opt.AnalyzerURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Zetru-Tenant", tenantID)
	req.Header.Set("X-Zetru-Policy", policyHeader(e))
	resp, err := s.opt.HTTPClient.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAnalyzerResponse+1))
	if err != nil {
		return 0, "", nil, err
	}
	if len(data) > maxAnalyzerResponse {
		return resp.StatusCode, "", nil, errors.New("analyzer response too large")
	}
	return resp.StatusCode, resp.Header.Get("Retry-After"), data, nil
}

var signalID = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,47}$`)

type signalHead struct {
	ID       string `json:"id"`
	Severity string `json:"fallback_severity"`
}

func validSignal(raw json.RawMessage) (signalHead, bool) {
	var h signalHead
	if json.Unmarshal(raw, &h) != nil || !signalID.MatchString(h.ID) {
		return h, false
	}
	return h, h.Severity == "info" || h.Severity == "caution" || h.Severity == "danger"
}

type fingerprintOut struct {
	ID            string `json:"id"`
	SeenDevices7d int    `json:"seen_devices_7d"`
	Reports       int    `json:"reports"`
}

type gatewaySignal struct {
	ID       string         `json:"id"`
	Severity string         `json:"fallback_severity"`
	Evidence map[string]int `json:"evidence"`
}

const maxSignals = 64

var severityRank = map[string]int{"info": 0, "caution": 1, "danger": 2}

func (s *Server) forwardAnalyze(r *http.Request, a *authed, e effectiveLimits, meta analyzeMeta) (response, bool) {
	ctx, cancel := context.WithTimeout(r.Context(), s.opt.AnalyzeTimeout)
	defer cancel()
	status, retryAfter, data, err := s.post(ctx, "/internal/v1/analyze", AnalyzeContentType, a.body, a.tenant.ID, e)
	if err != nil || status != http.StatusOK {
		if err != nil && ctx.Err() == nil {
			s.opt.ErrorLog.Error("analyzer request failed", "class", "analyzer")
		}
		return analyzerError(ctx, status, retryAfter, err)
	}
	out, reason := s.mergeAnalysis(data, a, e, *meta.MailSHA256)
	if reason != "" {
		s.opt.ErrorLog.Error("analyzer response rejected", "class", "analyzer_contract", "reason", reason)
		return errorResponse("analyzer_unavailable"), true
	}
	return response{status: http.StatusOK, body: out}, false
}

// mergeAnalysis checks the analyzer's response, replaces campaign_bands by the keyed fingerprint,
// adds BULK_CAMPAIGN_* signals and returns the final JSON. reason is a fixed string on failure.
func (s *Server) mergeAnalysis(data []byte, a *authed, e effectiveLimits, mailSHA256 string) ([]byte, string) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil || obj == nil {
		return nil, "not a JSON object"
	}
	var schema int
	if json.Unmarshal(obj["schema"], &schema) != nil || schema != 1 {
		return nil, "schema"
	}
	var echoed string
	if json.Unmarshal(obj["mail_sha256"], &echoed) != nil || echoed != mailSHA256 {
		return nil, "mail_sha256 mismatch"
	}
	var signals []json.RawMessage
	if json.Unmarshal(obj["signals"], &signals) != nil || signals == nil {
		return nil, "signals"
	}
	kept := make([]json.RawMessage, 0, len(signals)+1)
	severities := make([]string, 0, len(signals)+1)
	for _, raw := range signals {
		h, ok := validSignal(raw)
		if !ok {
			return nil, "invalid signal"
		}
		if strings.HasPrefix(h.ID, "BULK_CAMPAIGN_") {
			continue // campaign signals are the gateway's (internal spec)
		}
		kept = append(kept, raw)
		severities = append(severities, h.Severity)
	}
	if len(kept) > maxSignals {
		return nil, "too many signals"
	}

	var fingerprint any // JSON null unless the analyzer computed bands
	rawBands := obj["campaign_bands"]
	delete(obj, "campaign_bands")
	delete(obj, "fingerprint")
	if len(rawBands) > 0 && string(rawBands) != "null" {
		var values []string
		var bands [4]uint16
		err := json.Unmarshal(rawBands, &values)
		if err == nil {
			bands, err = campaign.ParseBands(values)
		}
		if err != nil {
			s.opt.ErrorLog.Error("analyzer sent invalid campaign_bands; no fingerprint", "class", "analyzer_contract")
		} else {
			res := s.opt.Campaign.Observe(a.tenant.ID, a.device.ID, e.cross, bands, mailSHA256)
			fingerprint = fingerprintOut{ID: res.FingerprintID, SeenDevices7d: res.SeenDevices7d, Reports: res.Reports}
			if res.Signal != "" {
				count := res.Reports
				if res.Signal == campaign.SignalSeen {
					count = res.SeenDevices7d
				}
				sig, _ := json.Marshal(gatewaySignal{ID: res.Signal, Severity: res.Severity, Evidence: map[string]int{"count": count}})
				kept, severities = addSignal(kept, severities, sig, res.Severity)
			}
		}
	}
	var err error
	if obj["fingerprint"], err = json.Marshal(fingerprint); err != nil {
		return nil, "encode"
	}
	if obj["signals"], err = json.Marshal(kept); err != nil {
		return nil, "encode"
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, "encode"
	}
	if len(out) > MaxResponseBytes {
		return nil, "response too large"
	}
	return out, ""
}

// addSignal appends a gateway signal within the 64-signal limit: when full, it replaces the last
// analyzer signal of lower severity, or is dropped.
func addSignal(list []json.RawMessage, severities []string, sig json.RawMessage, severity string) ([]json.RawMessage, []string) {
	if len(list) < maxSignals {
		return append(list, sig), append(severities, severity)
	}
	for i := len(list) - 1; i >= 0; i-- {
		if severityRank[severities[i]] < severityRank[severity] {
			list[i], severities[i] = sig, severity
			return list, severities
		}
	}
	return list, severities
}

// --- url check forwarding ---

type urlCheckResponse struct {
	Results []struct {
		URLSHA256 string           `json:"url_sha256"`
		Hit       *bool            `json:"hit"`
		Signal    *json.RawMessage `json:"signal"`
	} `json:"results"`
	Feeds []feedState `json:"feeds"`
}

func (s *Server) forwardURLCheck(r *http.Request, a *authed, req urlCheckRequest) response {
	e := s.effective(a.tenant)
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(r.Context(), s.opt.URLCheckTimeout)
	defer cancel()
	status, retryAfter, data, err := s.post(ctx, "/internal/v1/url/check", "application/json", body, a.tenant.ID, e)
	if err != nil || status != http.StatusOK {
		resp, _ := analyzerError(ctx, status, retryAfter, err)
		return resp
	}
	var check urlCheckResponse
	if !decodeJSON(data, &check) || check.Results == nil || len(check.Results) > len(req.Items) || len(data) > MaxResponseBytes {
		s.opt.ErrorLog.Error("analyzer url/check response rejected", "class", "analyzer_contract")
		return errorResponse("analyzer_unavailable")
	}
	asked := map[string]bool{}
	for _, it := range req.Items {
		asked[it.URLSHA256] = true
	}
	for _, res := range check.Results {
		if !asked[res.URLSHA256] || res.Hit == nil {
			s.opt.ErrorLog.Error("analyzer url/check response rejected", "class", "analyzer_contract")
			return errorResponse("analyzer_unavailable")
		}
		if res.Signal != nil && string(*res.Signal) != "null" {
			if _, ok := validSignal(*res.Signal); !ok {
				s.opt.ErrorLog.Error("analyzer url/check response rejected", "class", "analyzer_contract")
				return errorResponse("analyzer_unavailable")
			}
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, data); err != nil {
		return errorResponse("analyzer_unavailable")
	}
	return response{status: http.StatusOK, body: compact.Bytes()}
}

// --- analyzer health (for server/info) ---

type backendInfo struct {
	ID            string  `json:"id"`
	Enabled       bool    `json:"enabled"`
	Calibrated    bool    `json:"calibrated"`
	LicenceNotice *string `json:"licence_notice"`
}

type feedState struct {
	ID    string `json:"id"`
	AgeS  int64  `json:"age_s"`
	Stale bool   `json:"stale"`
}

type healthCache struct {
	mu       sync.Mutex
	fetched  time.Time
	ok       bool
	backends []backendInfo
	feeds    []feedState
}

var shortID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// analyzerHealth returns the analyzer's backends and feed states, cached for 60 s (15 s after a
// failure). Invalid entries are dropped. The probe does not use the client's request context, so a
// client that disconnects cannot make the cache record a failure.
func (s *Server) analyzerHealth() ([]backendInfo, []feedState, bool) {
	h := &s.health
	h.mu.Lock()
	defer h.mu.Unlock()
	ttl := 60 * time.Second
	if !h.ok {
		ttl = 15 * time.Second
	}
	if !h.fetched.IsZero() && s.opt.Now().Sub(h.fetched) < ttl {
		return h.backends, h.feeds, h.ok
	}
	h.fetched, h.ok, h.backends, h.feeds = s.opt.Now(), false, nil, nil
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.opt.AnalyzerURL+"/internal/healthz", nil)
	if err != nil {
		return nil, nil, false
	}
	resp, err := s.opt.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, false
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, nil, false
	}
	var body struct {
		Status   string        `json:"status"`
		Feeds    []feedState   `json:"feeds"`
		Backends []backendInfo `json:"backends"`
	}
	if json.Unmarshal(data, &body) != nil || body.Status != "ok" {
		return nil, nil, false
	}
	for _, f := range body.Feeds {
		if shortID.MatchString(f.ID) && f.AgeS >= 0 && len(h.feeds) < 64 {
			h.feeds = append(h.feeds, f)
		}
	}
	for _, b := range body.Backends {
		if !shortID.MatchString(b.ID) || len(h.backends) >= 16 {
			continue
		}
		if b.LicenceNotice != nil && (len(*b.LicenceNotice) > 512 || !utf8.ValidString(*b.LicenceNotice)) {
			continue
		}
		h.backends = append(h.backends, b)
	}
	h.ok = true
	return h.backends, h.feeds, true
}
