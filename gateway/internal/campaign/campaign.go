// Package campaign keeps the campaign counters of concept §6.5, §6.6 and §13.2.
//
// The analyzer returns four 16-bit SimHash bands per mail. The gateway keys each band with K_fp
// (HMAC-SHA256(K_fp, band_index ‖ band)) and keeps, per keyed band, two capped sets of keyed
// 64-bit hashes: the devices that saw a mail with this band (with their tenant hash and the last
// UTC day) and the devices that reported it. No text, no band value and no mail hash is stored in
// clear. Everything expires 30 days after its last day.
//
// Design choices (DECISIONS.md, "Campaign counters"):
//   - Capped sets instead of HyperLogLog sketches: the thresholds need exact counts only up to 20
//     and a membership test ("reported by a device of the same tenant"), which sketches cannot give.
//     Sets hold at most 32 members (reporters: at most 5 per tenant); counts saturate there.
//   - A mail matches a campaign only when at least two of its four bands agree (the count used is
//     the second-highest per-band count). Matching on any single 16-bit band would make an unrelated
//     mail collide with a reported band with probability 4·k/65536 for k reported bands, which
//     would put G2 gates on legitimate mail.
//   - Counting happens in the tenant's own scope; tenants whose policy enables cross-tenant counting
//     also count in, and read from, the global scope.
package campaign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"sync"
	"time"

	"zetru.app/gateway/internal/fsutil"
)

// Tunables (see package comment).
const (
	TTLDays          = 30
	SeenWindowDays   = 7
	SetCap           = 32
	ReportersPerTen  = 5
	MinBandAgreement = 2
	DefaultMaxBands  = 200_000
	DefaultMaxRefs   = 200_000
)

// Signal IDs produced by the gateway (§6.6).
const (
	SignalSeen      = "BULK_CAMPAIGN_SEEN"
	SignalReported  = "BULK_CAMPAIGN_REPORTED"
	SignalConfirmed = "BULK_CAMPAIGN_CONFIRMED"
)

// ErrNotFound means a report did not match a prior analysis of the same mail by the same tenant.
var ErrNotFound = errors.New("no matching analysis")

// Result of observing one analysed mail.
type Result struct {
	FingerprintID string // 32 lowercase hex characters
	SeenDevices7d int    // bucketed (0, 1, 2, 5, 20)
	Reports       int    // bucketed
	Signal        string // "" or one of the Signal* IDs
	Severity      string // severity of Signal
}

// Bucket maps a count to the reporting buckets of §11.2: 0, 1, 2–4, 5–19, 20+ → 0, 1, 2, 5, 20.
func Bucket(n int) int {
	switch {
	case n <= 0:
		return 0
	case n == 1:
		return 1
	case n < 5:
		return 2
	case n < 20:
		return 5
	default:
		return 20
	}
}

var bandHex = regexp.MustCompile(`^[0-9a-f]{4}$`)

// ParseBands validates the analyzer's campaign_bands: exactly 4 lowercase hex strings of 4 chars.
func ParseBands(values []string) ([4]uint16, error) {
	var out [4]uint16
	if len(values) != 4 {
		return out, errors.New("campaign_bands must have 4 entries")
	}
	for i, v := range values {
		if !bandHex.MatchString(v) {
			return out, errors.New("campaign_bands entry is not 4 lowercase hex characters")
		}
		b, _ := hex.DecodeString(v)
		out[i] = uint16(b[0])<<8 | uint16(b[1])
	}
	return out, nil
}

type (
	hash8 [8]byte
	key32 [32]byte
)

type member struct {
	tenant hash8
	day    int32
}

type band struct {
	seen      map[hash8]member
	reporters map[hash8]member
}

func newBand() *band {
	return &band{seen: map[hash8]member{}, reporters: map[hash8]member{}}
}

func (b *band) lastDay() int32 {
	var last int32
	for _, m := range b.seen {
		if m.day > last {
			last = m.day
		}
	}
	for _, m := range b.reporters {
		if m.day > last {
			last = m.day
		}
	}
	return last
}

func evictOldest(set map[hash8]member) {
	var oldestKey hash8
	oldest := int32(1 << 30)
	for k, m := range set {
		if m.day < oldest {
			oldest, oldestKey = m.day, k
		}
	}
	delete(set, oldestKey)
}

func (b *band) addSeen(device, tenant hash8, day int32) {
	if m, ok := b.seen[device]; ok {
		if day > m.day {
			m.day = day
		}
		m.tenant = tenant
		b.seen[device] = m
		return
	}
	if len(b.seen) >= SetCap {
		evictOldest(b.seen)
	}
	b.seen[device] = member{tenant: tenant, day: day}
}

func (b *band) addReporter(device, tenant hash8, day int32) {
	if _, ok := b.reporters[device]; ok {
		return
	}
	perTenant := 0
	for _, m := range b.reporters {
		if m.tenant == tenant {
			perTenant++
		}
	}
	if perTenant >= ReportersPerTen {
		return
	}
	if len(b.reporters) >= SetCap {
		evictOldest(b.reporters)
	}
	b.reporters[device] = member{tenant: tenant, day: day}
}

type mailRef struct {
	fp    string
	bands [4]key32
	day   int32
}

// Store holds all counters. It is safe for concurrent use.
type Store struct {
	kfp  []byte
	now  func() time.Time
	path string

	MaxBands int
	MaxRefs  int

	mu      sync.Mutex
	global  map[key32]*band
	tenants map[string]map[key32]*band
	refs    map[string]map[key32]mailRef // tenant -> HMAC(K_fp, tenant ‖ mail_sha256) -> ref
	reports map[string]map[key32]int32   // tenant -> HMAC(K_fp, "report" ‖ device ‖ fp) -> day
	dirty   bool
}

// Open creates a store keyed with kfp and loads path if it exists. A file written with a
// different K_fp, or a corrupt file, is discarded (moved aside) because its hashes are meaningless.
func Open(path string, kfp []byte, now func() time.Time) (*Store, error) {
	if len(kfp) != 32 {
		return nil, errors.New("K_fp must be 32 bytes")
	}
	if now == nil {
		now = time.Now
	}
	s := &Store{kfp: append([]byte(nil), kfp...), now: now, path: path, MaxBands: DefaultMaxBands, MaxRefs: DefaultMaxRefs,
		global: map[key32]*band{}, tenants: map[string]map[key32]*band{}, refs: map[string]map[key32]mailRef{},
		reports: map[string]map[key32]int32{}}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.decode(data); err != nil {
		_ = os.Rename(path, path+".discarded")
		s.global, s.tenants = map[key32]*band{}, map[string]map[key32]*band{}
		s.refs, s.reports = map[string]map[key32]mailRef{}, map[string]map[key32]int32{}
	}
	s.mu.Lock()
	s.expireLocked(dayNum(now()))
	s.mu.Unlock()
	return s, nil
}

func dayNum(t time.Time) int32 { return int32(t.Unix() / 86400) }

func (s *Store) mac(parts ...[]byte) key32 {
	h := hmac.New(sha256.New, s.kfp)
	for _, p := range parts {
		h.Write(p)
	}
	var out key32
	copy(out[:], h.Sum(nil))
	return out
}

func short(k key32) hash8 {
	var h hash8
	copy(h[:], k[:8])
	return h
}

// GlobalBandKey is HMAC-SHA256(K_fp, band_index ‖ band) with band_index one byte and band the two
// big-endian bytes of the 16-bit value (§6.5).
func (s *Store) GlobalBandKey(index int, value uint16) key32 {
	return s.mac([]byte{byte(index), byte(value >> 8), byte(value)})
}

func (s *Store) tenantBandKey(tenantID string, global key32) key32 {
	return s.mac([]byte("tenant-band"), []byte(tenantID), global[:])
}

func (s *Store) deviceHash(deviceID string) hash8 {
	return short(s.mac([]byte("device"), []byte(deviceID)))
}

func (s *Store) tenantHash(tenantID string) hash8 {
	return short(s.mac([]byte("tenant"), []byte(tenantID)))
}

func (s *Store) fingerprintID(keys [4]key32) string {
	k := s.mac([]byte("fingerprint"), keys[0][:], keys[1][:], keys[2][:], keys[3][:])
	return hex.EncodeToString(k[:16])
}

// mailRefKey is HMAC(K_fp, tenant ‖ mail_sha256) (§13.2 mail_ref).
func (s *Store) mailRefKey(tenantID, mailSHA256 string) key32 {
	return s.mac([]byte(tenantID), []byte(mailSHA256))
}

func (s *Store) reportKey(deviceID, fingerprintID string) key32 {
	return s.mac([]byte("report"), []byte(deviceID), []byte(fingerprintID))
}

func bandIn(scope map[key32]*band, k key32) *band {
	b := scope[k]
	if b == nil {
		b = newBand()
		scope[k] = b
	}
	return b
}

func (s *Store) tenantScope(tenantID string) map[key32]*band {
	scope := s.tenants[tenantID]
	if scope == nil {
		scope = map[key32]*band{}
		s.tenants[tenantID] = scope
	}
	return scope
}

// Observe records that a device of a tenant analysed a mail with the given bands and returns the
// fingerprint and campaign signal. cross selects cross-tenant counting (tenant policy).
func (s *Store) Observe(tenantID, deviceID string, cross bool, bands [4]uint16, mailSHA256 string) Result {
	var globalKeys, tenantKeys [4]key32
	for i, v := range bands {
		globalKeys[i] = s.GlobalBandKey(i, v)
		tenantKeys[i] = s.tenantBandKey(tenantID, globalKeys[i])
	}
	fp := s.fingerprintID(globalKeys)
	dev, ten := s.deviceHash(deviceID), s.tenantHash(tenantID)
	refKey := s.mailRefKey(tenantID, mailSHA256)
	today := dayNum(s.now())

	s.mu.Lock()
	defer s.mu.Unlock()
	scope := s.tenantScope(tenantID)
	var read [4]*band
	for i := range bands {
		tb := bandIn(scope, tenantKeys[i])
		tb.addSeen(dev, ten, today)
		read[i] = tb
		if cross {
			gb := bandIn(s.global, globalKeys[i])
			gb.addSeen(dev, ten, today)
			read[i] = gb
		}
	}
	refs := s.refs[tenantID]
	if refs == nil {
		refs = map[key32]mailRef{}
		s.refs[tenantID] = refs
	}
	refs[refKey] = mailRef{fp: fp, bands: globalKeys, day: today}
	s.dirty = true
	res := evaluate(read, ten, today)
	res.FingerprintID = fp
	s.enforceCapsLocked()
	return res
}

// kth returns the k-th largest value (k = 1 is the maximum).
func kth(values [4]int, k int) int {
	sorted := values[:]
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))
	return sorted[k-1]
}

func evaluate(bands [4]*band, myTenant hash8, today int32) Result {
	var seen, reports [4]int
	confirmed, reported := 0, 0
	for i, b := range bands {
		if b == nil {
			continue
		}
		for _, m := range b.seen {
			if m.day > today-SeenWindowDays {
				seen[i]++
			}
		}
		tenants := map[hash8]bool{}
		sameTenant := false
		for _, m := range b.reporters {
			if m.day <= today-TTLDays {
				continue // expired, not yet pruned
			}
			reports[i]++
			tenants[m.tenant] = true
			sameTenant = sameTenant || m.tenant == myTenant
		}
		if reports[i] >= 5 && len(tenants) >= 3 {
			confirmed++
		}
		if sameTenant || (reports[i] >= 3 && len(tenants) >= 2) {
			reported++
		}
	}
	seenAgg, reportAgg := kth(seen, MinBandAgreement), kth(reports, MinBandAgreement)
	res := Result{SeenDevices7d: Bucket(seenAgg), Reports: Bucket(reportAgg)}
	switch {
	case confirmed >= MinBandAgreement:
		res.Signal, res.Severity = SignalConfirmed, "danger"
	case reported >= MinBandAgreement:
		res.Signal, res.Severity = SignalReported, "caution"
	case reportAgg == 0 && seenAgg >= 5:
		res.Signal, res.Severity = SignalSeen, "info"
	}
	return res
}

// Verdicts accepted by Report; "legit" is recorded (once per device) but does not count.
var verdicts = map[string]bool{"phishing": true, "spam": true, "legit": true}

// Report records a user report (§11.3). It returns ErrNotFound unless the same tenant analysed the
// mail and got this fingerprint; duplicate reports by the same device return (true, nil).
func (s *Store) Report(tenantID, deviceID string, cross bool, fingerprintID, mailSHA256, verdict string) (bool, error) {
	if !verdicts[verdict] {
		return false, errors.New("unknown verdict")
	}
	refKey := s.mailRefKey(tenantID, mailSHA256)
	repKey := s.reportKey(deviceID, fingerprintID)
	dev, ten := s.deviceHash(deviceID), s.tenantHash(tenantID)
	today := dayNum(s.now())

	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.refs[tenantID][refKey]
	if !ok || !hmac.Equal([]byte(ref.fp), []byte(fingerprintID)) {
		return false, ErrNotFound
	}
	reports := s.reports[tenantID]
	if reports == nil {
		reports = map[key32]int32{}
		s.reports[tenantID] = reports
	}
	if _, done := reports[repKey]; done {
		return true, nil
	}
	reports[repKey] = today
	s.dirty = true
	if verdict == "legit" {
		return false, nil
	}
	scope := s.tenantScope(tenantID)
	for _, gk := range ref.bands {
		bandIn(scope, s.tenantBandKey(tenantID, gk)).addReporter(dev, ten, today)
		if cross {
			bandIn(s.global, gk).addReporter(dev, ten, today)
		}
	}
	s.enforceCapsLocked()
	return false, nil
}

// PurgeTenant removes everything keyed by a tenant: its scope, mail references and reports, and
// its members in global sets (§4.6 tenant deletion).
func (s *Store) PurgeTenant(tenantID string) {
	ten := s.tenantHash(tenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(map[hash8]bool{ten: true}, func(id string) bool { return id == tenantID })
}

// Retain drops all data of tenants not in valid (tenants deleted while the server was down or by
// the CLI).
func (s *Store) Retain(valid map[string]bool) {
	validHashes := map[hash8]bool{}
	for id := range valid {
		validHashes[s.tenantHash(id)] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invalid := map[hash8]bool{}
	for _, b := range s.global {
		for _, set := range []map[hash8]member{b.seen, b.reporters} {
			for _, m := range set {
				if !validHashes[m.tenant] {
					invalid[m.tenant] = true
				}
			}
		}
	}
	s.purgeLocked(invalid, func(id string) bool { return !valid[id] })
}

func (s *Store) purgeLocked(tenantHashes map[hash8]bool, tenantGone func(string) bool) {
	for id := range s.tenants {
		if tenantGone(id) {
			delete(s.tenants, id)
			s.dirty = true
		}
	}
	for id := range s.refs {
		if tenantGone(id) {
			delete(s.refs, id)
			s.dirty = true
		}
	}
	for id := range s.reports {
		if tenantGone(id) {
			delete(s.reports, id)
			s.dirty = true
		}
	}
	if len(tenantHashes) == 0 {
		return
	}
	for k, b := range s.global {
		for _, set := range []map[hash8]member{b.seen, b.reporters} {
			for dev, m := range set {
				if tenantHashes[m.tenant] {
					delete(set, dev)
					s.dirty = true
				}
			}
		}
		if len(b.seen) == 0 && len(b.reporters) == 0 {
			delete(s.global, k)
		}
	}
}

// Expire drops data older than the TTL.
func (s *Store) Expire() {
	today := dayNum(s.now())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(today)
}

func (s *Store) expireLocked(today int32) {
	cutoff := today - TTLDays + 1 // keep days cutoff..today (30 days)
	expireScope := func(scope map[key32]*band) {
		for k, b := range scope {
			for _, set := range []map[hash8]member{b.seen, b.reporters} {
				for dev, m := range set {
					if m.day < cutoff {
						delete(set, dev)
						s.dirty = true
					}
				}
			}
			if len(b.seen) == 0 && len(b.reporters) == 0 {
				delete(scope, k)
			}
		}
	}
	expireScope(s.global)
	for id, scope := range s.tenants {
		expireScope(scope)
		if len(scope) == 0 {
			delete(s.tenants, id)
		}
	}
	for id, refs := range s.refs {
		for k, r := range refs {
			if r.day < cutoff {
				delete(refs, k)
				s.dirty = true
			}
		}
		if len(refs) == 0 {
			delete(s.refs, id)
		}
	}
	for id, reps := range s.reports {
		for k, d := range reps {
			if d < cutoff {
				delete(reps, k)
				s.dirty = true
			}
		}
		if len(reps) == 0 {
			delete(s.reports, id)
		}
	}
}

// enforceCapsLocked evicts the least recently active bands and references when the store grows
// beyond its caps (bounded memory on a 256 MB container).
func (s *Store) enforceCapsLocked() {
	type aged struct {
		day  int32
		drop func()
	}
	nBands := len(s.global)
	for _, scope := range s.tenants {
		nBands += len(scope)
	}
	if nBands > s.MaxBands {
		var all []aged
		for k, b := range s.global {
			k := k
			all = append(all, aged{b.lastDay(), func() { delete(s.global, k) }})
		}
		for _, scope := range s.tenants {
			scope := scope
			for k, b := range scope {
				k := k
				all = append(all, aged{b.lastDay(), func() { delete(scope, k) }})
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].day < all[j].day })
		for _, a := range all[:len(all)-s.MaxBands*9/10] {
			a.drop()
		}
		s.dirty = true
	}
	nRefs := 0
	for _, refs := range s.refs {
		nRefs += len(refs)
	}
	for _, reps := range s.reports {
		nRefs += len(reps)
	}
	if nRefs > s.MaxRefs {
		var all []aged
		for _, refs := range s.refs {
			refs := refs
			for k, r := range refs {
				k := k
				all = append(all, aged{r.day, func() { delete(refs, k) }})
			}
		}
		for _, reps := range s.reports {
			reps := reps
			for k, d := range reps {
				k := k
				all = append(all, aged{d, func() { delete(reps, k) }})
			}
		}
		sort.Slice(all, func(i, j int) bool { return all[i].day < all[j].day })
		if drop := len(all) - s.MaxRefs*9/10; drop > 0 {
			for _, a := range all[:drop] {
				a.drop()
			}
		}
		s.dirty = true
	}
}

// Stats returns entry counts (for tests and the healthcheck).
func (s *Store) Stats() (globalBands, tenantBands, refs, reports int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	globalBands = len(s.global)
	for _, scope := range s.tenants {
		tenantBands += len(scope)
	}
	for _, r := range s.refs {
		refs += len(r)
	}
	for _, r := range s.reports {
		reports += len(r)
	}
	return
}

// --- persistence ---

type fileMember struct {
	D string `json:"d"`
	T string `json:"t"`
	Y int32  `json:"y"`
}

type fileBand struct {
	K string       `json:"k"`
	S []fileMember `json:"s,omitempty"`
	R []fileMember `json:"r,omitempty"`
}

type fileRef struct {
	K  string    `json:"k"`
	FP string    `json:"fp"`
	B  [4]string `json:"b"`
	Y  int32     `json:"y"`
}

type fileReport struct {
	K string `json:"k"`
	Y int32  `json:"y"`
}

type fileFormat struct {
	Version  int                     `json:"version"`
	KeyCheck string                  `json:"key_check"`
	Global   []fileBand              `json:"global"`
	Tenants  map[string][]fileBand   `json:"tenants"`
	Refs     map[string][]fileRef    `json:"mail_refs"`
	Reports  map[string][]fileReport `json:"reports"`
}

var b64 = base64.RawStdEncoding

func (s *Store) keyCheck() string {
	k := s.mac([]byte("key-check"))
	return hex.EncodeToString(k[:8])
}

func encodeBands(scope map[key32]*band) []fileBand {
	out := make([]fileBand, 0, len(scope))
	for k, b := range scope {
		fb := fileBand{K: b64.EncodeToString(k[:])}
		for d, m := range b.seen {
			fb.S = append(fb.S, fileMember{D: b64.EncodeToString(d[:]), T: b64.EncodeToString(m.tenant[:]), Y: m.day})
		}
		for d, m := range b.reporters {
			fb.R = append(fb.R, fileMember{D: b64.EncodeToString(d[:]), T: b64.EncodeToString(m.tenant[:]), Y: m.day})
		}
		out = append(out, fb)
	}
	return out
}

func decodeFixed(s string, out []byte) error {
	raw, err := b64.DecodeString(s)
	if err != nil || len(raw) != len(out) {
		return errors.New("bad hash")
	}
	copy(out, raw)
	return nil
}

func decodeBands(in []fileBand) (map[key32]*band, error) {
	scope := map[key32]*band{}
	for _, fb := range in {
		var k key32
		if err := decodeFixed(fb.K, k[:]); err != nil {
			return nil, err
		}
		b := newBand()
		for i, list := range [][]fileMember{fb.S, fb.R} {
			for _, fm := range list {
				var d, t hash8
				if decodeFixed(fm.D, d[:]) != nil || decodeFixed(fm.T, t[:]) != nil {
					return nil, errors.New("bad member")
				}
				if i == 0 {
					b.seen[d] = member{tenant: t, day: fm.Y}
				} else {
					b.reporters[d] = member{tenant: t, day: fm.Y}
				}
			}
		}
		scope[k] = b
	}
	return scope, nil
}

func (s *Store) decode(data []byte) error {
	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return err
	}
	if f.Version != 1 || f.KeyCheck != s.keyCheck() {
		return errors.New("counter file belongs to another key or version")
	}
	global, err := decodeBands(f.Global)
	if err != nil {
		return err
	}
	tenants := map[string]map[key32]*band{}
	for id, list := range f.Tenants {
		if tenants[id], err = decodeBands(list); err != nil {
			return err
		}
	}
	refs := map[string]map[key32]mailRef{}
	for id, list := range f.Refs {
		m := map[key32]mailRef{}
		for _, fr := range list {
			var k key32
			if err := decodeFixed(fr.K, k[:]); err != nil {
				return err
			}
			r := mailRef{fp: fr.FP, day: fr.Y}
			for i := range fr.B {
				if err := decodeFixed(fr.B[i], r.bands[i][:]); err != nil {
					return err
				}
			}
			m[k] = r
		}
		refs[id] = m
	}
	reports := map[string]map[key32]int32{}
	for id, list := range f.Reports {
		m := map[key32]int32{}
		for _, fr := range list {
			var k key32
			if err := decodeFixed(fr.K, k[:]); err != nil {
				return err
			}
			m[k] = fr.Y
		}
		reports[id] = m
	}
	s.mu.Lock()
	s.global, s.tenants, s.refs, s.reports = global, tenants, refs, reports
	s.mu.Unlock()
	return nil
}

// Save writes the store if it changed since the last save.
func (s *Store) Save() error {
	s.mu.Lock()
	s.expireLocked(dayNum(s.now()))
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	f := fileFormat{Version: 1, KeyCheck: s.keyCheck(), Global: encodeBands(s.global),
		Tenants: map[string][]fileBand{}, Refs: map[string][]fileRef{}, Reports: map[string][]fileReport{}}
	for id, scope := range s.tenants {
		f.Tenants[id] = encodeBands(scope)
	}
	for id, refs := range s.refs {
		for k, r := range refs {
			fr := fileRef{K: b64.EncodeToString(k[:]), FP: r.fp, Y: r.day}
			for i := range r.bands {
				fr.B[i] = b64.EncodeToString(r.bands[i][:])
			}
			f.Refs[id] = append(f.Refs[id], fr)
		}
	}
	for id, reps := range s.reports {
		for k, d := range reps {
			f.Reports[id] = append(f.Reports[id], fileReport{K: b64.EncodeToString(k[:]), Y: d})
		}
	}
	s.dirty = false
	s.mu.Unlock()
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(s.path, data, 0o600); err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("saving campaign counters: %w", err)
	}
	return nil
}
