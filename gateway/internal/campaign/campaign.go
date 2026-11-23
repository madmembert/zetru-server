// Package campaign keeps the campaign counters of concept §6.5, §6.6 and §13.2.
//
// The analyzer returns four 16-bit SimHash bands per mail. The gateway keys each band with K_fp
// (HMAC-SHA256(K_fp, band_index ‖ band)) and keeps, per keyed band, two capped sets of keyed
// 64-bit hashes: the devices that saw a mail with this band (with their tenant hash and the last
// UTC day) and the devices that reported it. No text, no band value and no mail hash is stored in
// clear. Everything expires 30 days after its last day.
//
// Design choices (DECISIONS.md, "Campaign counters" and "Memory"):
//   - Capped sets instead of HyperLogLog sketches: the thresholds need exact counts only up to 20
//     and a membership test ("reported by a device of the same tenant"), which sketches cannot give.
//     Sets hold at most 32 members (reporters: at most 5 per tenant); counts saturate there. A set is
//     a small slice, not a map: it never holds more than 32 entries.
//   - A mail matches a campaign only when at least two of its four bands agree (the count used is
//     the second-highest per-band count). Matching on any single 16-bit band would make an unrelated
//     mail collide with a reported band with probability 4·k/65536 for k reported bands, which
//     would put G2 gates on legitimate mail.
//   - Counting happens in the tenant's own scope; tenants whose policy enables cross-tenant counting
//     also count in, and read from, the global scope.
//   - Memory is bounded by two caps (bands of all scopes; mail references plus reports of all
//     tenants). When a cap is exceeded, entries are evicted from the largest scopes first (water
//     filling), so one tenant cannot evict another tenant's counters while it holds more than its
//     share. Inside a scope, bands without reporters go before bands with reporters, oldest first.
//   - The file is a streamed binary record format (bounded memory for save and load).
package campaign

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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
	// Defaults of the pi profile (config.Profile carries the per-profile values).
	DefaultMaxBands = 40_000
	DefaultMaxRefs  = 40_000
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

// member is one device in a band's seen or reporter set (20 bytes).
type member struct {
	device hash8
	tenant hash8
	day    int32
}

type band struct {
	seen      []member
	reporters []member
}

func (b *band) lastDay() int32 {
	var last int32
	for _, m := range b.seen {
		last = max(last, m.day)
	}
	for _, m := range b.reporters {
		last = max(last, m.day)
	}
	return last
}

// removeOldest drops the member with the smallest day (order inside a set does not matter).
func removeOldest(set []member) []member {
	oldest := 0
	for i := range set {
		if set[i].day < set[oldest].day {
			oldest = i
		}
	}
	set[oldest] = set[len(set)-1]
	return set[:len(set)-1]
}

func (b *band) addSeen(device, tenant hash8, day int32) {
	for i := range b.seen {
		if b.seen[i].device == device {
			b.seen[i].day = max(b.seen[i].day, day)
			b.seen[i].tenant = tenant
			return
		}
	}
	if len(b.seen) >= SetCap {
		b.seen = removeOldest(b.seen)
	}
	b.seen = append(b.seen, member{device: device, tenant: tenant, day: day})
}

func (b *band) addReporter(device, tenant hash8, day int32) {
	perTenant := 0
	for _, m := range b.reporters {
		if m.device == device {
			return
		}
		if m.tenant == tenant {
			perTenant++
		}
	}
	if perTenant >= ReportersPerTen {
		return
	}
	if len(b.reporters) >= SetCap {
		b.reporters = removeOldest(b.reporters)
	}
	b.reporters = append(b.reporters, member{device: device, tenant: tenant, day: day})
}

// filter keeps the members for which keep returns true and reports whether any was dropped.
func filter(set []member, keep func(member) bool) ([]member, bool) {
	out := set[:0]
	for _, m := range set {
		if keep(m) {
			out = append(out, m)
		}
	}
	dropped := len(out) != len(set)
	if len(out) == 0 {
		return nil, dropped
	}
	return out, dropped
}

type mailRef struct {
	fp    [16]byte
	bands [4]key32
	day   int32
}

// Limits are the store's caps; zero values select the defaults.
type Limits struct {
	MaxBands int // keyed bands of the global and all tenant scopes together
	MaxRefs  int // mail references and reports of all tenants together
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

	// New global bands created per tenant on globalDay (in memory only), see GlobalNewPerDay.
	globalDay int32
	globalNew map[string]int
}

// Open creates a store keyed with kfp and loads path if it exists. A file written with a
// different K_fp, an older format, or a corrupt file is deleted because its hashes are
// meaningless (and must not outlive the 30-day retention of §14.2 as a moved-aside copy).
func Open(path string, kfp []byte, now func() time.Time, lim Limits) (*Store, error) {
	if len(kfp) != 32 {
		return nil, errors.New("K_fp must be 32 bytes")
	}
	if now == nil {
		now = time.Now
	}
	if lim.MaxBands <= 0 {
		lim.MaxBands = DefaultMaxBands
	}
	if lim.MaxRefs <= 0 {
		lim.MaxRefs = DefaultMaxRefs
	}
	s := &Store{kfp: append([]byte(nil), kfp...), now: now, path: path, MaxBands: lim.MaxBands, MaxRefs: lim.MaxRefs}
	s.reset()
	if path == "" {
		return s, nil
	}
	_ = fsutil.RemoveIfExists(path + ".discarded") // left behind by earlier versions
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	err = s.decode(bufio.NewReaderSize(f, 64<<10))
	_ = f.Close()
	if err != nil {
		s.reset()
		if err := fsutil.RemoveIfExists(path); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	s.expireLocked(dayNum(now()))
	s.enforceCapsLocked()
	s.mu.Unlock()
	return s, nil
}

func (s *Store) reset() {
	s.global, s.tenants = map[key32]*band{}, map[string]map[key32]*band{}
	s.refs, s.reports = map[string]map[key32]mailRef{}, map[string]map[key32]int32{}
	s.globalNew = map[string]int{}
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

func (s *Store) fingerprint(keys [4]key32) [16]byte {
	k := s.mac([]byte("fingerprint"), keys[0][:], keys[1][:], keys[2][:], keys[3][:])
	var fp [16]byte
	copy(fp[:], k[:16])
	return fp
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
		b = &band{}
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

// GlobalNewPerDay is how many new global bands one tenant may create per UTC day: a tenth of the
// band cap. Existing global bands are always updated; beyond the allowance a cross-tenant tenant
// counts in, and reads from, its own scope only for the new bands.
func (s *Store) GlobalNewPerDay() int { return max(s.MaxBands/10, 1) }

func (s *Store) mayCreateGlobalLocked(tenantID string, today int32) bool {
	if today != s.globalDay {
		s.globalDay, s.globalNew = today, map[string]int{}
	}
	if s.globalNew[tenantID] >= s.GlobalNewPerDay() {
		return false
	}
	s.globalNew[tenantID]++
	return true
}

// Observe records that a device of a tenant analysed a mail with the given bands and returns the
// fingerprint and campaign signal. cross selects cross-tenant counting (tenant policy).
func (s *Store) Observe(tenantID, deviceID string, cross bool, bands [4]uint16, mailSHA256 string) Result {
	var globalKeys, tenantKeys [4]key32
	for i, v := range bands {
		globalKeys[i] = s.GlobalBandKey(i, v)
		tenantKeys[i] = s.tenantBandKey(tenantID, globalKeys[i])
	}
	fp := s.fingerprint(globalKeys)
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
			gb := s.global[globalKeys[i]]
			if gb == nil && s.mayCreateGlobalLocked(tenantID, today) {
				gb = bandIn(s.global, globalKeys[i])
			}
			if gb != nil {
				gb.addSeen(dev, ten, today)
				read[i] = gb
			}
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
	res.FingerprintID = hex.EncodeToString(fp[:])
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
	fp, err := hex.DecodeString(fingerprintID)
	if err != nil || len(fp) != 16 {
		return false, ErrNotFound
	}
	refKey := s.mailRefKey(tenantID, mailSHA256)
	repKey := s.reportKey(deviceID, fingerprintID)
	dev, ten := s.deviceHash(deviceID), s.tenantHash(tenantID)
	today := dayNum(s.now())

	s.mu.Lock()
	defer s.mu.Unlock()
	ref, ok := s.refs[tenantID][refKey]
	if !ok || !hmac.Equal(ref.fp[:], fp) {
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
		s.enforceCapsLocked()
		return false, nil
	}
	scope := s.tenantScope(tenantID)
	for _, gk := range ref.bands {
		bandIn(scope, s.tenantBandKey(tenantID, gk)).addReporter(dev, ten, today)
		if cross {
			// Reports are bounded by the per-device report quota, so they may always create a
			// global band (unlike sightings, see GlobalNewPerDay).
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
		for _, set := range [][]member{b.seen, b.reporters} {
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
	for id := range s.globalNew {
		if tenantGone(id) {
			delete(s.globalNew, id)
		}
	}
	if len(tenantHashes) == 0 {
		return
	}
	keep := func(m member) bool { return !tenantHashes[m.tenant] }
	for k, b := range s.global {
		var d1, d2 bool
		b.seen, d1 = filter(b.seen, keep)
		b.reporters, d2 = filter(b.reporters, keep)
		if d1 || d2 {
			s.dirty = true
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
	keep := func(m member) bool { return m.day >= cutoff }
	expireScope := func(scope map[key32]*band) {
		for k, b := range scope {
			var d1, d2 bool
			b.seen, d1 = filter(b.seen, keep)
			b.reporters, d2 = filter(b.reporters, keep)
			if d1 || d2 {
				s.dirty = true
			}
			if len(b.seen) == 0 && len(b.reporters) == 0 {
				delete(scope, k)
				s.dirty = true
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

// waterLevel returns the largest level L such that cutting every size above L down to L removes at
// least need entries. Scopes at or below L are left alone.
func waterLevel(sizes []int, need int) int {
	sorted := append([]int(nil), sizes...)
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))
	prefix := 0
	for k, size := range sorted {
		prefix += size
		level := (prefix - need) / (k + 1)
		next := 0
		if k+1 < len(sorted) {
			next = sorted[k+1]
		}
		if level >= next {
			return max(level, 0)
		}
	}
	return 0
}

// enforceCapsLocked keeps the store within its caps (bounded memory on a 256 MB container). When a
// cap is exceeded it evicts down to 90 % of the cap, taking entries only from the largest scopes:
// a tenant (or the global scope) loses entries only while it holds more than the others.
func (s *Store) enforceCapsLocked() {
	s.enforceBandCapLocked()
	s.enforceRefCapLocked()
}

func (s *Store) enforceBandCapLocked() {
	scopes := make([]map[key32]*band, 0, len(s.tenants)+1)
	total := len(s.global)
	scopes = append(scopes, s.global)
	for _, scope := range s.tenants {
		scopes = append(scopes, scope)
		total += len(scope)
	}
	if total <= s.MaxBands {
		return
	}
	sizes := make([]int, len(scopes))
	for i, scope := range scopes {
		sizes[i] = len(scope)
	}
	level := waterLevel(sizes, total-s.MaxBands*9/10)
	for _, scope := range scopes {
		if n := len(scope) - level; n > 0 {
			evictBands(scope, n)
		}
	}
	for id, scope := range s.tenants {
		if len(scope) == 0 {
			delete(s.tenants, id)
		}
	}
	s.dirty = true
}

// evictBands removes n bands of a scope: bands without reporters first (reports are scarce, a
// flood of sightings must not erase them), each group oldest first.
func evictBands(scope map[key32]*band, n int) {
	type aged struct {
		k        key32
		reported bool
		day      int32
	}
	all := make([]aged, 0, len(scope))
	for k, b := range scope {
		all = append(all, aged{k, len(b.reporters) > 0, b.lastDay()})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].reported != all[j].reported {
			return !all[i].reported
		}
		return all[i].day < all[j].day
	})
	for _, a := range all[:min(n, len(all))] {
		delete(scope, a.k)
	}
}

func (s *Store) enforceRefCapLocked() {
	ids := make([]string, 0, len(s.refs)+len(s.reports))
	seen := map[string]bool{}
	for id := range s.refs {
		ids, seen[id] = append(ids, id), true
	}
	for id := range s.reports {
		if !seen[id] {
			ids = append(ids, id)
		}
	}
	total := 0
	sizes := make([]int, len(ids))
	for i, id := range ids {
		sizes[i] = len(s.refs[id]) + len(s.reports[id])
		total += sizes[i]
	}
	if total <= s.MaxRefs {
		return
	}
	level := waterLevel(sizes, total-s.MaxRefs*9/10)
	for i, id := range ids {
		if n := sizes[i] - level; n > 0 {
			s.evictRefsLocked(id, n)
		}
	}
	s.dirty = true
}

// evictRefsLocked removes the n oldest mail references and reports of one tenant.
func (s *Store) evictRefsLocked(tenantID string, n int) {
	type aged struct {
		k      key32
		report bool
		day    int32
	}
	refs, reps := s.refs[tenantID], s.reports[tenantID]
	all := make([]aged, 0, len(refs)+len(reps))
	for k, r := range refs {
		all = append(all, aged{k, false, r.day})
	}
	for k, d := range reps {
		all = append(all, aged{k, true, d})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].day < all[j].day })
	for _, a := range all[:min(n, len(all))] {
		if a.report {
			delete(reps, a.k)
		} else {
			delete(refs, a.k)
		}
	}
	if len(refs) == 0 {
		delete(s.refs, tenantID)
	}
	if len(reps) == 0 {
		delete(s.reports, tenantID)
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

// TenantStats returns the band, reference and report counts of one tenant (for tests).
func (s *Store) TenantStats(tenantID string) (bands, refs, reports int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.tenants[tenantID]), len(s.refs[tenantID]), len(s.reports[tenantID])
}

// --- persistence ---
//
// File format 2 (binary, big-endian):
//
//	header  "ZCMP" | version 2 (1 byte) | first 8 bytes of HMAC(K_fp, "key-check")
//	record  'G' key(32) nSeen(1) nRep(1) member*         global band
//	        'T' tenant key(32) nSeen(1) nRep(1) member*  tenant band
//	        'R' tenant key(32) fp(16) bands(4×32) day(4) mail reference
//	        'P' tenant key(32) day(4)                    report
//	        'E' SHA-256 of everything before it, 'E' included (32)
//	member  device(8) tenant(8) day(4);  tenant = length (1) + ID bytes (1–64)
//
// Save streams records in batches under short lock sections; Open decodes record by record and
// enforces the caps while loading, so neither builds a second copy of the store.

const (
	fileMagic   = "ZCMP"
	fileVersion = 2
	saveBatch   = 256
	maxTenantID = 64
)

func (s *Store) keyCheck() []byte {
	k := s.mac([]byte("key-check"))
	return k[:8]
}

type recordWriter struct{ buf bytes.Buffer }

func (w *recordWriter) tenant(id string) {
	w.buf.WriteByte(byte(len(id)))
	w.buf.WriteString(id)
}

func (w *recordWriter) day(d int32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(d))
	w.buf.Write(b[:])
}

func (w *recordWriter) members(set []member) {
	for _, m := range set {
		w.buf.Write(m.device[:])
		w.buf.Write(m.tenant[:])
		w.day(m.day)
	}
}

func (w *recordWriter) band(kind byte, tenantID string, k key32, b *band) {
	w.buf.WriteByte(kind)
	if kind == 'T' {
		w.tenant(tenantID)
	}
	w.buf.Write(k[:])
	w.buf.WriteByte(byte(len(b.seen)))
	w.buf.WriteByte(byte(len(b.reporters)))
	w.members(b.seen)
	w.members(b.reporters)
}

type scopeKeys struct {
	id   string
	keys []key32
}

func keysOf[V any](m map[key32]V) []key32 {
	out := make([]key32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Save writes the store if it changed since the last save. Only the list of keys is copied; the
// records are encoded in batches of saveBatch under the lock and written to disk outside it.
func (s *Store) Save() error {
	s.mu.Lock()
	s.expireLocked(dayNum(s.now()))
	if !s.dirty || s.path == "" {
		s.mu.Unlock()
		return nil
	}
	s.dirty = false
	global := keysOf(s.global)
	var tenants, refs, reports []scopeKeys
	for id, scope := range s.tenants {
		tenants = append(tenants, scopeKeys{id, keysOf(scope)})
	}
	for id, m := range s.refs {
		refs = append(refs, scopeKeys{id, keysOf(m)})
	}
	for id, m := range s.reports {
		reports = append(reports, scopeKeys{id, keysOf(m)})
	}
	keyCheck := s.keyCheck()
	s.mu.Unlock()

	err := fsutil.WriteStreamAtomic(s.path, 0o600, func(out io.Writer) error {
		h := sha256.New()
		w := io.MultiWriter(out, h)
		if _, err := w.Write(append(append([]byte(fileMagic), fileVersion), keyCheck...)); err != nil {
			return err
		}
		// batch encodes the records of keys in groups of saveBatch with fn under the lock and
		// writes each group outside it.
		var rw recordWriter
		batch := func(keys []key32, fn func(rw *recordWriter, k key32)) error {
			for i := 0; i < len(keys); i += saveBatch {
				rw.buf.Reset()
				s.mu.Lock()
				for _, k := range keys[i:min(i+saveBatch, len(keys))] {
					fn(&rw, k)
				}
				s.mu.Unlock()
				if _, err := w.Write(rw.buf.Bytes()); err != nil {
					return err
				}
			}
			return nil
		}
		if err := batch(global, func(rw *recordWriter, k key32) {
			if b := s.global[k]; b != nil {
				rw.band('G', "", k, b)
			}
		}); err != nil {
			return err
		}
		for _, sk := range tenants {
			if err := batch(sk.keys, func(rw *recordWriter, k key32) {
				if b := s.tenants[sk.id][k]; b != nil {
					rw.band('T', sk.id, k, b)
				}
			}); err != nil {
				return err
			}
		}
		for _, sk := range refs {
			if err := batch(sk.keys, func(rw *recordWriter, k key32) {
				r, ok := s.refs[sk.id][k]
				if !ok {
					return
				}
				rw.buf.WriteByte('R')
				rw.tenant(sk.id)
				rw.buf.Write(k[:])
				rw.buf.Write(r.fp[:])
				for i := range r.bands {
					rw.buf.Write(r.bands[i][:])
				}
				rw.day(r.day)
			}); err != nil {
				return err
			}
		}
		for _, sk := range reports {
			if err := batch(sk.keys, func(rw *recordWriter, k key32) {
				d, ok := s.reports[sk.id][k]
				if !ok {
					return
				}
				rw.buf.WriteByte('P')
				rw.tenant(sk.id)
				rw.buf.Write(k[:])
				rw.day(d)
			}); err != nil {
				return err
			}
		}
		if _, err := w.Write([]byte{'E'}); err != nil {
			return err
		}
		_, err := out.Write(h.Sum(nil))
		return err
	})
	if err != nil {
		s.mu.Lock()
		s.dirty = true
		s.mu.Unlock()
		return fmt.Errorf("saving campaign counters: %w", err)
	}
	return nil
}

// recordReader reads the file format above, hashing everything it reads.
type recordReader struct {
	r   *bufio.Reader
	h   io.Writer
	err error
	buf [32]byte
}

func (rr *recordReader) read(n int) []byte {
	if rr.err != nil {
		return rr.buf[:n]
	}
	if _, rr.err = io.ReadFull(rr.r, rr.buf[:n]); rr.err == nil {
		rr.h.Write(rr.buf[:n])
	}
	return rr.buf[:n]
}

func (rr *recordReader) byte() byte { return rr.read(1)[0] }

func (rr *recordReader) key() key32 {
	var k key32
	copy(k[:], rr.read(32))
	return k
}

func (rr *recordReader) day() int32 { return int32(binary.BigEndian.Uint32(rr.read(4))) }

func (rr *recordReader) tenant() string {
	n := int(rr.byte())
	if rr.err == nil && (n < 1 || n > maxTenantID) {
		rr.err = errors.New("bad tenant ID length")
	}
	if rr.err != nil {
		return ""
	}
	id := make([]byte, n)
	if _, rr.err = io.ReadFull(rr.r, id); rr.err == nil {
		rr.h.Write(id)
	}
	return string(id)
}

func (rr *recordReader) members(n int) []member {
	if n > SetCap {
		rr.err = errors.New("set larger than its cap")
	}
	if rr.err != nil || n == 0 {
		return nil
	}
	set := make([]member, n)
	for i := range set {
		copy(set[i].device[:], rr.read(8))
		copy(set[i].tenant[:], rr.read(8))
		set[i].day = rr.day()
	}
	return set
}

func (rr *recordReader) band() (key32, *band) {
	k := rr.key()
	nSeen, nRep := int(rr.byte()), int(rr.byte())
	b := &band{seen: rr.members(nSeen)}
	b.reporters = rr.members(nRep)
	return k, b
}

// decode loads a file written by Save into the (empty) store. While loading it enforces the caps
// whenever a cap is exceeded by 10 %, so a file written under larger caps (another profile) cannot
// make the load use more memory than the caps allow.
func (s *Store) decode(r *bufio.Reader) error {
	h := sha256.New()
	rr := &recordReader{r: r, h: h}
	head := rr.read(len(fileMagic) + 1 + 8)
	if rr.err != nil || string(head[:4]) != fileMagic || head[4] != fileVersion || !hmac.Equal(head[5:13], s.keyCheck()) {
		return errors.New("counter file belongs to another key or version")
	}
	nBands, nRefs := 0, 0
	for {
		kind := rr.byte()
		if rr.err != nil {
			return rr.err
		}
		switch kind {
		case 'G':
			k, b := rr.band()
			if rr.err == nil {
				s.global[k] = b
				nBands++
			}
		case 'T':
			id := rr.tenant()
			k, b := rr.band()
			if rr.err == nil {
				s.tenantScope(id)[k] = b
				nBands++
			}
		case 'R':
			id := rr.tenant()
			k := rr.key()
			var ref mailRef
			copy(ref.fp[:], rr.read(16))
			for i := range ref.bands {
				ref.bands[i] = rr.key()
			}
			ref.day = rr.day()
			if rr.err == nil {
				if s.refs[id] == nil {
					s.refs[id] = map[key32]mailRef{}
				}
				s.refs[id][k] = ref
				nRefs++
			}
		case 'P':
			id := rr.tenant()
			k := rr.key()
			d := rr.day()
			if rr.err == nil {
				if s.reports[id] == nil {
					s.reports[id] = map[key32]int32{}
				}
				s.reports[id][k] = d
				nRefs++
			}
		case 'E':
			sum := h.Sum(nil)
			if !hmac.Equal(rr.read(32), sum) || rr.err != nil {
				return errors.New("counter file checksum mismatch")
			}
			if _, err := r.ReadByte(); err != io.EOF {
				return errors.New("trailing data after the counter file")
			}
			return nil
		default:
			return errors.New("unknown record type")
		}
		if rr.err != nil {
			return rr.err
		}
		if nBands > s.MaxBands+s.MaxBands/10 || nRefs > s.MaxRefs+s.MaxRefs/10 {
			s.enforceCapsLocked() // Open has not published the store yet: no lock needed
			nBands, nRefs = s.countsLocked()
		}
	}
}

func (s *Store) countsLocked() (bands, refs int) {
	bands = len(s.global)
	for _, scope := range s.tenants {
		bands += len(scope)
	}
	for _, m := range s.refs {
		refs += len(m)
	}
	for _, m := range s.reports {
		refs += len(m)
	}
	return bands, refs
}
