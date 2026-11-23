package campaign

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

var kfp = bytes.Repeat([]byte{7}, 32)

func dev(t, d int) (string, string) {
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", t), fmt.Sprintf("11111111-0000-4000-8000-%06d%06d", t, d)
}

const mail = "9f2c000000000000000000000000000000000000000000000000000000000000"

var bandsA = [4]uint16{0x1111, 0x2222, 0x3333, 0x4444}

func TestBucket(t *testing.T) {
	want := map[int]int{0: 0, 1: 1, 2: 2, 4: 2, 5: 5, 19: 5, 20: 20, 500: 20}
	for n, b := range want {
		if Bucket(n) != b {
			t.Errorf("Bucket(%d) = %d, want %d", n, Bucket(n), b)
		}
	}
}

func TestParseBands(t *testing.T) {
	got, err := ParseBands([]string{"0001", "ffff", "a0b1", "0000"})
	if err != nil || got != [4]uint16{1, 0xffff, 0xa0b1, 0} {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range [][]string{nil, {"0001", "0002", "0003"}, {"0001", "0002", "0003", "FFFF"}, {"001", "0002", "0003", "0004"}, {"0001", "0002", "0003", "00004"}} {
		if _, err := ParseBands(bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

func TestSeenThresholdAndWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s, _ := Open("", kfp, func() time.Time { return now }, Limits{})
	for d := 1; d <= 4; d++ {
		ten, device := dev(1, d)
		if r := s.Observe(ten, device, false, bandsA, mail); r.Signal != "" {
			t.Fatalf("signal after %d devices: %s", d, r.Signal)
		}
	}
	ten, device := dev(1, 5)
	r := s.Observe(ten, device, false, bandsA, mail)
	if r.Signal != SignalSeen || r.Severity != "info" || r.SeenDevices7d != 5 || r.Reports != 0 || len(r.FingerprintID) != 32 {
		t.Fatalf("5 devices: %+v", r)
	}
	// The same device again does not increase the distinct count.
	if r2 := s.Observe(ten, device, false, bandsA, mail); r2.SeenDevices7d != 5 || r2.FingerprintID != r.FingerprintID {
		t.Fatalf("repeat observation: %+v", r2)
	}
	// After 7 days without sightings, SEEN stops.
	now = now.Add(7 * 24 * time.Hour)
	ten6, dev6 := dev(1, 6)
	if r := s.Observe(ten6, dev6, false, bandsA, mail); r.Signal != "" || r.SeenDevices7d != 1 {
		t.Fatalf("seen window not applied: %+v", r)
	}
}

func TestSameTenantReportAndBandAgreement(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s, _ := Open("", kfp, func() time.Time { return now }, Limits{})
	ten, a := dev(1, 1)
	_, b := dev(1, 2)
	r := s.Observe(ten, a, false, bandsA, mail)
	if dup, err := s.Report(ten, a, false, r.FingerprintID, mail, "phishing"); err != nil || dup {
		t.Fatalf("report: %v %v", dup, err)
	}
	if dup, err := s.Report(ten, a, false, r.FingerprintID, mail, "phishing"); err != nil || !dup {
		t.Fatalf("duplicate report: %v %v", dup, err)
	}
	// A similar mail sharing 2 of 4 bands is a match.
	similar := [4]uint16{0x1111, 0x2222, 0x9999, 0x8888}
	got := s.Observe(ten, b, false, similar, "aa"+mail[2:])
	if got.Signal != SignalReported || got.Severity != "caution" || got.Reports != 1 {
		t.Fatalf("same-tenant report not applied: %+v", got)
	}
	// A mail sharing only 1 band is not.
	single := [4]uint16{0x1111, 0x7777, 0x9999, 0x8888}
	if got := s.Observe(ten, b, false, single, "bb"+mail[2:]); got.Signal != "" || got.Reports != 0 {
		t.Fatalf("single-band collision counted: %+v", got)
	}
}

func TestReportPreconditions(t *testing.T) {
	s, _ := Open("", kfp, nil, Limits{})
	ten, a := dev(1, 1)
	other, b := dev(2, 1)
	r := s.Observe(ten, a, true, bandsA, mail)
	if _, err := s.Report(other, b, true, r.FingerprintID, mail, "spam"); err != ErrNotFound {
		t.Fatalf("report without prior analysis by the tenant: %v", err)
	}
	if _, err := s.Report(ten, a, true, "00000000000000000000000000000000", mail, "spam"); err != ErrNotFound {
		t.Fatalf("report with wrong fingerprint: %v", err)
	}
	if _, err := s.Report(ten, a, true, r.FingerprintID, mail, "unsure"); err == nil {
		t.Fatal("unknown verdict accepted")
	}
	// legit is recorded once but does not count as a report.
	if _, err := s.Report(ten, a, true, r.FingerprintID, mail, "legit"); err != nil {
		t.Fatal(err)
	}
	_, c := dev(1, 2)
	if got := s.Observe(ten, c, true, bandsA, mail); got.Reports != 0 || got.Signal != "" {
		t.Fatalf("legit report counted: %+v", got)
	}
}

// observeAndReport lets device d of tenant tn analyse the mail and report it.
func observeAndReport(t *testing.T, s *Store, tn, d int, cross bool) {
	t.Helper()
	ten, device := dev(tn, d)
	r := s.Observe(ten, device, cross, bandsA, mail)
	if _, err := s.Report(ten, device, cross, r.FingerprintID, mail, "phishing"); err != nil {
		t.Fatal(err)
	}
}

func TestCrossTenantThresholds(t *testing.T) {
	s, _ := Open("", kfp, nil, Limits{})
	observer := func() Result {
		ten, device := dev(9, 1)
		return s.Observe(ten, device, true, bandsA, mail)
	}
	observeAndReport(t, s, 1, 1, true)
	observeAndReport(t, s, 2, 1, true)
	if r := observer(); r.Signal != "" || r.Reports != 2 {
		t.Fatalf("2 devices in 2 tenants: %+v", r)
	}
	observeAndReport(t, s, 2, 2, true)
	if r := observer(); r.Signal != SignalReported || r.Reports != 2 {
		t.Fatalf("3 devices in 2 tenants: %+v", r)
	}
	observeAndReport(t, s, 1, 2, true)
	observeAndReport(t, s, 1, 3, true)
	if r := observer(); r.Signal != SignalReported || r.Reports != 5 {
		t.Fatalf("5 devices in 2 tenants must not confirm: %+v", r)
	}
	observeAndReport(t, s, 3, 1, true)
	if r := observer(); r.Signal != SignalConfirmed || r.Severity != "danger" || r.Reports != 5 {
		t.Fatalf("6 devices in 3 tenants: %+v", r)
	}
	// A tenant without cross-tenant counting sees none of this.
	ten, device := dev(8, 1)
	if r := s.Observe(ten, device, false, bandsA, mail); r.Signal != "" || r.Reports != 0 {
		t.Fatalf("isolation broken: %+v", r)
	}
}

func TestPerTenantReporterCap(t *testing.T) {
	s, _ := Open("", kfp, nil, Limits{})
	for d := 1; d <= 8; d++ {
		observeAndReport(t, s, 1, d, true)
	}
	ten, device := dev(9, 1)
	// 8 reporters of one tenant count as 5, and reports from a single other tenant never reach
	// the cross-tenant thresholds (>= 2 tenants), so no signal and no SEEN (there are reports).
	if r := s.Observe(ten, device, true, bandsA, mail); r.Reports != 5 || r.Signal != "" {
		t.Fatalf("one tenant must not exceed 5 reporters per band: %+v", r)
	}
}

func TestExpiryPurgeAndPersistence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "campaign.json")
	s, err := Open(path, kfp, func() time.Time { return now }, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	observeAndReport(t, s, 1, 1, true)
	observeAndReport(t, s, 2, 1, false)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("counter file mode")
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte(mail)) || bytes.Contains(data, []byte("1111")) {
		t.Fatal("clear mail hash or band value persisted")
	}
	loaded, err := Open(path, kfp, func() time.Time { return now }, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	g1, t1, r1, p1 := s.Stats()
	g2, t2, r2, p2 := loaded.Stats()
	if g1 != g2 || t1 != t2 || r1 != r2 || p1 != p2 || g1 != 4 || t1 != 8 || r1 != 2 || p1 != 2 {
		t.Fatalf("round trip: %d/%d/%d/%d vs %d/%d/%d/%d", g1, t1, r1, p1, g2, t2, r2, p2)
	}
	// Another K_fp cannot read the file; it is deleted, not moved aside (GO-17).
	if err := os.WriteFile(path+".discarded", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup, _ := os.ReadFile(path)
	other, _ := Open(path, bytes.Repeat([]byte{8}, 32), func() time.Time { return now }, Limits{})
	if g, _, _, _ := other.Stats(); g != 0 {
		t.Fatal("counters of another key were loaded")
	}
	for _, p := range []string{path, path + ".discarded"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s survived: counters of an unusable file must not outlive their retention", filepath.Base(p))
		}
	}
	_ = os.WriteFile(path, backup, 0o600)
	// Tenant purge removes its scope, refs, reports and global members.
	ten1, _ := dev(1, 1)
	loaded.PurgeTenant(ten1)
	if g, tb, r, p := loaded.Stats(); g != 0 || tb != 4 || r != 1 || p != 1 {
		t.Fatalf("purge: %d/%d/%d/%d", g, tb, r, p)
	}
	ten2, _ := dev(2, 1)
	loaded.Retain(map[string]bool{ten1: true})
	if _, tb, r, p := loaded.Stats(); tb != 0 || r != 0 || p != 0 {
		t.Fatal("retain kept a deleted tenant")
	}
	_ = ten2
	// Expiry after 30 days.
	observeAndReport(t, loaded, 3, 1, true)
	now = now.Add(30 * 24 * time.Hour)
	loaded.Expire()
	if g, tb, r, p := loaded.Stats(); g+tb+r+p != 0 {
		t.Fatalf("not expired after 30 days: %d/%d/%d/%d", g, tb, r, p)
	}
}

func TestCapsBoundMemory(t *testing.T) {
	s, _ := Open("", kfp, nil, Limits{MaxBands: 100, MaxRefs: 50})
	ten, device := dev(1, 1)
	for i := 0; i < 200; i++ {
		b := [4]uint16{uint16(i), uint16(i + 1000), uint16(i + 2000), uint16(i + 3000)}
		s.Observe(ten, device, true, b, fmt.Sprintf("%064x", i))
	}
	g, tb, r, _ := s.Stats()
	if g+tb > 100 || r > 50 {
		t.Fatalf("caps not enforced: bands %d refs %d", g+tb, r)
	}
}

func TestFileFormatRejectsDamage(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "campaign.dat")
	s, _ := Open(path, kfp, func() time.Time { return now }, Limits{})
	observeAndReport(t, s, 1, 1, true)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	good, _ := os.ReadFile(path)
	if !bytes.HasPrefix(good, []byte("ZCMP\x02")) {
		t.Fatalf("unexpected header %q", good[:5])
	}
	damaged := map[string][]byte{
		"flipped byte": append(append([]byte{}, good[:40]...), append([]byte{good[40] ^ 1}, good[41:]...)...),
		"truncated":    good[:len(good)-10],
		"trailing":     append(append([]byte{}, good...), 0),
		"legacy json":  []byte(`{"version":1,"key_check":"x","global":[]}`),
	}
	for name, data := range damaged {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		loaded, err := Open(path, kfp, func() time.Time { return now }, Limits{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if g, tb, r, p := loaded.Stats(); g+tb+r+p != 0 {
			t.Errorf("%s: damaged file loaded", name)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("%s: damaged file kept", name)
		}
	}
}

func TestWaterLevel(t *testing.T) {
	cases := []struct {
		sizes      []int
		need, want int
	}{
		{[]int{100, 10, 10}, 50, 50}, // only the big scope is cut
		{[]int{100, 60, 10}, 60, 50}, // both big scopes are cut to the same level
		{[]int{30, 30, 30}, 30, 20},  // equal scopes share the cut
		{[]int{100}, 150, 0},         // more than everything: level 0
		{[]int{0, 0, 90}, 9, 81},     // empty scopes do not matter
	}
	for _, c := range cases {
		level := waterLevel(c.sizes, c.need)
		removed := 0
		for _, n := range c.sizes {
			removed += max(n-level, 0)
		}
		if level != c.want || (c.want > 0 && removed < c.need) {
			t.Errorf("waterLevel(%v, %d) = %d (removes %d), want %d", c.sizes, c.need, level, removed, c.want)
		}
	}
}

// TestEvictionStaysInsideTheFloodingTenant is the regression test for GO-05: one tenant that adds
// distinct mails as fast as it can must not evict another tenant's counters, reporters or mail
// references, and a flood of sightings must not evict reported global bands.
func TestEvictionStaysInsideTheFloodingTenant(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s, _ := Open("", kfp, func() time.Time { return now }, Limits{MaxBands: 2000, MaxRefs: 400})
	victimTenant, victim := dev(1, 1)
	r := s.Observe(victimTenant, victim, true, bandsA, mail)
	if _, err := s.Report(victimTenant, victim, true, r.FingerprintID, mail, "phishing"); err != nil {
		t.Fatal(err)
	}
	vBands, vRefs, vReports := s.TenantStats(victimTenant)

	attackerTenant, attacker := dev(2, 1)
	for i := 0; i < 5000; i++ {
		now = now.Add(time.Minute) // the attacker's entries are always the newest
		b := [4]uint16{uint16(i), uint16(i + 7), uint16(i + 13), uint16(i + 29)}
		s.Observe(attackerTenant, attacker, true, b, fmt.Sprintf("%064x", i))
	}
	g, tb, refs, reports := s.Stats()
	if g+tb > 2000 || refs+reports > 400 {
		t.Fatalf("caps not enforced: bands %d refs %d", g+tb, refs+reports)
	}
	if b, rf, rp := s.TenantStats(victimTenant); b != vBands || rf != vRefs || rp != vReports {
		t.Fatalf("victim lost entries: bands %d/%d refs %d/%d reports %d/%d", b, vBands, rf, vRefs, rp, vReports)
	}
	// The victim's report still works and still shows up for the tenant.
	_, other := dev(1, 2)
	if got := s.Observe(victimTenant, other, true, bandsA, "cc"+mail[2:]); got.Signal != SignalReported {
		t.Fatalf("victim's reported campaign evicted: %+v", got)
	}
	// Reported global bands outlived the flood of unreported global bands.
	s.mu.Lock()
	reported := 0
	for i, v := range bandsA {
		if b := s.global[s.GlobalBandKey(i, v)]; b != nil && len(b.reporters) > 0 {
			reported++
		}
	}
	s.mu.Unlock()
	if reported != 4 {
		t.Fatalf("reported global bands evicted: %d of 4 left", reported)
	}
}

func TestGlobalBandsPerTenantAndDay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s, _ := Open("", kfp, func() time.Time { return now }, Limits{MaxBands: 400, MaxRefs: 1000})
	ten, device := dev(1, 1)
	for i := 0; i < 30; i++ { // 120 band observations, the allowance is 40 new global bands a day
		b := [4]uint16{uint16(i), uint16(i + 100), uint16(i + 200), uint16(i + 300)}
		s.Observe(ten, device, true, b, fmt.Sprintf("%064x", i))
	}
	if g, _, _, _ := s.Stats(); g != s.GlobalNewPerDay() {
		t.Fatalf("global bands %d, want the daily allowance %d", g, s.GlobalNewPerDay())
	}
	// Another tenant has its own allowance; existing global bands are still counted.
	ten2, device2 := dev(2, 1)
	if r := s.Observe(ten2, device2, true, [4]uint16{0, 100, 200, 300}, mail); r.SeenDevices7d != 2 {
		t.Fatalf("existing global band not shared: %+v", r)
	}
	now = now.Add(24 * time.Hour)
	s.Observe(ten, device, true, [4]uint16{999, 998, 997, 996}, mail)
	if g, _, _, _ := s.Stats(); g != s.GlobalNewPerDay()+4 {
		t.Fatalf("allowance not reset on the next day: %d", g)
	}
}

// fillToCap fills a store white-box to its caps: MaxBands bands spread over tenants (each band with
// the given number of seen and reporter members) and MaxRefs mail references.
func fillToCap(s *Store, tenants, members int) {
	today := dayNum(s.now())
	set := func(n, salt int) []member {
		out := make([]member, n)
		for i := range out {
			binary.BigEndian.PutUint64(out[i].device[:], uint64(salt*SetCap+i))
			binary.BigEndian.PutUint64(out[i].tenant[:], uint64(i%7))
			out[i].day = today
		}
		return out
	}
	for i := 0; i < s.MaxBands; i++ {
		var k key32
		binary.BigEndian.PutUint64(k[:], uint64(i))
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i%tenants)
		s.tenantScope(id)[k] = &band{seen: set(members, i), reporters: set(members, i+1)}
	}
	for i := 0; i < s.MaxRefs; i++ {
		var k key32
		binary.BigEndian.PutUint64(k[:], uint64(i))
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", i%tenants)
		if s.refs[id] == nil {
			s.refs[id] = map[key32]mailRef{}
		}
		s.refs[id][k] = mailRef{day: today}
	}
	s.dirty = true
}

// peakHeap runs fn while sampling the heap in use and returns the peak.
func peakHeap(fn func()) uint64 {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	peak := ms.HeapInuse
	done := make(chan struct{})
	sampled := make(chan uint64)
	go func() {
		p := peak
		for {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			p = max(p, m.HeapInuse)
			select {
			case <-done:
				sampled <- p
				return
			case <-time.After(time.Millisecond):
			}
		}
	}()
	fn()
	close(done)
	return <-sampled
}

// TestSaveAndOpenMemoryAtTheCap is the regression test for GO-01. It fills a store with the pi
// profile's caps in the worst case (every band with 32 seen and 32 reporters) and measures the
// peak heap while saving and loading. The limit is the pi container's GOMEMLIMIT (200 MiB) minus
// the analyze body budget (96 MiB). Before the fix, Save alone peaked at about 4x the live store.
func TestSaveAndOpenMemoryAtTheCap(t *testing.T) {
	members := SetCap
	if testing.Short() {
		members = 2 // typical bands; the worst case runs without -short
	}
	const limit = 104 << 20
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "campaign.dat")
	lim := Limits{MaxBands: 40_000, MaxRefs: 40_000} // config.ProfileFor("pi")
	s, _ := Open(path, kfp, func() time.Time { return now }, lim)
	fillToCap(s, 3, members)
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	live := ms.HeapInuse

	before := ms.TotalAlloc
	savePeak := peakHeap(func() {
		if err := s.Save(); err != nil {
			t.Fatal(err)
		}
	})
	runtime.ReadMemStats(&ms)
	saveAlloc := ms.TotalAlloc - before
	info, _ := os.Stat(path)

	var loaded *Store
	s = nil
	openPeak := peakHeap(func() {
		var err error
		if loaded, err = Open(path, kfp, func() time.Time { return now }, lim); err != nil {
			t.Fatal(err)
		}
	})
	t.Logf("members/set %d: live %d MiB, file %d MiB, Save allocated %d MiB, peak Save %d MiB, peak Open %d MiB",
		members, live>>20, info.Size()>>20, saveAlloc>>20, savePeak>>20, openPeak>>20)
	if g, tb, r, _ := loaded.Stats(); g+tb != lim.MaxBands || r != lim.MaxRefs {
		t.Fatalf("round trip lost entries: bands %d refs %d", g+tb, r)
	}
	if savePeak > limit || openPeak > limit {
		t.Fatalf("peak heap above %d MiB", limit>>20)
	}
	// Save copies only the key lists (32 bytes per entry) plus small batches.
	if saveAlloc > uint64(lim.MaxBands+lim.MaxRefs)*64+8<<20 {
		t.Fatalf("Save allocated %d MiB: it builds a copy of the store", saveAlloc>>20)
	}
}

// TestOpenEnforcesCapsWhileLoading loads a file written under larger caps (vps) with smaller caps
// (pi): the store ends within the small caps.
func TestOpenEnforcesCapsWhileLoading(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "campaign.dat")
	big, _ := Open(path, kfp, func() time.Time { return now }, Limits{MaxBands: 5000, MaxRefs: 5000})
	fillToCap(big, 4, 1)
	if err := big.Save(); err != nil {
		t.Fatal(err)
	}
	small, _ := Open(path, kfp, func() time.Time { return now }, Limits{MaxBands: 1000, MaxRefs: 500})
	if g, tb, r, p := small.Stats(); g+tb > 1000 || r+p > 500 || g+tb == 0 {
		t.Fatalf("caps not applied while loading: bands %d refs %d", g+tb, r+p)
	}
}
