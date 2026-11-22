package campaign

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
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
	s, _ := Open("", kfp, func() time.Time { return now })
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
	s, _ := Open("", kfp, func() time.Time { return now })
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
	s, _ := Open("", kfp, nil)
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
	s, _ := Open("", kfp, nil)
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
	s, _ := Open("", kfp, nil)
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
	s, err := Open(path, kfp, func() time.Time { return now })
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
	loaded, err := Open(path, kfp, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	g1, t1, r1, p1 := s.Stats()
	g2, t2, r2, p2 := loaded.Stats()
	if g1 != g2 || t1 != t2 || r1 != r2 || p1 != p2 || g1 != 4 || t1 != 8 || r1 != 2 || p1 != 2 {
		t.Fatalf("round trip: %d/%d/%d/%d vs %d/%d/%d/%d", g1, t1, r1, p1, g2, t2, r2, p2)
	}
	// Another K_fp cannot read the file.
	other, _ := Open(path, bytes.Repeat([]byte{8}, 32), func() time.Time { return now })
	if g, _, _, _ := other.Stats(); g != 0 {
		t.Fatal("counters of another key were loaded")
	}
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
	s, _ := Open("", kfp, nil)
	s.MaxBands, s.MaxRefs = 100, 50
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
