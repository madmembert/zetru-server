package reqlog

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileLoggerRetention(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2027, 1, 20, 12, 0, 0, 0, time.UTC)
	for _, day := range []string{"2027-01-01", "2027-01-05", "2027-01-06", "2027-01-07", "2027-01-19"} {
		_ = os.WriteFile(filepath.Join(dir, "requests-"+day+".jsonl"), []byte("{}\n"), 0o600)
	}
	_ = os.WriteFile(filepath.Join(dir, "other.txt"), nil, 0o600)
	l, err := NewFileLogger(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	l.Log(Entry{Time: now, Endpoint: "POST /v1/analyze", Tenant: "t", Device: "d", Status: 200,
		Duration: 1500 * time.Millisecond, BodySize: 3 << 20})
	_ = l.Close()
	for _, gone := range []string{"2027-01-01", "2027-01-05", "2027-01-06"} {
		if _, err := os.Stat(filepath.Join(dir, "requests-"+gone+".jsonl")); !os.IsNotExist(err) {
			t.Errorf("%s not pruned", gone)
		}
	}
	for _, kept := range []string{"requests-2027-01-07.jsonl", "requests-2027-01-19.jsonl", "other.txt"} {
		if _, err := os.Stat(filepath.Join(dir, kept)); err != nil {
			t.Errorf("%s removed", kept)
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "requests-2027-01-20.jsonl"))
	want := `{"ts":"2027-01-20T12:00:00Z","endpoint":"POST /v1/analyze","tenant":"t","device":"d","status":200,"dur":"<2s","size":"<5MB"}`
	if strings.TrimSpace(string(data)) != want {
		t.Fatalf("log line:\n%s\nwant\n%s", data, want)
	}
	info, _ := os.Stat(filepath.Join(dir, "requests-2027-01-20.jsonl"))
	if info.Mode().Perm() != 0o600 {
		t.Fatal("log file mode")
	}
}

func TestWriterLoggerAndBuckets(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf)
	l.Log(Entry{Time: time.Unix(0, 0), Endpoint: "GET /healthz", Status: 200})
	if !strings.Contains(buf.String(), `"size":"0"`) || strings.Contains(buf.String(), "tenant") {
		t.Fatalf("unexpected line %s", buf.String())
	}
	Discard().Log(Entry{})
	if DurationBucket(25*time.Second) != ">=20s" || SizeBucket(21<<20) != ">20MB" || SizeBucket(500) != "<1KB" {
		t.Fatal("buckets")
	}
}

// TestUnauthenticatedRequestsAreCounted is the regression test for GO-03: requests that did not
// authenticate produce one line per minute and key, not one line each.
func TestUnauthenticatedRequestsAreCounted(t *testing.T) {
	var buf bytes.Buffer
	l := NewWriterLogger(&buf)
	start := time.Date(2027, 1, 20, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 1000; i++ {
		l.Count(Entry{Time: start.Add(time.Duration(i) * 10 * time.Millisecond), Endpoint: "unknown", Status: 404, Code: "not_found"})
		l.Count(Entry{Time: start, Endpoint: "POST /v1/analyze", Status: 401, Code: "unknown_device"})
	}
	if buf.Len() != 0 {
		t.Fatal("counts written before their minute is over")
	}
	l.Log(Entry{Time: start.Add(time.Minute), Endpoint: "GET /v1/devices", Tenant: "t", Device: "d", Status: 200})
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{
		`{"ts":"2027-01-20T12:00:00Z","endpoint":"POST /v1/analyze","status":401,"code":"unknown_device","count":1000}`,
		`{"ts":"2027-01-20T12:00:00Z","endpoint":"unknown","status":404,"code":"not_found","count":1000}`,
		`{"ts":"2027-01-20T12:01:00Z","endpoint":"GET /v1/devices","tenant":"t","device":"d","status":200,"dur":"<100ms","size":"0"}`,
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("lines:\n%s\nwant\n%s", buf.String(), strings.Join(want, "\n"))
	}
	l.Count(Entry{Time: start.Add(2 * time.Minute), Endpoint: "GET /healthz", Status: 200})
	_ = l.Close()
	if !strings.Contains(buf.String(), `"endpoint":"GET /healthz","status":200,"count":1`) {
		t.Fatalf("Close did not flush the counts:\n%s", buf.String())
	}
}

// TestDailyFileCap is the regression test for GO-03: a daily file never grows beyond its cap
// (plus one summary line); further lines are dropped and counted.
func TestDailyFileCap(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2027, 1, 20, 12, 0, 0, 0, time.UTC)
	l, err := NewFileLogger(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	l.SetMaxDailyBytes(4096)
	for i := 0; i < 1000; i++ {
		l.Log(Entry{Time: now, Endpoint: "POST /v1/analyze", Tenant: "00000000-0000-4000-8000-000000000001",
			Device: "00000000-0000-4000-8000-000000000002", Status: 200, BodySize: 2000})
	}
	if l.Dropped() < 950 {
		t.Fatalf("dropped %d lines", l.Dropped())
	}
	_ = l.Close()
	path := filepath.Join(dir, "requests-2027-01-20.jsonl")
	data, _ := os.ReadFile(path)
	if len(data) > 4096+200 {
		t.Fatalf("file grew to %d bytes", len(data))
	}
	if !strings.Contains(string(data), `"code":"log_cap_reached","count":`) {
		t.Fatalf("summary line missing:\n%s", data)
	}
	// A restart on the same day keeps honouring the cap.
	l2, _ := NewFileLogger(dir, func() time.Time { return now })
	l2.SetMaxDailyBytes(4096)
	l2.Log(Entry{Time: now, Endpoint: "GET /healthz", Status: 200})
	if l2.Dropped() != 1 {
		t.Fatal("cap not applied to an existing file")
	}
	_ = l2.Close()
}
