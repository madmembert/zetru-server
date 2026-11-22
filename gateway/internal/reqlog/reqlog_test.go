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
