// Package reqlog writes the per-request log of concept §11.5: time, endpoint, tenant ID, device
// ID, status code, duration bucket and body size bucket (plus the fixed error code). It never
// receives request content, addresses, domains, URLs, hashes, evidence or client IP addresses —
// the Entry type has no field that could carry them.
//
// Retention (§14.2): 14 days. In file mode the log is written to one file per UTC day in the
// gateway data volume and files older than 14 days are deleted, which enforces the retention
// independently of Docker's size-based log rotation.
package reqlog

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Retention of request logs.
const Retention = 14 * 24 * time.Hour

// Entry is one logged request. Endpoint must be a route template (e.g. "DELETE /v1/devices/{id}"),
// never a raw path. Tenant and Device must be IDs from the registry, never request header values.
type Entry struct {
	Time     time.Time
	Endpoint string
	Tenant   string
	Device   string
	Status   int
	Code     string
	Duration time.Duration
	BodySize int64
}

type line struct {
	TS       string `json:"ts"`
	Endpoint string `json:"endpoint"`
	Tenant   string `json:"tenant,omitempty"`
	Device   string `json:"device,omitempty"`
	Status   int    `json:"status"`
	Code     string `json:"code,omitempty"`
	Duration string `json:"dur"`
	Size     string `json:"size"`
}

// DurationBucket coarsens a duration.
func DurationBucket(d time.Duration) string {
	switch {
	case d < 100*time.Millisecond:
		return "<100ms"
	case d < 500*time.Millisecond:
		return "<500ms"
	case d < 2*time.Second:
		return "<2s"
	case d < 6*time.Second:
		return "<6s"
	case d < 20*time.Second:
		return "<20s"
	default:
		return ">=20s"
	}
}

// SizeBucket coarsens a body size.
func SizeBucket(n int64) string {
	switch {
	case n <= 0:
		return "0"
	case n < 1<<10:
		return "<1KB"
	case n < 64<<10:
		return "<64KB"
	case n < 1<<20:
		return "<1MB"
	case n < 5<<20:
		return "<5MB"
	case n <= 20<<20:
		return "<=20MB"
	default:
		return ">20MB"
	}
}

// Logger writes entries to daily files, to a writer, or nowhere.
type Logger struct {
	mu     sync.Mutex
	dir    string    // file mode when non-empty
	out    io.Writer // writer mode when non-nil
	now    func() time.Time
	day    string
	file   *os.File
	pruned string
}

// NewFileLogger logs to dir/requests-YYYY-MM-DD.jsonl (mode 0600).
func NewFileLogger(dir string, now func() time.Time) (*Logger, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Logger{dir: dir, now: now}
	l.prune(now())
	return l, nil
}

// NewWriterLogger logs to w (e.g. stdout); retention is then the operator's log rotation.
func NewWriterLogger(w io.Writer) *Logger { return &Logger{out: w, now: time.Now} }

// Discard returns a logger that drops everything.
func Discard() *Logger { return &Logger{now: time.Now} }

// Log writes one entry. Errors are ignored: logging must never fail a request.
func (l *Logger) Log(e Entry) {
	if l == nil || (l.dir == "" && l.out == nil) {
		return
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // appends the newline
	enc.SetEscapeHTML(false)
	if err := enc.Encode(line{TS: e.Time.UTC().Format(time.RFC3339), Endpoint: e.Endpoint, Tenant: e.Tenant,
		Device: e.Device, Status: e.Status, Code: e.Code, Duration: DurationBucket(e.Duration), Size: SizeBucket(e.BodySize)}); err != nil {
		return
	}
	data := buf.Bytes()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.out != nil {
		_, _ = l.out.Write(data)
		return
	}
	day := e.Time.UTC().Format("2006-01-02")
	if day != l.day || l.file == nil {
		if l.file != nil {
			_ = l.file.Close()
			l.file = nil
		}
		f, err := os.OpenFile(filepath.Join(l.dir, "requests-"+day+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		l.file, l.day = f, day
		l.prune(e.Time)
	}
	_, _ = l.file.Write(data)
}

// prune deletes daily files older than the retention period (callers hold mu or are the constructor).
func (l *Logger) prune(now time.Time) {
	today := now.UTC().Format("2006-01-02")
	if l.pruned == today {
		return
	}
	l.pruned = today
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return
	}
	// A daily file is deleted once its day is no longer completely inside the retention period,
	// so no entry is kept longer than 14 days.
	cutoff := now.UTC().Add(-Retention).Format("2006-01-02")
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		if !strings.HasPrefix(name, "requests-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		day := strings.TrimSuffix(strings.TrimPrefix(name, "requests-"), ".jsonl")
		if day <= cutoff {
			_ = os.Remove(filepath.Join(l.dir, name))
		}
	}
}

// Close closes the current file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
