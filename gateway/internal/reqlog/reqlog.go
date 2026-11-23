// Package reqlog writes the per-request log of concept §11.5: time, endpoint, tenant ID, device
// ID, status code, duration bucket and body size bucket (plus the fixed error code). It never
// receives request content, addresses, domains, URLs, hashes, evidence or client IP addresses —
// the Entry type has no field that could carry them.
//
// Retention (§14.2): 14 days. In file mode the log is written to one file per UTC day in the
// gateway data volume and files older than 14 days are deleted, which enforces the retention
// independently of Docker's size-based log rotation.
//
// Volume (GO-03): requests that did not authenticate are not logged one line each but counted per
// minute, endpoint, status and code (Count), so unauthenticated traffic cannot grow the log at its
// own rate. A daily file is also capped (DefaultMaxDailyBytes); lines beyond the cap are dropped
// and counted in a final summary line, so the log can never fill the volume that holds the
// registry and the keys.
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

// DefaultMaxDailyBytes caps one daily file (15 files at most: 750 MB).
const DefaultMaxDailyBytes = 50 << 20

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
	Duration string `json:"dur,omitempty"`
	Size     string `json:"size,omitempty"`
	Count    int64  `json:"count,omitempty"` // aggregated lines: number of requests
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
	mu       sync.Mutex
	dir      string    // file mode when non-empty
	out      io.Writer // writer mode when non-nil
	now      func() time.Time
	maxBytes int64

	day         string
	file        *os.File
	size        int64 // bytes in the current daily file
	fileDropped int64 // lines dropped from the current daily file
	dropped     int64 // lines dropped since start
	pruned      string

	aggMinute time.Time
	agg       map[aggKey]int64
}

type aggKey struct {
	endpoint string
	status   int
	code     string
}

// NewFileLogger logs to dir/requests-YYYY-MM-DD.jsonl (mode 0600).
func NewFileLogger(dir string, now func() time.Time) (*Logger, error) {
	if now == nil {
		now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	l := &Logger{dir: dir, now: now, maxBytes: DefaultMaxDailyBytes}
	l.prune(now())
	return l, nil
}

// NewWriterLogger logs to w (e.g. stdout); retention is then the operator's log rotation.
func NewWriterLogger(w io.Writer) *Logger { return &Logger{out: w, now: time.Now} }

// Discard returns a logger that drops everything.
func Discard() *Logger { return &Logger{now: time.Now} }

// SetMaxDailyBytes changes the daily file cap (call before use).
func (l *Logger) SetMaxDailyBytes(n int64) { l.maxBytes = n }

// Dropped returns the number of lines dropped because a daily file reached its cap.
func (l *Logger) Dropped() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

func (l *Logger) active() bool { return l != nil && (l.dir != "" || l.out != nil) }

func encode(v line) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf) // appends the newline
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil
	}
	return buf.Bytes()
}

// Log writes one line for an authenticated request. Errors are ignored: logging must never fail
// a request.
func (l *Logger) Log(e Entry) {
	if !l.active() {
		return
	}
	data := encode(line{TS: e.Time.UTC().Format(time.RFC3339), Endpoint: e.Endpoint, Tenant: e.Tenant,
		Device: e.Device, Status: e.Status, Code: e.Code, Duration: DurationBucket(e.Duration), Size: SizeBucket(e.BodySize)})
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushAggLocked(e.Time, false)
	l.writeLocked(data, e.Time)
}

// Count records a request that did not authenticate. Such requests are written as one line per
// minute, endpoint, status and code with their number ("count"); tenant and device are never
// part of these lines.
func (l *Logger) Count(e Entry) {
	if !l.active() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushAggLocked(e.Time, false)
	if l.agg == nil {
		l.agg = map[aggKey]int64{}
	}
	if len(l.agg) == 0 {
		l.aggMinute = e.Time.UTC().Truncate(time.Minute)
	}
	l.agg[aggKey{e.Endpoint, e.Status, e.Code}]++
}

// Flush writes the counts of minutes that are over and applies the retention; the server calls it
// every minute so that both happen without traffic.
func (l *Logger) Flush() {
	if !l.active() {
		return
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushAggLocked(now, false)
	if l.dir != "" {
		l.prune(now)
	}
}

// flushAggLocked writes the aggregated lines once their minute is over (or always with force).
func (l *Logger) flushAggLocked(now time.Time, force bool) {
	if len(l.agg) == 0 || (!force && !now.UTC().Truncate(time.Minute).After(l.aggMinute)) {
		return
	}
	keys := make([]aggKey, 0, len(l.agg))
	for k := range l.agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].endpoint != keys[j].endpoint {
			return keys[i].endpoint < keys[j].endpoint
		}
		if keys[i].status != keys[j].status {
			return keys[i].status < keys[j].status
		}
		return keys[i].code < keys[j].code
	})
	ts := l.aggMinute.Format(time.RFC3339)
	for _, k := range keys {
		l.writeLocked(encode(line{TS: ts, Endpoint: k.endpoint, Status: k.status, Code: k.code, Count: l.agg[k]}), l.aggMinute)
	}
	l.agg = map[aggKey]int64{}
}

func (l *Logger) writeLocked(data []byte, t time.Time) {
	if data == nil {
		return
	}
	if l.out != nil {
		_, _ = l.out.Write(data)
		return
	}
	day := t.UTC().Format("2006-01-02")
	if day != l.day || l.file == nil {
		l.closeFileLocked()
		f, err := os.OpenFile(filepath.Join(l.dir, "requests-"+day+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
		l.file, l.day, l.size, l.fileDropped = f, day, 0, 0
		if info, err := f.Stat(); err == nil {
			l.size = info.Size()
		}
		l.prune(t)
	}
	if l.size+int64(len(data)) > l.maxBytes {
		l.fileDropped++
		l.dropped++
		return
	}
	n, _ := l.file.Write(data)
	l.size += int64(n)
}

// closeFileLocked closes the daily file; if lines were dropped it first appends one summary line
// (beyond the cap) with their number.
func (l *Logger) closeFileLocked() {
	if l.file == nil {
		return
	}
	if l.fileDropped > 0 {
		_, _ = l.file.Write(encode(line{TS: l.now().UTC().Format(time.RFC3339), Endpoint: "request-log",
			Code: "log_cap_reached", Count: l.fileDropped}))
		l.fileDropped = 0
	}
	_ = l.file.Close()
	l.file = nil
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

// Close writes pending counts and closes the current file.
func (l *Logger) Close() error {
	if !l.active() {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.flushAggLocked(l.now(), true)
	if l.file != nil {
		l.closeFileLocked()
	}
	return nil
}
