// Package limits implements per-device rate limits (token buckets, in memory) and daily quotas
// (persisted, 2-day retention) of concept §11.4 and §13.2.
package limits

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"sync"
	"time"

	"zetru.app/gateway/internal/fsutil"
)

// RateLimiter is a set of token buckets keyed by an opaque string (device ID plus endpoint class,
// or a source address for enrolment). Keys live in memory only.
type RateLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	maxKeys int
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
	rate   int
}

// NewRateLimiter returns a limiter holding at most maxKeys buckets (0 = 100,000).
func NewRateLimiter(now func() time.Time, maxKeys int) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	if maxKeys <= 0 {
		maxKeys = 100_000
	}
	return &RateLimiter{now: now, maxKeys: maxKeys, buckets: map[string]*bucket{}}
}

// Allow takes one token from the bucket for key, which holds perMinute tokens and refills
// continuously at perMinute per minute. When no token is available it returns the wait until one
// is (at least one second). If the key table is full, new keys are refused (fail closed).
func (r *RateLimiter) Allow(key string, perMinute int) (bool, time.Duration) {
	if perMinute <= 0 {
		return false, time.Minute
	}
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[key]
	if b == nil {
		if len(r.buckets) >= r.maxKeys {
			r.pruneLocked(now)
			if len(r.buckets) >= r.maxKeys {
				return false, time.Minute
			}
		}
		b = &bucket{tokens: float64(perMinute), last: now, rate: perMinute}
		r.buckets[key] = b
	}
	perSecond := float64(perMinute) / 60
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens = math.Min(float64(perMinute), b.tokens+elapsed*perSecond)
	}
	b.last = now
	b.rate = perMinute
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration(math.Ceil((1-b.tokens)/perSecond)) * time.Second
	if wait < time.Second {
		wait = time.Second
	}
	return false, wait
}

// Prune drops buckets that have refilled completely (they carry no state).
func (r *RateLimiter) Prune() {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
}

func (r *RateLimiter) pruneLocked(now time.Time) {
	for key, b := range r.buckets {
		full := b.tokens + now.Sub(b.last).Seconds()*float64(b.rate)/60
		if full >= float64(b.rate) {
			delete(r.buckets, key)
		}
	}
}

// Len returns the number of buckets (for tests).
func (r *RateLimiter) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

// Quota counts uses per key and UTC day. Only today and yesterday are kept (§14.2: 2 days).
// Counts are flushed to disk by Save; a crash loses at most the counts since the last Save.
type Quota struct {
	mu     sync.Mutex
	path   string
	now    func() time.Time
	counts map[string]map[string]int // day -> key -> count
	dirty  bool
}

// OpenQuota loads the quota file at path (empty if missing). A corrupt file is moved aside and
// counting restarts, because quota counters are not security state.
func OpenQuota(path string, now func() time.Time) (*Quota, error) {
	if now == nil {
		now = time.Now
	}
	q := &Quota{path: path, now: now, counts: map[string]map[string]int{}}
	if path == "" {
		return q, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return q, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &q.counts); err != nil || q.counts == nil {
		_ = os.Rename(path, path+".corrupt")
		q.counts = map[string]map[string]int{}
	}
	q.pruneLocked(now())
	return q, nil
}

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// untilMidnight returns the time until the next UTC day starts (at least one second).
func untilMidnight(now time.Time) time.Duration {
	u := now.UTC()
	next := time.Date(u.Year(), u.Month(), u.Day()+1, 0, 0, 0, 0, time.UTC)
	d := (next.Sub(u) + time.Second - 1) / time.Second * time.Second // round up
	if d < time.Second {
		d = time.Second
	}
	return d
}

// Take counts one use of key if fewer than limit uses happened today; otherwise it returns the
// time until the quota resets.
func (q *Quota) Take(key string, limit int) (bool, time.Duration) {
	now := q.now()
	d := day(now)
	q.mu.Lock()
	defer q.mu.Unlock()
	m := q.counts[d]
	if m == nil {
		q.pruneLocked(now)
		m = map[string]int{}
		q.counts[d] = m
	}
	if m[key] >= limit {
		return false, untilMidnight(now)
	}
	m[key]++
	q.dirty = true
	return true, 0
}

// Refund gives back one use taken today (used when the analyzer could not take the mail).
func (q *Quota) Refund(key string) {
	d := day(q.now())
	q.mu.Lock()
	defer q.mu.Unlock()
	if m := q.counts[d]; m != nil && m[key] > 0 {
		m[key]--
		q.dirty = true
	}
}

// Count returns today's count for key.
func (q *Quota) Count(key string) int {
	d := day(q.now())
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.counts[d][key]
}

// Retain drops all keys for which keep returns false (deleted devices).
func (q *Quota) Retain(keep func(key string) bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, m := range q.counts {
		for key := range m {
			if !keep(key) {
				delete(m, key)
				q.dirty = true
			}
		}
	}
}

func (q *Quota) pruneLocked(now time.Time) {
	today, yesterday := day(now), day(now.Add(-24*time.Hour))
	for d := range q.counts {
		if d != today && d != yesterday {
			delete(q.counts, d)
			q.dirty = true
		}
	}
}

// Save writes the counters if they changed.
func (q *Quota) Save() error {
	q.mu.Lock()
	q.pruneLocked(q.now())
	if !q.dirty || q.path == "" {
		q.mu.Unlock()
		return nil
	}
	data, err := json.Marshal(q.counts)
	q.dirty = false
	q.mu.Unlock()
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(q.path, data, 0o600); err != nil {
		q.mu.Lock()
		q.dirty = true
		q.mu.Unlock()
		return err
	}
	return nil
}
