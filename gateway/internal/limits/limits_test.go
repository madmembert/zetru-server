package limits

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRateLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	r := NewRateLimiter(func() time.Time { return now }, 3)
	for i := 0; i < 30; i++ {
		if ok, _ := r.Allow("dev|analyze", 30); !ok {
			t.Fatalf("request %d rejected within the burst", i)
		}
	}
	ok, wait := r.Allow("dev|analyze", 30)
	if ok || wait != 2*time.Second {
		t.Fatalf("31st request: ok=%v wait=%v (want 2s at 30/min)", ok, wait)
	}
	if ok, _ := r.Allow("other|analyze", 30); !ok {
		t.Fatal("buckets must be per key")
	}
	now = now.Add(2 * time.Second)
	if ok, _ := r.Allow("dev|analyze", 30); !ok {
		t.Fatal("bucket did not refill")
	}
	if ok, _ := r.Allow("dev|analyze", 30); ok {
		t.Fatal("refill too fast")
	}
	// Key table full: new keys are refused until idle buckets are pruned.
	for i := 0; i < 10; i++ {
		_, _ = r.Allow("other|analyze", 30)
	}
	_, _ = r.Allow("third", 5)
	if ok, _ := r.Allow("fourth", 5); ok {
		t.Fatal("key table cap not enforced")
	}
	now = now.Add(2 * time.Minute)
	if ok, _ := r.Allow("fourth", 5); !ok {
		t.Fatal("full buckets were not pruned at the cap")
	}
	r.Prune()
	if r.Len() != 1 {
		t.Fatalf("prune left %d buckets", r.Len())
	}
}

func TestQuota(t *testing.T) {
	now := time.Date(2027, 1, 15, 23, 59, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "quota.json")
	q, err := OpenQuota(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if ok, _ := q.Take("dev", 3); !ok {
			t.Fatal("quota rejected too early")
		}
	}
	ok, wait := q.Take("dev", 3)
	if ok || wait != time.Minute {
		t.Fatalf("quota exceeded: ok=%v wait=%v", ok, wait)
	}
	q.Refund("dev")
	if ok, _ := q.Take("dev", 3); !ok {
		t.Fatal("refund not applied")
	}
	if err := q.Save(); err != nil {
		t.Fatal(err)
	}
	q2, _ := OpenQuota(path, func() time.Time { return now })
	if q2.Count("dev") != 3 {
		t.Fatalf("quota not persisted: %d", q2.Count("dev"))
	}
	now = now.Add(2 * time.Minute) // next UTC day
	if ok, _ := q2.Take("dev", 3); !ok {
		t.Fatal("quota did not reset at midnight UTC")
	}
	q2.Retain(func(key string) bool { return key != "dev" })
	if q2.Count("dev") != 0 {
		t.Fatal("retain did not drop the key")
	}
	now = now.Add(72 * time.Hour)
	_ = q2.Save()
	if len(q2.counts) != 0 {
		t.Fatalf("old days kept: %v", q2.counts)
	}
}
