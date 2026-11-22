package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func pubKey(t *testing.T) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := k.PublicKey.Bytes()
	return base64.StdEncoding.EncodeToString(raw)
}

func TestEnrollmentLifecycle(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	dir := t.TempDir()
	r, err := Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := r.CreateTenant("home")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.CreateTenant("home"); !errors.Is(err, ErrTenantExists) {
		t.Fatalf("duplicate tenant name accepted: %v", err)
	}
	if _, _, err := r.CreateEnrolmentToken("00000000-0000-4000-8000-000000000000", TokenTTL); !errors.Is(err, ErrUnknownTenant) {
		t.Fatal("token for unknown tenant")
	}
	tok, expires, err := r.CreateEnrolmentToken(tenant.ID, TokenTTL)
	if err != nil || !expires.Equal(now.Add(TokenTTL)) || len(tok) != 22 {
		t.Fatalf("token: %q %v %v", tok, expires, err)
	}
	if _, err := r.Enroll(tok, "not-a-key", "iPhone"); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if _, err := r.Enroll("unknown-token", pubKey(t), "iPhone"); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("unknown token: %v", err)
	}
	pk := pubKey(t)
	dev, err := r.Enroll(tok, pk, "iPhone")
	if err != nil {
		t.Fatal(err)
	}
	if dev.TenantID != tenant.ID || dev.LastSeenDay != "2027-01-15" || !ValidUUID(dev.ID) {
		t.Fatalf("device %+v", dev)
	}
	if _, err := r.Enroll(tok, pubKey(t), "iPad"); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("token must be single-use: %v", err)
	}
	expired, _, _ := r.CreateEnrolmentToken(tenant.ID, time.Minute)
	now = now.Add(2 * time.Minute)
	if _, err := r.Enroll(expired, pubKey(t), "x"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token: %v", err)
	}
	// Used and expired tokens are forgotten after a day.
	now = now.Add(25 * time.Hour)
	if err := r.TouchLastSeen(dev.ID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enroll(tok, pubKey(t), "x"); !errors.Is(err, ErrTokenUnknown) {
		t.Fatalf("old token not pruned: %v", err)
	}

	// Persistence and reopening.
	reopened, err := Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Device(dev.ID); err != nil || got.PublicKey != pk || got.LastSeenDay != "2027-01-16" {
		t.Fatalf("device not persisted: %v %+v", err, got)
	}
	newPK := pubKey(t)
	if err := reopened.RotateKey(dev.ID, newPK); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RevokeInTenant("00000000-0000-4000-8000-000000000000", dev.ID); !errors.Is(err, ErrUnknownDevice) {
		t.Fatal("revocation across tenants allowed")
	}
	if err := reopened.Revoke(dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Device(dev.ID); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked device usable: %v", err)
	}
	if err := reopened.RotateKey(dev.ID, pubKey(t)); !errors.Is(err, ErrRevoked) {
		t.Fatal("revoked device rotated")
	}
	// The first handle sees the change made through the second one (CLI next to the server).
	if _, err := r.Device(dev.ID); !errors.Is(err, ErrRevoked) {
		t.Fatalf("change by another handle not picked up: %v", err)
	}
	if err := reopened.DeleteTenant(tenant.ID); err != nil {
		t.Fatal(err)
	}
	if len(r.Devices("")) != 0 || len(r.Tenants()) != 0 {
		t.Fatal("tenant deletion must remove devices")
	}
	if _, err := os.Stat(filepath.Join(dir, "registry.json.bak")); err != nil {
		t.Fatal("backup copy missing")
	}
}

func TestPolicyValidation(t *testing.T) {
	r, _ := Open(t.TempDir(), nil)
	tenant, _ := r.CreateTenant("t")
	bad := []Policy{
		{Backends: []string{"Rules"}},
		{Backends: []string{"rules", "rules"}},
		{MaxMailBytes: 100},
		{MaxMailBytes: MaxMailBytesLimit + 1},
		{DailyQuota: -1},
	}
	for _, p := range bad {
		if err := r.SetPolicy(tenant.ID, p); err == nil {
			t.Errorf("policy %+v accepted", p)
		}
	}
	good := Policy{Backends: []string{"rules", "encoder"}, DailyQuota: 100, MaxMailBytes: 1 << 20, CrossTenantCounting: true}
	if err := r.SetPolicy(tenant.ID, good); err != nil {
		t.Fatal(err)
	}
	got, _ := r.Tenant(tenant.ID)
	if got.Policy.DailyQuota != 100 || !got.Policy.CrossTenantCounting || len(got.Policy.Backends) != 2 {
		t.Fatalf("policy not stored: %+v", got.Policy)
	}
}

func TestCorruptFileIsFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "registry.json"), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); err == nil {
		t.Fatal("corrupt registry accepted")
	}
}

func TestConcurrentWritersDoNotLoseUpdates(t *testing.T) {
	dir := t.TempDir()
	a, _ := Open(dir, nil)
	b, _ := Open(dir, nil)
	tenant, _ := a.CreateTenant("t")
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reg := a
			if i%2 == 1 {
				reg = b
			}
			tok, _, err := reg.CreateEnrolmentToken(tenant.ID, TokenTTL)
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := reg.Enroll(tok, pubKey(t), "d"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	c, _ := Open(dir, nil)
	if n := len(c.Devices(tenant.ID)); n != 20 {
		t.Fatalf("lost updates: %d devices", n)
	}
}
