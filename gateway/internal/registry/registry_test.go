package registry

import (
	"path/filepath"
	"testing"
	"time"
)

func TestEnrollmentLifecycle(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	path := filepath.Join(t.TempDir(), "registry.json")
	r, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := r.EnsureTenant("home")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := r.EnsureTenant("home")
	if again.ID != tenant.ID {
		t.Fatal("EnsureTenant must be idempotent")
	}
	tok, err := r.CreateEnrolmentToken(tenant.ID, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enroll(tok, "wrong-tenant", "pk", "iPhone"); err != ErrBadToken {
		t.Fatalf("token accepted for wrong tenant: %v", err)
	}
	dev, err := r.Enroll(tok, tenant.ID, "pk", "iPhone")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enroll(tok, tenant.ID, "pk2", "iPad"); err != ErrBadToken {
		t.Fatal("token must be single-use")
	}
	expired, _ := r.CreateEnrolmentToken(tenant.ID, time.Minute)
	now = now.Add(2 * time.Minute)
	if _, err := r.Enroll(expired, tenant.ID, "pk", "x"); err != ErrBadToken {
		t.Fatal("expired token accepted")
	}
	// Persistence.
	reopened, err := Open(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.Device(dev.ID); err != nil || got.PublicKey != "pk" {
		t.Fatalf("device not persisted: %v %+v", err, got)
	}
	if err := reopened.RotateKey(dev.ID, "pk-new"); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Revoke(dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Device(dev.ID); err != ErrRevoked {
		t.Fatalf("revoked device usable: %v", err)
	}
	if err := reopened.RotateKey(dev.ID, "pk-3"); err != ErrRevoked {
		t.Fatal("revoked device rotated")
	}
	if err := reopened.DeleteTenant(tenant.ID); err != nil {
		t.Fatal(err)
	}
	if len(reopened.Devices("")) != 0 {
		t.Fatal("tenant deletion must remove devices")
	}
}
