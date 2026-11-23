package keys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitLoadAndRotation(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	if err := Init(dir, []string{"zetru.local", "192.168.1.20"}, now); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, nil, now); err == nil {
		t.Fatal("Init must refuse to overwrite keys")
	}
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub := m.Identity.Public().(ed25519.PublicKey)
	if m.PinSet.Seq != 1 || len(m.PinSet.Pins) != 2 || m.PinSet.Pins[0] != m.PrimaryPin || m.PinSet.Pins[1] != m.BackupPin {
		t.Fatalf("initial pin set wrong: %+v", m.PinSet)
	}
	if m.PrimaryPin == m.BackupPin {
		t.Fatal("primary and backup must differ")
	}
	if !VerifyPinSet(pub, m.PinSet) {
		t.Fatal("pin set signature invalid")
	}
	tampered := m.PinSet
	tampered.Pins = []string{m.PinSet.Pins[1], m.PinSet.Pins[0]}
	if VerifyPinSet(pub, tampered) {
		t.Fatal("tampered pin set verified")
	}
	if len(m.Fingerprint) != 32 || len(m.IdentityPublic()) != 44 {
		t.Fatal("identity or fingerprint key missing")
	}
	for _, name := range []string{"identity.key", "fingerprint.key", "tls-state.json", "backup/tls.pem"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v err %v", name, info.Mode().Perm(), err)
		}
	}
	leaf := m.Primary.Leaf
	if len(leaf.IPAddresses) != 1 || leaf.DNSNames[0] != "zetru.local" {
		t.Fatal("SANs missing")
	}
	if got := ShortFingerprint(pub); len(got) != 19 {
		t.Fatalf("short fingerprint %q", got)
	}

	// Planned rotation: old key keeps being served, pin set grows to [old, next, backup].
	oldPin := m.PrimaryPin
	if err := StartRotation(dir, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := StartRotation(dir, nil, now); err == nil {
		t.Fatal("second concurrent rotation accepted")
	}
	m2, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m2.PrimaryPin != oldPin || m2.NextPin == "" || m2.PinSet.Seq != 2 ||
		len(m2.PinSet.Pins) != 3 || m2.PinSet.Pins[0] != oldPin || m2.PinSet.Pins[1] != m2.NextPin || m2.PinSet.Pins[2] != m.BackupPin {
		t.Fatalf("rotation pin set wrong: %+v", m2.PinSet)
	}
	if promoted, err := PromoteIfDue(dir, now.Add(TransitionPeriod-time.Second)); err != nil || promoted {
		t.Fatalf("promoted too early: %v %v", promoted, err)
	}
	if promoted, err := PromoteIfDue(dir, now.Add(TransitionPeriod)); err != nil || !promoted {
		t.Fatalf("not promoted when due: %v %v", promoted, err)
	}
	m3, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m3.PrimaryPin != m2.NextPin || m3.PinSet.Seq != 3 || len(m3.PinSet.Pins) != 2 || m3.Rotation != nil {
		t.Fatalf("promotion wrong: %+v", m3.PinSet)
	}
	if err := CompleteRotation(dir, now); err != ErrNoRotation {
		t.Fatalf("complete without rotation: %v", err)
	}

	// Key loss: the backup becomes primary, a new backup is generated, the lost key is unpinned.
	if err := ActivateBackup(dir, nil, now); err != nil {
		t.Fatal(err)
	}
	m4, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m4.PrimaryPin != m.BackupPin || m4.BackupPin == m.BackupPin || m4.PinSet.Seq != 4 ||
		len(m4.PinSet.Pins) != 2 || m4.PinSet.Pins[1] != m4.BackupPin {
		t.Fatalf("backup activation wrong: %+v", m4.PinSet)
	}
	if _, err := os.Stat(filepath.Join(dir, "backup", "tls.pem.new")); !os.IsNotExist(err) {
		t.Fatal("temporary backup file left behind")
	}
	// The new backup file on disk is the pinned backup key.
	data, _ := os.ReadFile(filepath.Join(dir, "backup", "tls.pem"))
	if _, pin, err := parsePair(string(data)); err != nil || pin != m4.BackupPin {
		t.Fatal("backup file does not match the pinned backup")
	}
	// A backup moved offline cannot be activated.
	_ = os.Remove(filepath.Join(dir, "backup", "tls.pem"))
	if err := ActivateBackup(dir, nil, now); err == nil {
		t.Fatal("activation without backup key succeeded")
	}
	if _, err := Load(dir); err != nil {
		t.Fatalf("server must still load with the backup offline: %v", err)
	}
}

func TestRepairInterruptedActivation(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	if err := Init(dir, nil, now); err != nil {
		t.Fatal(err)
	}
	// A stale .new file from a crash before the state was written is removed.
	stale, _, _ := newTLSPair(nil, now)
	_ = os.WriteFile(filepath.Join(dir, "backup", "tls.pem.new"), []byte(stale), 0o600)
	if err := StartRotation(dir, nil, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "backup", "tls.pem.new")); !os.IsNotExist(err) {
		t.Fatal("stale backup candidate not removed")
	}
}

func TestManagerPicksUpChanges(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(1_800_000_000, 0)
	if err := Init(dir, nil, now); err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := mgr.Material().PinSet.Seq
	if err := StartRotation(dir, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := mgr.Tick(now); err != nil {
		t.Fatal(err)
	}
	if mgr.Material().PinSet.Seq != first+1 {
		t.Fatal("manager did not reload the rotated pin set")
	}
	if err := mgr.Tick(now.Add(TransitionPeriod + time.Hour)); err != nil {
		t.Fatal(err)
	}
	m := mgr.Material()
	if m.Rotation != nil || m.PinSet.Seq != first+2 {
		t.Fatal("manager did not promote a due rotation")
	}
	cert, _ := mgr.GetCertificate(nil)
	if SPKIPin(cert.Leaf) != m.PrimaryPin {
		t.Fatal("served certificate is not the primary key")
	}
}
