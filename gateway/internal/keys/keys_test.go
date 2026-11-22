package keys

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestInitAndLoad(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir, []string{"zetru.local", "192.168.1.20"}); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir, nil); err == nil {
		t.Fatal("Init must refuse to overwrite keys")
	}
	m, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	pins := m.Pins()
	if len(pins) != 2 || pins[0] == pins[1] {
		t.Fatalf("expected two distinct pins, got %v", pins)
	}
	if len(m.Fingerprint) != 32 || len(m.IdentityPublic()) == 0 {
		t.Fatal("identity or fingerprint key missing")
	}
	info, _ := os.Stat(filepath.Join(dir, "identity.key"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity key mode %v", info.Mode().Perm())
	}
	if len(m.TLSLeaf.IPAddresses) != 1 || m.TLSLeaf.DNSNames[0] != "zetru.local" {
		t.Fatal("SANs missing")
	}
	old := pins[0]
	if err := RotateTLS(dir, nil); err != nil {
		t.Fatal(err)
	}
	m2, _ := Load(dir)
	if m2.Pins()[0] == old {
		t.Fatal("rotation did not change the primary pin")
	}
	if got := ShortFingerprint(m.Identity.Public().(ed25519.PublicKey)); len(got) != 19 {
		t.Fatalf("short fingerprint %q", got)
	}
}
