package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"zetru.app/gateway/internal/config"
	"zetru.app/gateway/internal/keys"
	"zetru.app/gateway/internal/pairing"
	"zetru.app/gateway/internal/registry"
)

var linkPattern = regexp.MustCompile(`zetru://pair\?v=1&d=[A-Za-z0-9_-]+`)

func run(t *testing.T, fn func([]string) error, args ...string) (string, error) {
	t.Helper()
	var buf bytes.Buffer
	stdout = &buf
	defer func() { stdout = os.Stdout }()
	err := fn(args)
	return buf.String(), err
}

func TestOperatorCommands(t *testing.T) {
	dir := t.TempDir()
	out, err := run(t, cmdInit, "--data", dir, "--name", "Home server", "--url", "https://192.168.1.20:8443",
		"--url", "https://zetru.example.net:8443", "--qr", "plain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "▀") || !strings.Contains(out, "Server identity fingerprint: ") {
		t.Fatalf("init output lacks QR code or fingerprint:\n%s", out)
	}
	link := linkPattern.FindString(out)
	p, err := pairing.Parse(link)
	if err != nil {
		t.Fatalf("pairing link %q: %v", link, err)
	}
	mat, _ := keys.Load(dir)
	reg, _ := registry.Open(dir, nil)
	tenant, err := reg.TenantByName("default")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "Home server" || p.Trust != "pin_only" || len(p.URLs) != 2 || p.SID != mat.IdentityPublic() ||
		p.Tenant != tenant.ID || strings.Join(p.Pins, ",") != strings.Join(mat.PinSet.Pins, ",") || len(p.Token) != 22 {
		t.Fatalf("payload %+v", p)
	}
	if mat.Primary.Leaf.IPAddresses[0].String() != "192.168.1.20" || mat.Primary.Leaf.DNSNames[0] != "zetru.example.net" {
		t.Fatal("certificate SANs do not match the URLs")
	}
	for _, name := range []string{"identity.key", "fingerprint.key", "tls-state.json", "registry.json", "server.json"} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s missing or not 0600", name)
		}
	}
	if _, err := run(t, cmdInit, "--data", dir, "--name", "x", "--url", "https://a.b"); err == nil {
		t.Fatal("second init succeeded")
	}
	if _, err := run(t, cmdInit, "--data", t.TempDir(), "--name", "x", "--url", "http://insecure"); err == nil {
		t.Fatal("http URL accepted")
	}

	// The token from the pairing code enrols a device; devices lists it; revoke revokes it.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	dev, err := reg.Enroll(p.Token, base64.StdEncoding.EncodeToString(raw), "Max\x07 iPhone")
	if err != nil {
		t.Fatal(err)
	}
	out, _ = run(t, cmdDevices, "--data", dir)
	if !strings.Contains(out, dev.ID) || !strings.Contains(out, "active") || strings.Contains(out, "\x07") {
		t.Fatalf("devices output:\n%q", out)
	}
	if _, err := run(t, cmdRevoke, dev.ID, "--data", dir); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Device(dev.ID); err != registry.ErrRevoked {
		t.Fatal("revoke had no effect")
	}

	// pair needs an existing tenant unless --create is given.
	if _, err := run(t, cmdPair, "--data", dir, "--tenant", "office", "--qr", "none"); err == nil {
		t.Fatal("pair created a tenant without --create")
	}
	out, err = run(t, cmdPair, "--data", dir, "--tenant", "office", "--create", "--qr", "none")
	if err != nil || strings.Contains(out, "▀") {
		t.Fatalf("pair --create: %v", err)
	}
	if p2, err := pairing.Parse(linkPattern.FindString(out)); err != nil || p2.Token == p.Token {
		t.Fatal("pair must issue a fresh token")
	}

	// Rotation: new pairing codes carry three pins during the transition.
	if _, err := run(t, cmdRotateTLS, "--data", dir); err != nil {
		t.Fatal(err)
	}
	out, _ = run(t, cmdPair, "--data", dir, "--tenant", "office", "--qr", "none")
	if p3, err := pairing.Parse(linkPattern.FindString(out)); err != nil || len(p3.Pins) != 3 {
		t.Fatalf("pins during rotation: %v", err)
	}
	if _, err := run(t, cmdRotateTLS, "--data", dir, "--complete"); err != nil {
		t.Fatal(err)
	}
	if m, _ := keys.Load(dir); m.PinSet.Seq != 3 || len(m.PinSet.Pins) != 2 {
		t.Fatal("rotation not completed")
	}

	// Tenant policy and deletion.
	if _, err := run(t, cmdTenant, "policy", "office", "--data", dir, "--daily-quota", "100", "--cross-tenant", "on", "--backends", "rules,encoder"); err != nil {
		t.Fatal(err)
	}
	office, _ := reg.TenantByName("office")
	if office.Policy.DailyQuota != 100 || !office.Policy.CrossTenantCounting || len(office.Policy.Backends) != 2 {
		t.Fatalf("policy %+v", office.Policy)
	}
	if _, err := run(t, cmdTenant, "policy", "office", "--data", dir, "--max-mail-bytes", "10"); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if _, err := run(t, cmdTenant, "delete", "office", "--data", dir); err == nil {
		t.Fatal("delete without --yes")
	}
	if _, err := run(t, cmdTenant, "delete", "office", "--data", dir, "--yes"); err != nil {
		t.Fatal(err)
	}
	out, _ = run(t, cmdTenant, "list", "--data", dir)
	if strings.Contains(out, "office") || !strings.Contains(out, "default") {
		t.Fatalf("tenant list:\n%s", out)
	}

	if _, err := run(t, cmdSetURLs, "--data", dir, "--url", "https://10.0.0.5:8443"); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := config.Load(dir); len(cfg.URLs) != 1 || cfg.URLs[0] != "https://10.0.0.5:8443" {
		t.Fatal("set-urls")
	}
}
