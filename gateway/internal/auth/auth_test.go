package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func newNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func signCanonical(t *testing.T, key *ecdsa.PrivateKey, canonical string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(canonical))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func TestCanonicalStringFormat(t *testing.T) {
	got := CanonicalString("POST", "/v1/analyze?x=1", "1800000000", "AAAAAAAAAAAAAAAAAAAAAA", BodyHash(nil))
	want := "ZETRU1\nPOST\n/v1/analyze?x=1\n1800000000\nAAAAAAAAAAAAAAAAAAAAAA\n" +
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Fatalf("canonical string:\n%q\nwant\n%q", got, want)
	}
}

func TestSignatureVerification(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	pub, err := ParseDevicePublicKey(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("From: a@b.de\r\n\r\nhi")
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	n := newNonce()
	canonical := CanonicalString("POST", "/v1/analyze", ts, n, BodyHash(body))
	sig := signCanonical(t, key, canonical)
	if err := VerifySignature(pub, canonical, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifySignature(pub, CanonicalString("POST", "/v1/url/check", ts, n, BodyHash(body)), sig); err != ErrBadSignature {
		t.Fatalf("path swap accepted: %v", err)
	}
	if err := VerifySignature(pub, CanonicalString("POST", "/v1/analyze", ts, n, BodyHash([]byte("x"))), sig); err != ErrBadSignature {
		t.Fatalf("body swap accepted: %v", err)
	}
	if err := VerifySignature(pub, canonical, "not base64!"); err != ErrBadSignature {
		t.Fatalf("garbage signature accepted: %v", err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := VerifySignature(pub, canonical, signCanonical(t, other, canonical)); err != ErrBadSignature {
		t.Fatalf("foreign key accepted: %v", err)
	}
}

func TestParseDevicePublicKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	if _, err := ParseDevicePublicKey(base64.StdEncoding.EncodeToString(raw)); err != nil {
		t.Fatal(err)
	}
	// Compressed or truncated points, P-384 points and off-curve points are rejected.
	cases := map[string][]byte{
		"truncated":  raw[:64],
		"compressed": append([]byte{0x02}, raw[1:33]...),
		"offcurve":   append(append([]byte{0x04}, raw[1:33]...), make([]byte, 32)...),
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cases["p384"], _ = p384.PublicKey.Bytes()
	for name, value := range cases {
		if _, err := ParseDevicePublicKey(base64.StdEncoding.EncodeToString(value)); err == nil {
			t.Errorf("%s key accepted", name)
		}
	}
	if _, err := ParseDevicePublicKey("%%%"); err == nil {
		t.Error("non-base64 accepted")
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseDevicePublicKey(base64.StdEncoding.EncodeToString(edKey)); err == nil {
		t.Error("ed25519 key accepted")
	}
}

func TestTimestampWindow(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, ok := range []int64{0, -120, 120, 60} {
		if err := CheckTimestamp(strconv.FormatInt(now.Unix()+ok, 10), now); err != nil {
			t.Errorf("offset %d rejected", ok)
		}
	}
	for _, bad := range []string{strconv.FormatInt(now.Unix()-121, 10), strconv.FormatInt(now.Unix()+121, 10), "", "abc", "-5", "1.5", "99999999999999999999"} {
		if err := CheckTimestamp(bad, now); err != ErrStaleTimestamp {
			t.Errorf("timestamp %q accepted", bad)
		}
	}
}

func TestNonceCache(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := NewNonceCache(func() time.Time { return now }, 3)
	n := newNonce()
	if err := c.Reserve("dev", n); err != nil {
		t.Fatal(err)
	}
	if err := c.Reserve("dev", n); err != ErrReplayedNonce {
		t.Fatalf("replay accepted: %v", err)
	}
	if err := c.Reserve("other", n); err != nil {
		t.Fatalf("nonces must be per device: %v", err)
	}
	c.Release("dev", n)
	if err := c.Reserve("dev", n); err != nil {
		t.Fatalf("released nonce still blocked: %v", err)
	}
	_ = c.Reserve("dev", newNonce())
	_ = c.Reserve("dev", newNonce())
	if err := c.Reserve("dev", newNonce()); err != ErrNonceCacheFull {
		t.Fatalf("per-device cap not enforced: %v", err)
	}
	now = now.Add(NonceRetention + time.Second)
	if err := c.Reserve("dev", newNonce()); err != nil {
		t.Fatalf("expired nonces not evicted at cap: %v", err)
	}
	now = now.Add(NonceRetention + time.Second)
	c.Prune()
	if c.Devices() != 0 {
		t.Fatalf("prune left %d devices", c.Devices())
	}
	if !ValidNonce(n) || ValidNonce("short") || ValidNonce(n[:21]+"=") || ValidNonce("AAAAAAAAAAAAAAAAAAAAA+") {
		t.Fatal("nonce format check wrong")
	}
}

func TestResponseSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := ResponseSigner{Key: priv}
	body := []byte(`{"ok":true}`)
	sig := signer.Sign("abc", 200, body)
	raw, _ := base64.StdEncoding.DecodeString(sig)
	if !ed25519.Verify(pub, []byte("ZETRU1-RESP\nabc\n200\n"+BodyHash(body)), raw) {
		t.Fatal("response signature does not verify")
	}
	if !VerifyResponse(pub, "abc", 200, body, sig) {
		t.Fatal("VerifyResponse rejects a valid signature")
	}
	if VerifyResponse(pub, "abc", 500, body, sig) || VerifyResponse(pub, "abd", 200, body, sig) {
		t.Fatal("signature must bind status and nonce")
	}
}
