package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strconv"
	"testing"
	"time"
)

func signed(t *testing.T, key *ecdsa.PrivateKey, body []byte, ts time.Time, nonce string) SignedRequest {
	t.Helper()
	r := SignedRequest{Method: "POST", PathAndQuery: "/v1/analyze", Timestamp: strconv.FormatInt(ts.Unix(), 10),
		Nonce: nonce, ContentHash: BodyHash(body), Meta: "eyJ2IjoxfQ"}
	digest := sha256.Sum256([]byte(CanonicalString(r)))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = base64.StdEncoding.EncodeToString(sig)
	return r
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestSignatureVerification(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pub, err := ParseDevicePublicKey(base64.StdEncoding.EncodeToString(der))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("From: a@b.de\r\n\r\nhi")
	req := signed(t, key, body, time.Now(), nonce())
	if err := VerifyBodyAndSignature(pub, req, body); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := VerifyBodyAndSignature(pub, req, []byte("tampered")); err != ErrBodyHash {
		t.Fatalf("tampered body accepted: %v", err)
	}
	other := req
	other.PathAndQuery = "/v1/url/check"
	if err := VerifyBodyAndSignature(pub, other, body); err != ErrSignature {
		t.Fatalf("path swap accepted: %v", err)
	}
	other = req
	other.Meta = ""
	if err := VerifyBodyAndSignature(pub, other, body); err != ErrSignature {
		t.Fatalf("meta change accepted: %v", err)
	}
}

func TestRejectsNonP256Keys(t *testing.T) {
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(edKey.Public())
	if _, err := ParseDevicePublicKey(base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Fatal("ed25519 accepted as device key")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParseDevicePublicKey(base64.StdEncoding.EncodeToString(der)); err == nil {
		t.Fatal("P-384 accepted as device key")
	}
}

func TestFreshnessAndReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	v := NewVerifier(func() time.Time { return now })
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	n := nonce()
	req := signed(t, key, nil, now.Add(-60*time.Second), n)
	if err := v.CheckFreshness("dev", req); err != nil {
		t.Fatalf("fresh request rejected: %v", err)
	}
	if err := v.CheckFreshness("dev", req); err != ErrReplay {
		t.Fatalf("replay accepted: %v", err)
	}
	if err := v.CheckFreshness("other-device", req); err != nil {
		t.Fatalf("nonces must be per device: %v", err)
	}
	old := signed(t, key, nil, now.Add(-121*time.Second), nonce())
	if err := v.CheckFreshness("dev", old); err != ErrClock {
		t.Fatalf("stale timestamp accepted: %v", err)
	}
	future := signed(t, key, nil, now.Add(121*time.Second), nonce())
	if err := v.CheckFreshness("dev", future); err != ErrClock {
		t.Fatalf("future timestamp accepted: %v", err)
	}
	bad := signed(t, key, nil, now, "short")
	if err := v.CheckFreshness("dev", bad); err != ErrNonceFormat {
		t.Fatalf("bad nonce accepted: %v", err)
	}
	now = now.Add(6 * time.Minute)
	v.Prune()
	if len(v.nonces) != 0 {
		t.Fatalf("prune left %d devices", len(v.nonces))
	}
}

func TestResponseSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := ResponseSigner{Key: priv}
	body := []byte(`{"ok":true}`)
	sig, _ := base64.StdEncoding.DecodeString(signer.Sign("abc", 200, body))
	if !ed25519.Verify(pub, []byte("ZETRU1-RESP\nabc\n200\n"+BodyHash(body)), sig) {
		t.Fatal("response signature does not verify")
	}
	if ed25519.Verify(pub, []byte(ResponseSigningString("abc", 500, body)), sig) {
		t.Fatal("signature must bind the status")
	}
}
