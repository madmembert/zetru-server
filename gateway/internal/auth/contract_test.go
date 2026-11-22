package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestSwiftSignedRequest verifies a request signed by the iOS client's real signing code
// (fixture generated from ZetruKit RequestSigning). This is the cross-language contract for §4.4.
func TestSwiftSignedRequest(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "swift_signed_request.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]string
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	key, err := ParseDevicePublicKey(f["public_key"])
	if err != nil {
		t.Fatalf("app public key format rejected: %v", err)
	}
	body, err := base64.StdEncoding.DecodeString(f["body_b64"])
	if err != nil {
		t.Fatal(err)
	}
	if BodyHash(body) != f["content_sha256"] {
		t.Fatal("body hash differs between Swift and Go")
	}
	if !ValidNonce(f["nonce"]) {
		t.Fatal("Swift nonce format rejected")
	}
	canonical := CanonicalString(f["method"], f["path"], f["timestamp"], f["nonce"], f["content_sha256"])
	if err := VerifySignature(key, canonical, f["signature"]); err != nil {
		t.Fatalf("Swift signature rejected by the gateway: %v", err)
	}
	if err := VerifySignature(key, canonical+"x", f["signature"]); err == nil {
		t.Fatal("tampered canonical string accepted")
	}
}

// TestWriteResponseFixture writes a gateway-signed response for the Swift contract test.
// Run with ZETRU_WRITE_FIXTURES=1; otherwise it only checks that the committed fixture verifies.
func TestWriteResponseFixture(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "ios", "ZetruKitTests", "Fixtures", "gateway_signed_response.json")
	if os.Getenv("ZETRU_WRITE_FIXTURES") == "1" {
		pub, priv, _ := ed25519.GenerateKey(nil)
		body := []byte(`{"schema":1}`)
		signer := ResponseSigner{Key: priv}
		fixture := map[string]any{
			"sid":       base64.StdEncoding.EncodeToString(pub),
			"nonce":     "j0J6a5unelTgc8PLi6an0w",
			"status":    200,
			"body_b64":  base64.StdEncoding.EncodeToString(body),
			"signature": signer.Sign("j0J6a5unelTgc8PLi6an0w", 200, body),
		}
		data, _ := json.MarshalIndent(fixture, "", "  ")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("fixture not present")
	}
	var f struct {
		SID, Nonce, BodyB64, Signature string
		Status                         int
	}
	var m map[string]any
	_ = json.Unmarshal(data, &m)
	f.SID, f.Nonce, f.BodyB64, f.Signature = m["sid"].(string), m["nonce"].(string), m["body_b64"].(string), m["signature"].(string)
	f.Status = int(m["status"].(float64))
	pub, _ := base64.StdEncoding.DecodeString(f.SID)
	body, _ := base64.StdEncoding.DecodeString(f.BodyB64)
	if !VerifyResponse(ed25519.PublicKey(pub), f.Nonce, f.Status, body, f.Signature) {
		t.Fatal("committed response fixture does not verify")
	}
}
