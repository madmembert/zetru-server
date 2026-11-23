package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// contractFile is a file of the shared app/server contract (contract/signing at the repository root).
// The app repository copies it with scripts/sync-server-contract.py.
func contractFile(name string) string {
	return filepath.Join("..", "..", "..", "contract", "signing", name)
}

// TestSwiftSignedRequest verifies a request signed by the iOS client's real signing code
// (fixture generated from ZetruKit RequestSigning). This is the cross-language contract for §4.4
// (7-line canonical string) and for the request binding of §4.5.
func TestSwiftSignedRequest(t *testing.T) {
	raw, err := os.ReadFile(contractFile("swift_signed_request.json"))
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
	canonical := CanonicalString(f["method"], f["path"], f["device"], f["timestamp"], f["nonce"], f["content_sha256"])
	if err := VerifySignature(key, canonical, f["signature"]); err != nil {
		t.Fatalf("Swift signature rejected by the gateway: %v", err)
	}
	if err := VerifySignature(key, canonical+"x", f["signature"]); err == nil {
		t.Fatal("tampered canonical string accepted")
	}
	// The device line is signed: the same request under another device ID must fail.
	other := CanonicalString(f["method"], f["path"], "00000000-0000-4000-8000-000000000000", f["timestamp"], f["nonce"], f["content_sha256"])
	if err := VerifySignature(key, other, f["signature"]); err == nil {
		t.Fatal("signature not bound to Zetru-Device")
	}
	if got := RequestBinding(canonical); got != f["binding"] {
		t.Fatalf("request binding differs between Swift and Go:\n go    %s\n swift %s", got, f["binding"])
	}
}

// Request fields of the response fixture (the Swift test rebuilds the binding from them).
const (
	fixtureNonce     = "j0J6a5unelTgc8PLi6an0w"
	fixtureMethod    = "POST"
	fixturePath      = "/v1/analyze"
	fixtureDevice    = "6f1c2d3e-4a5b-4c6d-8e7f-8091a2b3c4d5"
	fixtureTimestamp = "1800000000"
)

// TestWriteResponseFixture writes a gateway-signed response for the Swift contract test.
// Run with ZETRU_WRITE_FIXTURES=1; otherwise it only checks that the committed fixture verifies.
// The signature covers the 5-line message of §4.5 whose binding is the SHA-256 of the 7-line
// canonical string built from the request fields stored next to it.
func TestWriteResponseFixture(t *testing.T) {
	path := contractFile("gateway_signed_response.json")
	if os.Getenv("ZETRU_WRITE_FIXTURES") == "1" {
		pub, priv, _ := ed25519.GenerateKey(nil)
		body := []byte(`{"schema":1}`)
		contentHash := BodyHash(nil)
		binding := RequestBinding(CanonicalString(fixtureMethod, fixturePath, fixtureDevice, fixtureTimestamp, fixtureNonce, contentHash))
		fixture := map[string]any{
			"sid":            base64.StdEncoding.EncodeToString(pub),
			"nonce":          fixtureNonce,
			"status":         200,
			"body_b64":       base64.StdEncoding.EncodeToString(body),
			"signature":      ResponseSigner{Key: priv}.Sign(fixtureNonce, 200, body, binding),
			"method":         fixtureMethod,
			"path":           fixturePath,
			"device":         fixtureDevice,
			"timestamp":      fixtureTimestamp,
			"content_sha256": contentHash,
		}
		data, _ := json.MarshalIndent(fixture, "", "  ")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skip("fixture not present")
	}
	var f struct {
		SID           string `json:"sid"`
		Nonce         string `json:"nonce"`
		Status        int    `json:"status"`
		BodyB64       string `json:"body_b64"`
		Signature     string `json:"signature"`
		Method        string `json:"method"`
		Path          string `json:"path"`
		Device        string `json:"device"`
		Timestamp     string `json:"timestamp"`
		ContentSHA256 string `json:"content_sha256"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Nonce != fixtureNonce || f.Method != fixtureMethod || f.Path != fixturePath || f.Device != fixtureDevice ||
		f.Timestamp != fixtureTimestamp || f.ContentSHA256 != BodyHash(nil) || f.Status != 200 {
		t.Fatalf("committed response fixture has unexpected request fields: %+v", f)
	}
	pub, _ := base64.StdEncoding.DecodeString(f.SID)
	body, _ := base64.StdEncoding.DecodeString(f.BodyB64)
	if string(body) != `{"schema":1}` {
		t.Fatalf("fixture body %q", body)
	}
	binding := RequestBinding(CanonicalString(f.Method, f.Path, f.Device, f.Timestamp, f.Nonce, f.ContentSHA256))
	if !VerifyResponse(ed25519.PublicKey(pub), f.Nonce, f.Status, body, binding, f.Signature) {
		t.Fatal("committed response fixture does not verify with the 5-line message")
	}
	// The binding is part of the signed message: another request (here: another device) must fail.
	otherBinding := RequestBinding(CanonicalString(f.Method, f.Path, "", f.Timestamp, f.Nonce, f.ContentSHA256))
	if VerifyResponse(ed25519.PublicKey(pub), f.Nonce, f.Status, body, otherBinding, f.Signature) {
		t.Fatal("response signature not bound to the request")
	}
}
