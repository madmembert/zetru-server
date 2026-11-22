// Package auth verifies signed device requests (concept §4.4) and signs responses (§4.5).
package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Header names used by the protocol.
const (
	HeaderDevice    = "Zetru-Device"
	HeaderTimestamp = "Zetru-Timestamp"
	HeaderNonce     = "Zetru-Nonce"
	HeaderContent   = "Zetru-Content-SHA256"
	HeaderSignature = "Zetru-Signature"
	HeaderMeta      = "Zetru-Meta"

	// ClockSkew is the accepted difference between device and server time.
	ClockSkew = 120 * time.Second
	// NonceRetention is how long nonces are remembered (must exceed 2 × ClockSkew).
	NonceRetention = 5 * time.Minute
)

// Errors map to the stable error codes of the API (§11.6).
var (
	ErrMissingHeaders = errors.New("missing_auth_headers")
	ErrClock          = errors.New("clock_skew")
	ErrReplay         = errors.New("replayed_nonce")
	ErrBodyHash       = errors.New("body_hash_mismatch")
	ErrSignature      = errors.New("bad_signature")
	ErrNonceFormat    = errors.New("bad_nonce")
)

// SignedRequest carries the fields needed to verify one request.
type SignedRequest struct {
	Method       string
	PathAndQuery string
	Timestamp    string
	Nonce        string
	ContentHash  string
	Meta         string
	Signature    string
}

// CanonicalString builds the string that the device signs.
func CanonicalString(r SignedRequest) string {
	return strings.Join([]string{"ZETRU1", r.Method, r.PathAndQuery, r.Timestamp, r.Nonce, r.ContentHash, r.Meta}, "\n")
}

// BodyHash returns the lower-case hex SHA-256 of body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// ParseDevicePublicKey parses a base64 SubjectPublicKeyInfo (DER) and requires ECDSA P-256.
func ParseDevicePublicKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PublicKey)
	if !ok || ecKey.Curve.Params().Name != "P-256" {
		return nil, errors.New("device key must be ECDSA P-256")
	}
	return ecKey, nil
}

// ValidNonce checks the nonce format: 16 random bytes, base64url without padding (22 chars).
func ValidNonce(nonce string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	return err == nil && len(raw) == 16
}

// Verifier checks timestamps, nonces, body hashes and signatures.
type Verifier struct {
	now    func() time.Time
	mu     sync.Mutex
	nonces map[string]map[string]time.Time // device -> nonce -> expiry
}

// NewVerifier returns a verifier using the given clock (nil = time.Now).
func NewVerifier(now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{now: now, nonces: map[string]map[string]time.Time{}}
}

// CheckFreshness validates the timestamp window and records the nonce (replay protection).
// It must run before the body is processed.
func (v *Verifier) CheckFreshness(deviceID string, r SignedRequest) error {
	if r.Timestamp == "" || r.Nonce == "" || r.ContentHash == "" || r.Signature == "" {
		return ErrMissingHeaders
	}
	if !ValidNonce(r.Nonce) {
		return ErrNonceFormat
	}
	seconds, err := strconv.ParseInt(r.Timestamp, 10, 64)
	if err != nil {
		return ErrClock
	}
	now := v.now()
	delta := now.Sub(time.Unix(seconds, 0))
	if delta > ClockSkew || delta < -ClockSkew {
		return ErrClock
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	perDevice := v.nonces[deviceID]
	if perDevice == nil {
		perDevice = map[string]time.Time{}
		v.nonces[deviceID] = perDevice
	}
	if expiry, seen := perDevice[r.Nonce]; seen && expiry.After(now) {
		return ErrReplay
	}
	perDevice[r.Nonce] = now.Add(NonceRetention)
	return nil
}

// Prune drops expired nonces; call periodically.
func (v *Verifier) Prune() {
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for device, nonces := range v.nonces {
		for nonce, expiry := range nonces {
			if !expiry.After(now) {
				delete(nonces, nonce)
			}
		}
		if len(nonces) == 0 {
			delete(v.nonces, device)
		}
	}
}

// VerifyBodyAndSignature checks the content hash against the body and the ECDSA signature.
func VerifyBodyAndSignature(key *ecdsa.PublicKey, r SignedRequest, body []byte) error {
	if !strings.EqualFold(BodyHash(body), r.ContentHash) {
		return ErrBodyHash
	}
	signature, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return ErrSignature
	}
	digest := sha256.Sum256([]byte(CanonicalString(r)))
	if !ecdsa.VerifyASN1(key, digest[:], signature) {
		return ErrSignature
	}
	return nil
}

// ResponseSigner signs responses with the server identity key (§4.5).
type ResponseSigner struct {
	Key ed25519.PrivateKey
}

// ResponseSigningString binds a response to the request nonce and status.
func ResponseSigningString(nonce string, status int, body []byte) string {
	return "ZETRU1-RESP\n" + nonce + "\n" + strconv.Itoa(status) + "\n" + BodyHash(body)
}

// Sign returns the base64 Ed25519 signature for a response.
func (s ResponseSigner) Sign(nonce string, status int, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.Key, []byte(ResponseSigningString(nonce, status, body))))
}
