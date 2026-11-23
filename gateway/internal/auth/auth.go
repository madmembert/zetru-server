// Package auth implements the request-signing protocol of concept §4.4 (canonical string, ECDSA
// P-256 device signatures, timestamp window, per-device nonce cache) and the Ed25519 response
// signatures of §4.5, which are bound to the request through the request binding.
package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
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

	// ClockSkew is the accepted difference between device and server time (§11.4).
	ClockSkew = 120 * time.Second
	// NonceRetention is how long nonces are remembered (§4.4); it exceeds 2 × ClockSkew, so a
	// request whose nonce has been forgotten is always rejected by the timestamp check.
	NonceRetention = 5 * time.Minute
	// DefaultMaxNoncesPerDevice bounds the memory one device key can occupy in the replay cache.
	DefaultMaxNoncesPerDevice = 2048
)

// Errors. Their text equals the API error code of §11.6 they map to.
var (
	ErrBadRequest     = errors.New("bad_request")
	ErrStaleTimestamp = errors.New("stale_timestamp")
	ErrReplayedNonce  = errors.New("replayed_nonce")
	ErrBadSignature   = errors.New("bad_signature")
	// ErrNonceCacheFull means one device has more live nonces than allowed; mapped to rate_limited.
	ErrNonceCacheFull = errors.New("rate_limited")
)

// CanonicalString builds the string a device signs (§4.4): the seven lines `ZETRU1`, HTTP method,
// path including query, Zetru-Device, Zetru-Timestamp, Zetru-Nonce and Zetru-Content-SHA256,
// joined with "\n" (no trailing newline).
func CanonicalString(method, pathAndQuery, device, timestamp, nonce, contentHash string) string {
	return strings.Join([]string{"ZETRU1", method, pathAndQuery, device, timestamp, nonce, contentHash}, "\n")
}

// RequestBinding is the lowercase hex SHA-256 of a request's canonical string (§4.5). The gateway
// computes it from the request line and the raw received header values (a missing header counts
// as the empty string) and signs it into every response, so a response can only be used for the
// request it answers.
func RequestBinding(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// BodyHash returns the lowercase hex SHA-256 of body.
func BodyHash(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// ParseDevicePublicKey parses a base64 (standard, padded) X9.63 uncompressed P-256 point of
// 65 bytes (§11.3). The point must lie on the curve.
func ParseDevicePublicKey(b64 string) (*ecdsa.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return nil, errors.New("device key: not base64")
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, errors.New("device key: not an uncompressed P-256 point")
	}
	key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
	if err != nil {
		return nil, errors.New("device key: invalid P-256 point")
	}
	return key, nil
}

// ValidNonce checks the nonce format: 16 random bytes, base64url without padding (22 chars).
func ValidNonce(nonce string) bool {
	if len(nonce) != 22 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	return err == nil && len(raw) == 16
}

// ValidContentHash checks a hex SHA-256 (64 hex characters).
func ValidContentHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

// CheckTimestamp validates a Unix-seconds timestamp against now ± ClockSkew.
func CheckTimestamp(ts string, now time.Time) error {
	if ts == "" || len(ts) > 12 {
		return ErrStaleTimestamp
	}
	for _, c := range ts {
		if c < '0' || c > '9' {
			return ErrStaleTimestamp
		}
	}
	seconds, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrStaleTimestamp
	}
	delta := now.Sub(time.Unix(seconds, 0))
	if delta > ClockSkew || delta < -ClockSkew {
		return ErrStaleTimestamp
	}
	return nil
}

// VerifySignature checks a base64 DER ECDSA P-256/SHA-256 signature over the canonical string.
func VerifySignature(key *ecdsa.PublicKey, canonical, signatureB64 string) error {
	if signatureB64 == "" || len(signatureB64) > 200 {
		return ErrBadSignature
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return ErrBadSignature
	}
	digest := sha256.Sum256([]byte(canonical))
	if !ecdsa.VerifyASN1(key, digest[:], sig) {
		return ErrBadSignature
	}
	return nil
}

// NonceCache is the in-memory replay cache (§4.4): per device, 5-minute retention.
//
// The gateway reserves a nonce (Reserve, atomic) only after the request signature has been
// verified, so unsigned traffic never occupies the cache. Release removes the nonce again when the
// request then fails the body check. Only nonces of authenticated requests stay in the cache.
type NonceCache struct {
	mu        sync.Mutex
	now       func() time.Time
	maxPerDev int
	nonces    map[string]map[string]time.Time // device -> nonce -> expiry
}

// NewNonceCache returns a cache using the given clock (nil = time.Now).
func NewNonceCache(now func() time.Time, maxPerDevice int) *NonceCache {
	if now == nil {
		now = time.Now
	}
	if maxPerDevice <= 0 {
		maxPerDevice = DefaultMaxNoncesPerDevice
	}
	return &NonceCache{now: now, maxPerDev: maxPerDevice, nonces: map[string]map[string]time.Time{}}
}

// Reserve records nonce for device. It fails with ErrReplayedNonce if the nonce is already known
// and with ErrNonceCacheFull if the device has too many live nonces.
func (c *NonceCache) Reserve(device, nonce string) error {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	perDevice := c.nonces[device]
	if perDevice == nil {
		perDevice = map[string]time.Time{}
		c.nonces[device] = perDevice
	}
	if expiry, seen := perDevice[nonce]; seen && expiry.After(now) {
		return ErrReplayedNonce
	}
	if len(perDevice) >= c.maxPerDev {
		for n, expiry := range perDevice {
			if !expiry.After(now) {
				delete(perDevice, n)
			}
		}
		if len(perDevice) >= c.maxPerDev {
			return ErrNonceCacheFull
		}
	}
	perDevice[nonce] = now.Add(NonceRetention)
	return nil
}

// Seen reports whether nonce is a live nonce of device. It records nothing; the gateway uses it
// to answer a replay before it spends a signature verification, and reserves with Reserve only
// after the signature is valid.
func (c *NonceCache) Seen(device, nonce string) bool {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	expiry, seen := c.nonces[device][nonce]
	return seen && expiry.After(now)
}

// Release forgets a nonce reserved by a request that then failed authentication.
func (c *NonceCache) Release(device, nonce string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if perDevice := c.nonces[device]; perDevice != nil {
		delete(perDevice, nonce)
		if len(perDevice) == 0 {
			delete(c.nonces, device)
		}
	}
}

// Prune drops expired nonces; call periodically.
func (c *NonceCache) Prune() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for device, nonces := range c.nonces {
		for nonce, expiry := range nonces {
			if !expiry.After(now) {
				delete(nonces, nonce)
			}
		}
		if len(nonces) == 0 {
			delete(c.nonces, device)
		}
	}
}

// Len returns the number of live nonces of a device (for tests).
func (c *NonceCache) Len(device string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.nonces[device])
}

// Devices returns the number of devices with cached nonces (for tests).
func (c *NonceCache) Devices() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.nonces)
}

// ResponseSigningString is the message a response signature covers (§4.5): the lines
// `ZETRU1-RESP`, request nonce, HTTP status, SHA-256 hex of the response body and the request
// binding (RequestBinding), joined with "\n".
func ResponseSigningString(nonce string, status int, body []byte, binding string) string {
	return "ZETRU1-RESP\n" + nonce + "\n" + strconv.Itoa(status) + "\n" + BodyHash(body) + "\n" + binding
}

// ResponseSigner signs responses with the server identity key.
type ResponseSigner struct {
	Key ed25519.PrivateKey
}

// Sign returns the base64 Ed25519 signature for a response.
func (s ResponseSigner) Sign(nonce string, status int, body []byte, binding string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.Key, []byte(ResponseSigningString(nonce, status, body, binding))))
}

// VerifyResponse checks a response signature (used by the healthcheck and tests).
func VerifyResponse(pub ed25519.PublicKey, nonce string, status int, body []byte, binding, signatureB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, []byte(ResponseSigningString(nonce, status, body, binding)), sig)
}
