// Package registry stores tenants, devices and enrolment tokens (concept §3.4, §4.2, §4.6).
// The registry is small (households, small companies) and kept as one JSON file written atomically;
// this keeps the gateway free of third-party database drivers.
package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	"zetru.app/gateway/internal/keys"
)

// Policy is per-tenant configuration.
type Policy struct {
	EnabledBackends     []string `json:"enabled_backends"`
	DailyQuota          int      `json:"daily_quota"`
	MaxMailBytes        int      `json:"max_mail_bytes"`
	CrossTenantCounting bool     `json:"cross_tenant_counting"`
}

// DefaultPolicy for self-hosted tenants.
func DefaultPolicy() Policy {
	return Policy{EnabledBackends: []string{"rules"}, DailyQuota: 5000, MaxMailBytes: 20 << 20, CrossTenantCounting: false}
}

// Tenant is one customer boundary.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Policy    Policy    `json:"policy"`
	CreatedAt time.Time `json:"created_at"`
}

// Device is one paired app install.
type Device struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Label     string     `json:"label"`
	PublicKey string     `json:"public_key"` // base64 SPKI DER, ECDSA P-256
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// token is a single-use enrolment token; only its hash is stored.
type token struct {
	Hash      string    `json:"hash"`
	TenantID  string    `json:"tenant_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type state struct {
	Tenants []Tenant `json:"tenants"`
	Devices []Device `json:"devices"`
	Tokens  []token  `json:"tokens"`
}

// Errors.
var (
	ErrUnknownTenant = errors.New("unknown tenant")
	ErrBadToken      = errors.New("invalid or expired enrolment token")
	ErrUnknownDevice = errors.New("unknown device")
	ErrRevoked       = errors.New("device revoked")
)

// Registry is safe for concurrent use.
type Registry struct {
	mu    sync.Mutex
	path  string
	state state
	now   func() time.Time
}

// Open loads (or creates) the registry file.
func Open(path string, now func() time.Time) (*Registry, error) {
	if now == nil {
		now = time.Now
	}
	r := &Registry{path: path, now: now}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &r.state); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Registry) save() error {
	data, err := json.MarshalIndent(r.state, "", "  ")
	if err != nil {
		return err
	}
	return keys.WriteFileAtomic(r.path, data)
}

// NewID returns a random UUIDv4 string.
func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// EnsureTenant returns the tenant with the given name, creating it if needed.
func (r *Registry) EnsureTenant(name string) (Tenant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.state.Tenants {
		if t.Name == name {
			return t, nil
		}
	}
	t := Tenant{ID: NewID(), Name: name, Policy: DefaultPolicy(), CreatedAt: r.now().UTC()}
	r.state.Tenants = append(r.state.Tenants, t)
	return t, r.save()
}

// Tenant looks up a tenant.
func (r *Registry) Tenant(id string) (Tenant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.state.Tenants {
		if t.ID == id {
			return t, nil
		}
	}
	return Tenant{}, ErrUnknownTenant
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// CreateEnrolmentToken returns a fresh single-use 128-bit token valid for ttl.
func (r *Registry) CreateEnrolmentToken(tenantID string, ttl time.Duration) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	found := false
	for _, t := range r.state.Tenants {
		if t.ID == tenantID {
			found = true
		}
	}
	if !found {
		return "", ErrUnknownTenant
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	now := r.now()
	kept := r.state.Tokens[:0]
	for _, t := range r.state.Tokens {
		if t.ExpiresAt.After(now) {
			kept = append(kept, t)
		}
	}
	r.state.Tokens = append(kept, token{Hash: hashToken(value), TenantID: tenantID, ExpiresAt: now.Add(ttl).UTC()})
	return value, r.save()
}

// Enroll consumes a token and registers a device.
func (r *Registry) Enroll(tokenValue, tenantID, publicKey, label string) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	wanted := hashToken(tokenValue)
	index := -1
	for i, t := range r.state.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(wanted)) == 1 && t.ExpiresAt.After(now) && t.TenantID == tenantID {
			index = i
			break
		}
	}
	if index < 0 {
		return Device{}, ErrBadToken
	}
	r.state.Tokens = append(r.state.Tokens[:index], r.state.Tokens[index+1:]...)
	if len(label) > 64 {
		label = label[:64]
	}
	device := Device{ID: NewID(), TenantID: tenantID, Label: label, PublicKey: publicKey, CreatedAt: now.UTC()}
	r.state.Devices = append(r.state.Devices, device)
	return device, r.save()
}

// Device returns an active device.
func (r *Registry) Device(id string) (Device, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.state.Devices {
		if d.ID == id {
			if d.RevokedAt != nil {
				return d, ErrRevoked
			}
			return d, nil
		}
	}
	return Device{}, ErrUnknownDevice
}

// Devices lists devices of a tenant (or all if tenantID is empty).
func (r *Registry) Devices(tenantID string) []Device {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []Device
	for _, d := range r.state.Devices {
		if tenantID == "" || d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out
}

// Revoke marks a device revoked (idempotent).
func (r *Registry) Revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.state.Devices {
		if r.state.Devices[i].ID == id {
			if r.state.Devices[i].RevokedAt == nil {
				t := r.now().UTC()
				r.state.Devices[i].RevokedAt = &t
			}
			return r.save()
		}
	}
	return ErrUnknownDevice
}

// RotateKey replaces the public key of an active device.
func (r *Registry) RotateKey(id, publicKey string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.state.Devices {
		if r.state.Devices[i].ID == id {
			if r.state.Devices[i].RevokedAt != nil {
				return ErrRevoked
			}
			t := r.now().UTC()
			r.state.Devices[i].PublicKey = publicKey
			r.state.Devices[i].RotatedAt = &t
			return r.save()
		}
	}
	return ErrUnknownDevice
}

// DeleteTenant removes a tenant and all its devices and tokens.
func (r *Registry) DeleteTenant(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tenants := r.state.Tenants[:0]
	found := false
	for _, t := range r.state.Tenants {
		if t.ID == id {
			found = true
			continue
		}
		tenants = append(tenants, t)
	}
	if !found {
		return ErrUnknownTenant
	}
	r.state.Tenants = tenants
	devices := r.state.Devices[:0]
	for _, d := range r.state.Devices {
		if d.TenantID != id {
			devices = append(devices, d)
		}
	}
	r.state.Devices = devices
	tokens := r.state.Tokens[:0]
	for _, t := range r.state.Tokens {
		if t.TenantID != id {
			tokens = append(tokens, t)
		}
	}
	r.state.Tokens = tokens
	return r.save()
}
