// Package registry stores tenants, devices and enrolment tokens (concept §3.4, §4.2, §4.6, §13.2).
//
// Deviation from the concept (documented in DECISIONS.md): the registry is one JSON file instead of
// a SQLite database, so the gateway stays free of third-party drivers. The store is made robust by:
//   - atomic writes (temp file, fsync, rename, directory fsync) and a copy of the previous version
//     in registry.json.bak;
//   - an exclusive flock around every read-modify-write cycle, so the CLI (pair, revoke, …) and the
//     running server can change the file concurrently without losing updates;
//   - change detection on every lookup (inode/size/mtime), so a revocation made with the CLI takes
//     effect on the next request;
//   - strict validation on load: a corrupt file stops the gateway instead of silently unpairing
//     every device.
package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"zetru.app/gateway/internal/auth"
	"zetru.app/gateway/internal/fsutil"
)

const (
	fileName = "registry.json"
	bakName  = "registry.json.bak"
	lockName = ".registry.lock"

	// TokenTTL is the validity of an enrolment token (§4.2).
	TokenTTL = 10 * time.Minute
	// tokenMemory is how long used or expired tokens are kept so that the API can answer with
	// token_used / token_expired instead of a generic error.
	tokenMemory = 24 * time.Hour
	// MaxMailBytesLimit is the largest max_mail_bytes a tenant policy may set (§5.1, §11.4).
	MaxMailBytesLimit = 20 << 20
)

// Policy is per-tenant configuration (§3.4). Zero values mean "use the profile default".
type Policy struct {
	Backends            []string `json:"backends"`
	DailyQuota          int      `json:"daily_quota"`
	RatePerMinute       int      `json:"rate_per_minute"`
	MaxMailBytes        int      `json:"max_mail_bytes"`
	CrossTenantCounting bool     `json:"cross_tenant_counting"`
}

// DefaultPolicy for new tenants: rules backend only, profile limits, no cross-tenant counting
// (the self-hosted default, §3.4).
func DefaultPolicy() Policy {
	return Policy{Backends: []string{"rules"}}
}

var backendID = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)

// Validate checks a policy.
func (p Policy) Validate() error {
	if len(p.Backends) > 8 {
		return errors.New("at most 8 backends")
	}
	seen := map[string]bool{}
	for _, b := range p.Backends {
		if !backendID.MatchString(b) || seen[b] {
			return fmt.Errorf("invalid or duplicate backend id %q", b)
		}
		seen[b] = true
	}
	if p.DailyQuota < 0 || p.DailyQuota > 10_000_000 {
		return errors.New("daily_quota out of range")
	}
	if p.RatePerMinute < 0 || p.RatePerMinute > 10_000 {
		return errors.New("rate_per_minute out of range")
	}
	if p.MaxMailBytes != 0 && (p.MaxMailBytes < 1024 || p.MaxMailBytes > MaxMailBytesLimit) {
		return fmt.Errorf("max_mail_bytes must be 0 (default) or between 1024 and %d", MaxMailBytesLimit)
	}
	return nil
}

// Tenant is one customer boundary.
type Tenant struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"created_at"`
	Status    string `json:"status"`
	Policy    Policy `json:"policy"`
}

// Device is one paired app install.
type Device struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Label       string `json:"label"`
	PublicKey   string `json:"public_key"` // base64 X9.63 uncompressed P-256 point
	CreatedAt   int64  `json:"created_at"`
	LastSeenDay string `json:"last_seen_day"`
	RotatedAt   int64  `json:"rotated_at,omitempty"`
	RevokedAt   int64  `json:"revoked_at,omitempty"`
}

// Revoked reports whether the device is revoked.
func (d Device) Revoked() bool { return d.RevokedAt != 0 }

// token is a single-use enrolment token; only its SHA-256 is stored.
type token struct {
	Hash      string `json:"hash"`
	TenantID  string `json:"tenant_id"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	UsedAt    int64  `json:"used_at,omitempty"`
}

type state struct {
	Version    int      `json:"version"`
	Generation uint64   `json:"generation"`
	Tenants    []Tenant `json:"tenants"`
	Devices    []Device `json:"devices"`
	Tokens     []token  `json:"tokens"`
}

func (s state) clone() state {
	out := s
	out.Tenants = append([]Tenant(nil), s.Tenants...)
	for i := range out.Tenants {
		out.Tenants[i].Policy.Backends = append([]string(nil), s.Tenants[i].Policy.Backends...)
	}
	out.Devices = append([]Device(nil), s.Devices...)
	out.Tokens = append([]token(nil), s.Tokens...)
	return out
}

// Errors.
var (
	ErrUnknownTenant = errors.New("unknown tenant")
	ErrTenantExists  = errors.New("a tenant with this name exists")
	ErrUnknownDevice = errors.New("unknown device")
	ErrRevoked       = errors.New("device revoked")
	ErrTokenUnknown  = errors.New("unknown enrolment token")
	ErrTokenUsed     = errors.New("enrolment token already used")
	ErrTokenExpired  = errors.New("enrolment token expired")
)

// Registry is safe for concurrent use within a process and across processes sharing the directory.
type Registry struct {
	path, bakPath, lockPath string
	now                     func() time.Time

	mu    sync.RWMutex
	st    state
	stamp fsutil.Stamp
}

// Open loads (or starts) the registry in dir.
func Open(dir string, now func() time.Time) (*Registry, error) {
	if now == nil {
		now = time.Now
	}
	r := &Registry{path: filepath.Join(dir, fileName), bakPath: filepath.Join(dir, bakName),
		lockPath: filepath.Join(dir, lockName), now: now}
	st, stamp, _, err := r.readFile()
	if err != nil {
		return nil, err
	}
	r.st, r.stamp = st, stamp
	return r, nil
}

// readFile reads and validates the registry file; a missing file is an empty registry.
func (r *Registry) readFile() (state, fsutil.Stamp, []byte, error) {
	stamp, err := fsutil.StatStamp(r.path)
	if err != nil {
		return state{}, stamp, nil, err
	}
	data, err := os.ReadFile(r.path)
	if errors.Is(err, os.ErrNotExist) {
		return state{Version: 1}, fsutil.Stamp{}, nil, nil
	}
	if err != nil {
		return state{}, stamp, nil, err
	}
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return state{}, stamp, nil, fmt.Errorf("registry %s is corrupt (restore %s): %w", r.path, bakName, err)
	}
	if err := st.validate(); err != nil {
		return state{}, stamp, nil, fmt.Errorf("registry %s is invalid (restore %s): %w", r.path, bakName, err)
	}
	return st, stamp, data, nil
}

func (s state) validate() error {
	if s.Version != 1 {
		return fmt.Errorf("unsupported version %d", s.Version)
	}
	tenants := map[string]bool{}
	names := map[string]bool{}
	for _, t := range s.Tenants {
		if !ValidUUID(t.ID) || tenants[t.ID] || names[t.Name] || validateName(t.Name) != nil {
			return fmt.Errorf("invalid tenant %q", t.ID)
		}
		if err := t.Policy.Validate(); err != nil {
			return fmt.Errorf("tenant %s: %w", t.ID, err)
		}
		tenants[t.ID], names[t.Name] = true, true
	}
	devices := map[string]bool{}
	for _, d := range s.Devices {
		if !ValidUUID(d.ID) || devices[d.ID] || !tenants[d.TenantID] {
			return fmt.Errorf("invalid device %q", d.ID)
		}
		if _, err := auth.ParseDevicePublicKey(d.PublicKey); err != nil {
			return fmt.Errorf("device %s: %w", d.ID, err)
		}
		devices[d.ID] = true
	}
	for _, t := range s.Tokens {
		if len(t.Hash) != 64 || !tenants[t.TenantID] {
			return errors.New("invalid enrolment token entry")
		}
	}
	return nil
}

// refresh reloads the in-memory state when the file was replaced by another process. A reload
// error keeps the previous state (our own writes are atomic, so this needs an external cause)
// and is returned to the caller.
func (r *Registry) refresh() error {
	stamp, err := fsutil.StatStamp(r.path)
	if err != nil {
		return err
	}
	r.mu.RLock()
	same := stamp == r.stamp
	r.mu.RUnlock()
	if same {
		return nil
	}
	st, stamp, _, err := r.readFile()
	if err != nil {
		return err
	}
	r.mu.Lock()
	r.st, r.stamp = st, stamp
	r.mu.Unlock()
	return nil
}

// Refresh forces a change check; the server calls it periodically to surface load errors.
func (r *Registry) Refresh() error { return r.refresh() }

// mutate applies fn to the latest on-disk state under the cross-process lock and persists it.
func (r *Registry) mutate(fn func(st *state, now time.Time) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	lock, err := fsutil.LockFile(r.lockPath)
	if err != nil {
		return err
	}
	defer lock.Unlock()
	st, stamp, raw, err := r.readFile()
	if err != nil {
		return err
	}
	r.st, r.stamp = st, stamp
	next := st.clone()
	now := r.now()
	if err := fn(&next, now); err != nil {
		return err
	}
	pruneTokens(&next, now)
	next.Generation++
	if err := next.validate(); err != nil {
		return fmt.Errorf("refusing to write an invalid registry: %w", err)
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if raw != nil {
		if err := fsutil.WriteFileAtomic(r.bakPath, raw, 0o600); err != nil {
			return err
		}
	}
	if err := fsutil.WriteFileAtomic(r.path, data, 0o600); err != nil {
		return err
	}
	r.st = next
	r.stamp, err = fsutil.StatStamp(r.path)
	return err
}

func pruneTokens(st *state, now time.Time) {
	kept := st.Tokens[:0]
	for _, t := range st.Tokens {
		end := t.ExpiresAt
		if t.UsedAt != 0 && t.UsedAt > end {
			end = t.UsedAt
		}
		if now.Unix() <= end+int64(tokenMemory/time.Second) {
			kept = append(kept, t)
		}
	}
	st.Tokens = kept
}

// NewID returns a random UUIDv4 string.
func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidUUID checks the lowercase canonical UUID form used for all IDs.
func ValidUUID(s string) bool { return uuidPattern.MatchString(s) }

func validateName(name string) error {
	if name == "" || utf8.RuneCountInString(name) > 64 || !utf8.ValidString(name) {
		return errors.New("tenant name must be 1-64 characters")
	}
	for _, c := range name {
		if unicode.IsControl(c) {
			return errors.New("tenant name must not contain control characters")
		}
	}
	return nil
}

// Day formats the UTC day of t as YYYY-MM-DD.
func Day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// CreateTenant adds a tenant with the default policy.
func (r *Registry) CreateTenant(name string) (Tenant, error) {
	if err := validateName(name); err != nil {
		return Tenant{}, err
	}
	var created Tenant
	err := r.mutate(func(st *state, now time.Time) error {
		for _, t := range st.Tenants {
			if t.Name == name {
				return ErrTenantExists
			}
		}
		created = Tenant{ID: NewID(), Name: name, CreatedAt: now.Unix(), Status: "active", Policy: DefaultPolicy()}
		st.Tenants = append(st.Tenants, created)
		return nil
	})
	return created, err
}

// TenantByName looks up a tenant by its operator-chosen name.
func (r *Registry) TenantByName(name string) (Tenant, error) {
	_ = r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range r.st.Tenants {
		if t.Name == name {
			return t, nil
		}
	}
	return Tenant{}, ErrUnknownTenant
}

// Tenant looks up a tenant by ID.
func (r *Registry) Tenant(id string) (Tenant, error) {
	_ = r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, t := range r.st.Tenants {
		if t.ID == id {
			return t, nil
		}
	}
	return Tenant{}, ErrUnknownTenant
}

// Tenants lists all tenants sorted by name.
func (r *Registry) Tenants() []Tenant {
	_ = r.refresh()
	r.mu.RLock()
	out := append([]Tenant(nil), r.st.Tenants...)
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SetPolicy replaces a tenant's policy after validation.
func (r *Registry) SetPolicy(tenantID string, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	return r.mutate(func(st *state, _ time.Time) error {
		for i := range st.Tenants {
			if st.Tenants[i].ID == tenantID {
				st.Tenants[i].Policy = p
				return nil
			}
		}
		return ErrUnknownTenant
	})
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// CreateEnrolmentToken returns a fresh single-use 128-bit token (base64url) valid for ttl.
func (r *Registry) CreateEnrolmentToken(tenantID string, ttl time.Duration) (string, time.Time, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	var expires time.Time
	err := r.mutate(func(st *state, now time.Time) error {
		found := false
		for _, t := range st.Tenants {
			found = found || t.ID == tenantID
		}
		if !found {
			return ErrUnknownTenant
		}
		expires = now.Add(ttl)
		st.Tokens = append(st.Tokens, token{Hash: hashToken(value), TenantID: tenantID, CreatedAt: now.Unix(), ExpiresAt: expires.Unix()})
		return nil
	})
	return value, expires, err
}

// Enroll consumes a token and registers a device with the given public key (base64 X9.63).
func (r *Registry) Enroll(tokenValue, publicKey, label string) (Device, error) {
	if _, err := auth.ParseDevicePublicKey(publicKey); err != nil {
		return Device{}, err
	}
	wanted := []byte(hashToken(tokenValue))
	var device Device
	err := r.mutate(func(st *state, now time.Time) error {
		index := -1
		for i, t := range st.Tokens {
			if subtle.ConstantTimeCompare([]byte(t.Hash), wanted) == 1 {
				index = i
			}
		}
		if index < 0 {
			return ErrTokenUnknown
		}
		t := &st.Tokens[index]
		if t.UsedAt != 0 {
			return ErrTokenUsed
		}
		if now.Unix() >= t.ExpiresAt {
			return ErrTokenExpired
		}
		t.UsedAt = now.Unix()
		device = Device{ID: NewID(), TenantID: t.TenantID, Label: label, PublicKey: publicKey,
			CreatedAt: now.Unix(), LastSeenDay: Day(now)}
		st.Devices = append(st.Devices, device)
		return nil
	})
	if err != nil {
		return Device{}, err
	}
	return device, nil
}

// Device returns a device. Revoked devices are returned together with ErrRevoked.
func (r *Registry) Device(id string) (Device, error) {
	_ = r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, d := range r.st.Devices {
		if d.ID == id {
			if d.Revoked() {
				return d, ErrRevoked
			}
			return d, nil
		}
	}
	return Device{}, ErrUnknownDevice
}

// Devices lists the devices of a tenant (all tenants if tenantID is empty), including revoked ones.
func (r *Registry) Devices(tenantID string) []Device {
	_ = r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []Device
	for _, d := range r.st.Devices {
		if tenantID == "" || d.TenantID == tenantID {
			out = append(out, d)
		}
	}
	return out
}

// IDs returns the sets of all tenant and device IDs (for counter retention).
func (r *Registry) IDs() (tenants map[string]bool, devices map[string]bool) {
	_ = r.refresh()
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenants, devices = map[string]bool{}, map[string]bool{}
	for _, t := range r.st.Tenants {
		tenants[t.ID] = true
	}
	for _, d := range r.st.Devices {
		devices[d.ID] = true
	}
	return tenants, devices
}

// TouchLastSeen records the day a device was last seen; it writes at most once per device and day.
func (r *Registry) TouchLastSeen(id string, now time.Time) error {
	day := Day(now)
	r.mu.RLock()
	current := ""
	for _, d := range r.st.Devices {
		if d.ID == id {
			current = d.LastSeenDay
		}
	}
	r.mu.RUnlock()
	if current == day {
		return nil
	}
	return r.mutate(func(st *state, _ time.Time) error {
		for i := range st.Devices {
			if st.Devices[i].ID == id {
				st.Devices[i].LastSeenDay = day
				return nil
			}
		}
		return ErrUnknownDevice
	})
}

// Revoke marks a device revoked (idempotent).
func (r *Registry) Revoke(id string) error {
	return r.RevokeInTenant("", id)
}

// RevokeInTenant revokes a device only if it belongs to tenantID (any tenant if empty).
// A device of another tenant is reported as unknown.
func (r *Registry) RevokeInTenant(tenantID, id string) error {
	return r.mutate(func(st *state, now time.Time) error {
		for i := range st.Devices {
			d := &st.Devices[i]
			if d.ID == id && (tenantID == "" || d.TenantID == tenantID) {
				if d.RevokedAt == 0 {
					d.RevokedAt = now.Unix()
				}
				return nil
			}
		}
		return ErrUnknownDevice
	})
}

// RotateKey replaces the public key of an active device.
func (r *Registry) RotateKey(id, publicKey string) error {
	if _, err := auth.ParseDevicePublicKey(publicKey); err != nil {
		return err
	}
	return r.mutate(func(st *state, now time.Time) error {
		for i := range st.Devices {
			if st.Devices[i].ID == id {
				if st.Devices[i].Revoked() {
					return ErrRevoked
				}
				st.Devices[i].PublicKey = publicKey
				st.Devices[i].RotatedAt = now.Unix()
				return nil
			}
		}
		return ErrUnknownDevice
	})
}

// DeleteTenant removes a tenant and all its devices and tokens (§4.6).
func (r *Registry) DeleteTenant(id string) error {
	return r.mutate(func(st *state, _ time.Time) error {
		tenants := st.Tenants[:0]
		found := false
		for _, t := range st.Tenants {
			if t.ID == id {
				found = true
				continue
			}
			tenants = append(tenants, t)
		}
		if !found {
			return ErrUnknownTenant
		}
		st.Tenants = tenants
		devices := st.Devices[:0]
		for _, d := range st.Devices {
			if d.TenantID != id {
				devices = append(devices, d)
			}
		}
		st.Devices = devices
		tokens := st.Tokens[:0]
		for _, t := range st.Tokens {
			if t.TenantID != id {
				tokens = append(tokens, t)
			}
		}
		st.Tokens = tokens
		return nil
	})
}
