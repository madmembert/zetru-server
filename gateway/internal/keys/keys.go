// Package keys creates, loads and rotates the gateway's key material (concept §4.1, §4.6).
//
// Layout of the data directory (all files mode 0600):
//
//	identity.key      Ed25519 server identity key (PKCS#8 PEM), signs responses and pin sets
//	fingerprint.key   K_fp, 32 random bytes (base64), keys campaign counters
//	tls-state.json    primary TLS key pair, pending "next" key pair, the signed pin set and the
//	                  rotation state, in one file so that every transition is one atomic write
//	backup/tls.pem    backup TLS key pair (the operator may move it offline; its pin stays in
//	                  tls-state.json)
//
// Every mutation holds an exclusive lock on .keys.lock, so the CLI can run next to the server.
package keys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"zetru.app/gateway/internal/fsutil"
)

const (
	identityFile    = "identity.key"
	fingerprintFile = "fingerprint.key"
	stateFile       = "tls-state.json"
	backupDir       = "backup"
	backupFile      = "tls.pem"
	backupNewFile   = "tls.pem.new"
	lockFile        = ".keys.lock"

	// TransitionPeriod is how long the old primary key stays pinned and served after a planned
	// rotation starts (§4.6: "After 30 days the old key is removed").
	TransitionPeriod = 30 * 24 * time.Hour
)

// Rotation kinds.
const RotationPlanned = "planned"

// PinSet is the public, signed pin set (§4.6, ServerInfo.pin_set). Signature is an additive field:
// base64 Ed25519 by the server identity key over PinSetSigningString.
type PinSet struct {
	Seq       int      `json:"seq"`
	Pins      []string `json:"pins"`
	ValidFrom int64    `json:"valid_from"`
	Signature string   `json:"signature"`
}

// Rotation describes a pending planned rotation.
type Rotation struct {
	Kind         string `json:"kind"`
	StartedAt    int64  `json:"started_at"`
	PromoteAfter int64  `json:"promote_after"`
}

// state is the on-disk content of tls-state.json.
type state struct {
	Version    int       `json:"version"`
	PinSet     PinSet    `json:"pin_set"`
	BackupPin  string    `json:"backup_pin"`
	Rotation   *Rotation `json:"rotation,omitempty"`
	PrimaryPEM string    `json:"primary_pem"`
	NextPEM    string    `json:"next_pem,omitempty"`
}

// Material is everything the gateway needs at runtime.
type Material struct {
	Primary     tls.Certificate // Leaf is set
	PrimaryPin  string
	NextPin     string // empty unless a rotation is pending
	BackupPin   string
	Identity    ed25519.PrivateKey
	Fingerprint []byte // K_fp, 32 bytes
	PinSet      PinSet
	Rotation    *Rotation
}

// SPKIPin returns base64(SHA-256(SubjectPublicKeyInfo)) of a certificate (§4.3).
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// PinSetSigningString is the byte string the identity key signs for a pin set:
// "ZETRU1-PINSET\n<seq>\n<valid_from>\n<pin 1>\n…\n<pin n>".
func PinSetSigningString(ps PinSet) string {
	return "ZETRU1-PINSET\n" + strconv.Itoa(ps.Seq) + "\n" + strconv.FormatInt(ps.ValidFrom, 10) + "\n" + strings.Join(ps.Pins, "\n")
}

// VerifyPinSet checks the pin-set signature with the server identity public key.
func VerifyPinSet(pub ed25519.PublicKey, ps PinSet) bool {
	sig, err := base64.StdEncoding.DecodeString(ps.Signature)
	return err == nil && len(pub) == ed25519.PublicKeySize && ed25519.Verify(pub, []byte(PinSetSigningString(ps)), sig)
}

func signPinSet(identity ed25519.PrivateKey, ps *PinSet) {
	ps.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(identity, []byte(PinSetSigningString(*ps))))
}

// IdentityPublic returns the base64 server identity public key ("sid").
func (m *Material) IdentityPublic() string {
	return base64.StdEncoding.EncodeToString(m.Identity.Public().(ed25519.PublicKey))
}

// ShortFingerprint formats the first 8 bytes of the identity key as "abcd efgh ijkl mnop" (§4.2).
func ShortFingerprint(publicKey ed25519.PublicKey) string {
	h := hex.EncodeToString(publicKey[:8])
	return fmt.Sprintf("%s %s %s %s", h[0:4], h[4:8], h[8:12], h[12:16])
}

// Exists reports whether key material has been initialised in dir.
func Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, identityFile))
	return err == nil
}

// Init creates all key material in dir. It refuses to overwrite existing keys.
func Init(dir string, hosts []string, now time.Time) error {
	if err := os.MkdirAll(filepath.Join(dir, backupDir), 0o700); err != nil {
		return err
	}
	lock, err := fsutil.LockFile(filepath.Join(dir, lockFile))
	if err != nil {
		return err
	}
	defer lock.Unlock()
	for _, name := range []string{identityFile, fingerprintFile, stateFile, filepath.Join(backupDir, backupFile)} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return errors.New("key material already exists; refusing to overwrite")
		}
	}
	primaryPEM, primaryPin, err := newTLSPair(hosts, now)
	if err != nil {
		return err
	}
	backupPEM, backupPin, err := newTLSPair(hosts, now)
	if err != nil {
		return err
	}
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(identity)
	if err != nil {
		return err
	}
	fp := make([]byte, 32)
	if _, err := rand.Read(fp); err != nil {
		return err
	}
	st := state{Version: 1, BackupPin: backupPin, PrimaryPEM: primaryPEM,
		PinSet: PinSet{Seq: 1, Pins: []string{primaryPin, backupPin}, ValidFrom: now.Unix()}}
	signPinSet(identity, &st.PinSet)
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, identityFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, fingerprintFile), []byte(base64.StdEncoding.EncodeToString(fp)+"\n"), 0o600); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, backupDir, backupFile), []byte(backupPEM), 0o600); err != nil {
		return err
	}
	return writeState(dir, st)
}

// Load reads and validates the key material in dir.
func Load(dir string) (*Material, error) {
	identity, err := loadIdentity(dir)
	if err != nil {
		return nil, err
	}
	fpText, err := os.ReadFile(filepath.Join(dir, fingerprintFile))
	if err != nil {
		return nil, fmt.Errorf("fingerprint key: %w", err)
	}
	fp, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(fpText)))
	if err != nil || len(fp) != 32 {
		return nil, errors.New("fingerprint key: invalid")
	}
	st, err := readState(dir)
	if err != nil {
		return nil, err
	}
	return materialFromState(st, identity, fp)
}

func materialFromState(st state, identity ed25519.PrivateKey, fp []byte) (*Material, error) {
	primary, primaryPin, err := parsePair(st.PrimaryPEM)
	if err != nil {
		return nil, fmt.Errorf("primary TLS key: %w", err)
	}
	pub := identity.Public().(ed25519.PublicKey)
	if !VerifyPinSet(pub, st.PinSet) {
		return nil, errors.New("pin set signature does not verify with the identity key")
	}
	if len(st.PinSet.Pins) < 2 || len(st.PinSet.Pins) > 3 {
		return nil, errors.New("pin set must contain 2 or 3 pins")
	}
	if !contains(st.PinSet.Pins, primaryPin) {
		return nil, errors.New("the primary TLS key is not in the pin set; refusing to serve an unpinned key")
	}
	if !contains(st.PinSet.Pins, st.BackupPin) {
		return nil, errors.New("the backup pin is not in the pin set")
	}
	m := &Material{Primary: primary, PrimaryPin: primaryPin, BackupPin: st.BackupPin, Identity: identity,
		Fingerprint: fp, PinSet: st.PinSet, Rotation: st.Rotation}
	if st.Rotation != nil {
		_, nextPin, err := parsePair(st.NextPEM)
		if err != nil {
			return nil, fmt.Errorf("next TLS key: %w", err)
		}
		if !contains(st.PinSet.Pins, nextPin) {
			return nil, errors.New("the next TLS key is not in the pin set")
		}
		m.NextPin = nextPin
	}
	return m, nil
}

// StartRotation begins a planned rotation (§4.6): it creates the next key pair and publishes the
// pin set [current, next, backup]. The current key keeps being served for TransitionPeriod.
func StartRotation(dir string, hosts []string, now time.Time) error {
	return mutate(dir, func(st *state, identity ed25519.PrivateKey) error {
		if st.Rotation != nil {
			return errors.New("a rotation is already pending; complete it first (rotate-tls --complete)")
		}
		_, currentPin, err := parsePair(st.PrimaryPEM)
		if err != nil {
			return err
		}
		nextPEM, nextPin, err := newTLSPair(hosts, now)
		if err != nil {
			return err
		}
		st.NextPEM = nextPEM
		st.Rotation = &Rotation{Kind: RotationPlanned, StartedAt: now.Unix(), PromoteAfter: now.Add(TransitionPeriod).Unix()}
		st.PinSet = PinSet{Seq: st.PinSet.Seq + 1, Pins: []string{currentPin, nextPin, st.BackupPin}, ValidFrom: now.Unix()}
		signPinSet(identity, &st.PinSet)
		return nil
	})
}

// ErrNoRotation is returned when no rotation is pending (or, for PromoteIfDue, none is due).
var ErrNoRotation = errors.New("no rotation is pending")

// CompleteRotation makes the next key the primary key and removes the old key from the pin set.
func CompleteRotation(dir string, now time.Time) error {
	return completeRotation(dir, now, false)
}

func completeRotation(dir string, now time.Time, onlyIfDue bool) error {
	return mutate(dir, func(st *state, identity ed25519.PrivateKey) error {
		if st.Rotation == nil || (onlyIfDue && now.Unix() < st.Rotation.PromoteAfter) {
			return ErrNoRotation
		}
		_, nextPin, err := parsePair(st.NextPEM)
		if err != nil {
			return err
		}
		st.PrimaryPEM = st.NextPEM
		st.NextPEM = ""
		st.Rotation = nil
		st.PinSet = PinSet{Seq: st.PinSet.Seq + 1, Pins: []string{nextPin, st.BackupPin}, ValidFrom: now.Unix()}
		signPinSet(identity, &st.PinSet)
		return nil
	})
}

// PromoteIfDue completes a pending rotation once its transition period has passed.
func PromoteIfDue(dir string, now time.Time) (bool, error) {
	st, err := readState(dir)
	if err != nil {
		return false, err
	}
	if st.Rotation == nil || now.Unix() < st.Rotation.PromoteAfter {
		return false, nil
	}
	err = completeRotation(dir, now, true)
	if errors.Is(err, ErrNoRotation) {
		return false, nil // completed or replaced concurrently
	}
	return err == nil, err
}

// ActivateBackup handles loss of the primary key (§4.6): the backup key (already pinned) becomes the
// primary key immediately, a fresh backup key is generated, and the lost key leaves the pin set.
// A pending planned rotation is cancelled. backup/tls.pem must hold the backup key pair.
func ActivateBackup(dir string, hosts []string, now time.Time) error {
	newBackupPath := filepath.Join(dir, backupDir, backupNewFile)
	err := mutate(dir, func(st *state, identity ed25519.PrivateKey) error {
		data, err := os.ReadFile(filepath.Join(dir, backupDir, backupFile))
		if err != nil {
			return fmt.Errorf("backup key not found at %s: restore it before activating (%w)", filepath.Join(dir, backupDir, backupFile), err)
		}
		_, oldBackupPin, err := parsePair(string(data))
		if err != nil {
			return fmt.Errorf("backup key: %w", err)
		}
		if oldBackupPin != st.BackupPin {
			return errors.New("the backup key file does not match the pinned backup key")
		}
		newBackupPEM, newBackupPin, err := newTLSPair(hosts, now)
		if err != nil {
			return err
		}
		if err := fsutil.WriteFileAtomic(newBackupPath, []byte(newBackupPEM), 0o600); err != nil {
			return err
		}
		st.PrimaryPEM = string(data)
		st.NextPEM = ""
		st.Rotation = nil
		st.BackupPin = newBackupPin
		st.PinSet = PinSet{Seq: st.PinSet.Seq + 1, Pins: []string{oldBackupPin, newBackupPin}, ValidFrom: now.Unix()}
		signPinSet(identity, &st.PinSet)
		return nil
	})
	if err != nil {
		return err
	}
	lock, err := fsutil.LockFile(filepath.Join(dir, lockFile))
	if err != nil {
		return err
	}
	defer lock.Unlock()
	return repairBackup(dir)
}

// repairBackup finishes an interrupted ActivateBackup: a pending backup/tls.pem.new whose pin is the
// pinned backup pin replaces backup/tls.pem; a stale one is removed. Callers hold the lock.
func repairBackup(dir string) error {
	newPath := filepath.Join(dir, backupDir, backupNewFile)
	data, err := os.ReadFile(newPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, err := readState(dir)
	if err != nil {
		return err
	}
	if _, pin, perr := parsePair(string(data)); perr == nil && pin == st.BackupPin {
		if err := os.Rename(newPath, filepath.Join(dir, backupDir, backupFile)); err != nil {
			return err
		}
		return fsutil.SyncDir(filepath.Join(dir, backupDir))
	}
	return os.Remove(newPath)
}

// mutate runs fn on the current state under the keys lock and writes the result atomically.
func mutate(dir string, fn func(st *state, identity ed25519.PrivateKey) error) error {
	lock, err := fsutil.LockFile(filepath.Join(dir, lockFile))
	if err != nil {
		return err
	}
	defer lock.Unlock()
	if err := repairBackup(dir); err != nil {
		return err
	}
	identity, err := loadIdentity(dir)
	if err != nil {
		return err
	}
	st, err := readState(dir)
	if err != nil {
		return err
	}
	if err := fn(&st, identity); err != nil {
		return err
	}
	return writeState(dir, st)
}

func readState(dir string) (state, error) {
	var st state
	data, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return st, fmt.Errorf("TLS state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, fmt.Errorf("TLS state: %w", err)
	}
	if st.Version != 1 {
		return st, fmt.Errorf("TLS state: unsupported version %d", st.Version)
	}
	return st, nil
}

func writeState(dir string, st state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(filepath.Join(dir, stateFile), data, 0o600)
}

func loadIdentity(dir string) (ed25519.PrivateKey, error) {
	identityPEM, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		return nil, fmt.Errorf("identity key: %w", err)
	}
	block, _ := pem.Decode(identityPEM)
	if block == nil {
		return nil, errors.New("identity key: no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	identity, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not Ed25519")
	}
	return identity, nil
}

// newTLSPair returns a PEM (certificate + PKCS#8 key) of a fresh self-signed P-256 certificate.
func newTLSPair(hosts []string, now time.Time) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return "", "", err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Zetru analysis server"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(20, 0, 0), // pinned key, not CA-validated (§4.3)
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if host != "" {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", err
	}
	out := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return out, SPKIPin(cert), nil
}

// parsePair parses a PEM with a certificate and its matching private key.
func parsePair(pemText string) (tls.Certificate, string, error) {
	pair, err := tls.X509KeyPair([]byte(pemText), []byte(pemText))
	if err != nil {
		return tls.Certificate{}, "", err
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		return tls.Certificate{}, "", errors.New("TLS key must be ECDSA P-256")
	}
	pair.Leaf = leaf
	return pair, SPKIPin(leaf), nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Manager holds the live key material of a running server and picks up changes made by the CLI.
type Manager struct {
	dir   string
	mu    sync.Mutex
	stamp fsutil.Stamp
	mat   atomic.Pointer[Material]
}

// NewManager loads the material in dir.
func NewManager(dir string) (*Manager, error) {
	m := &Manager{dir: dir}
	if _, err := m.Refresh(true); err != nil {
		return nil, err
	}
	return m, nil
}

// Material returns the current material (never nil after NewManager succeeded).
func (m *Manager) Material() *Material { return m.mat.Load() }

// GetCertificate serves the current primary certificate; it is used as tls.Config.GetCertificate so
// that a promotion takes effect without a restart.
func (m *Manager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := m.mat.Load().Primary
	return &cert, nil
}

// Refresh reloads the material if tls-state.json changed (or always if force is set). On a load
// error the previous material stays active and the error is returned.
func (m *Manager) Refresh(force bool) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	stamp, err := fsutil.StatStamp(filepath.Join(m.dir, stateFile))
	if err != nil {
		return false, err
	}
	if !force && stamp == m.stamp {
		return false, nil
	}
	mat, err := Load(m.dir)
	if err != nil {
		return false, err
	}
	m.mat.Store(mat)
	m.stamp = stamp
	return true, nil
}

// Tick promotes a due rotation and reloads changed material.
func (m *Manager) Tick(now time.Time) error {
	if _, err := PromoteIfDue(m.dir, now); err != nil {
		return err
	}
	_, err := m.Refresh(false)
	return err
}
