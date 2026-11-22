// Package keys creates and loads the gateway's key material (concept §4.1).
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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Material is everything the gateway needs at runtime.
type Material struct {
	TLS         tls.Certificate
	TLSLeaf     *x509.Certificate
	BackupLeaf  *x509.Certificate // nil if the backup was moved offline
	BackupPin   string            // kept in pins.json when the backup key is offline
	Identity    ed25519.PrivateKey
	Fingerprint []byte // K_fp, 32 bytes
}

const (
	tlsKeyFile      = "tls.key"
	tlsCertFile     = "tls.crt"
	backupDir       = "backup"
	identityFile    = "identity.key"
	fingerprintFile = "fingerprint.key"
	backupPinFile   = "backup.pin"
)

// SPKIPin returns base64(SHA-256(SubjectPublicKeyInfo)) of a certificate.
func SPKIPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Pins returns the primary and backup pins.
func (m *Material) Pins() []string {
	pins := []string{SPKIPin(m.TLSLeaf)}
	if m.BackupLeaf != nil {
		pins = append(pins, SPKIPin(m.BackupLeaf))
	} else if m.BackupPin != "" {
		pins = append(pins, m.BackupPin)
	}
	return pins
}

// IdentityPublic returns the base64 server identity public key ("sid").
func (m *Material) IdentityPublic() string {
	return base64.StdEncoding.EncodeToString(m.Identity.Public().(ed25519.PublicKey))
}

// ShortFingerprint formats the first 8 bytes of the identity key as "abcd efgh ijkl mnop".
func ShortFingerprint(publicKey ed25519.PublicKey) string {
	h := hex.EncodeToString(publicKey[:8])
	return fmt.Sprintf("%s %s %s %s", h[0:4], h[4:8], h[8:12], h[12:16])
}

// Init creates all key material in dir. It refuses to overwrite existing keys.
func Init(dir string, hostnames []string) error {
	if _, err := os.Stat(filepath.Join(dir, identityFile)); err == nil {
		return errors.New("keys already exist; refusing to overwrite")
	}
	if err := os.MkdirAll(filepath.Join(dir, backupDir), 0o700); err != nil {
		return err
	}
	for _, target := range []string{dir, filepath.Join(dir, backupDir)} {
		if err := writeTLSPair(target, hostnames); err != nil {
			return err
		}
	}
	_, identity, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(identity)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, identityFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil {
		return err
	}
	fp := make([]byte, 32)
	if _, err := rand.Read(fp); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, fingerprintFile), []byte(base64.StdEncoding.EncodeToString(fp)))
}

// RotateTLS replaces the primary TLS pair; the old pin must be published for a transition period by the caller.
func RotateTLS(dir string, hostnames []string) error {
	return writeTLSPair(dir, hostnames)
}

func writeTLSPair(dir string, hostnames []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Zetru analysis server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // pinned key, not CA-validated
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, host := range hostnames {
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else if host != "" {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(filepath.Join(dir, tlsKeyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, tlsCertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// Load reads the key material from dir.
func Load(dir string) (*Material, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, tlsCertFile), filepath.Join(dir, tlsKeyFile))
	if err != nil {
		return nil, fmt.Errorf("tls key pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	pair.Leaf = leaf
	material := &Material{TLS: pair, TLSLeaf: leaf}
	if backupPEM, err := os.ReadFile(filepath.Join(dir, backupDir, tlsCertFile)); err == nil {
		if block, _ := pem.Decode(backupPEM); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				material.BackupLeaf = cert
			}
		}
	}
	if pin, err := os.ReadFile(filepath.Join(dir, backupPinFile)); err == nil {
		material.BackupPin = string(pin)
	}
	identityPEM, err := os.ReadFile(filepath.Join(dir, identityFile))
	if err != nil {
		return nil, err
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
	material.Identity = identity
	fpText, err := os.ReadFile(filepath.Join(dir, fingerprintFile))
	if err != nil {
		return nil, err
	}
	fp, err := base64.StdEncoding.DecodeString(string(fpText))
	if err != nil || len(fp) != 32 {
		return nil, errors.New("fingerprint key: invalid")
	}
	material.Fingerprint = fp
	return material, nil
}

// writeFileAtomic writes with mode 0600 via a temporary file and rename.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// WriteFileAtomic is exported for other packages that persist state.
func WriteFileAtomic(path string, data []byte) error { return writeFileAtomic(path, data) }
