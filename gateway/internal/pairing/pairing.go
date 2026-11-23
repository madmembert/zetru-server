// Package pairing builds the pairing code of concept §4.2:
// zetru://pair?v=1&d=<base64url(JSON)> with the fields v, urls, pins, trust, sid, tenant, token, name.
package pairing

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"zetru.app/gateway/internal/config"
	"zetru.app/gateway/internal/registry"
)

// Payload is the JSON inside the pairing code. Field order follows §4.2.
type Payload struct {
	V      int      `json:"v"`
	URLs   []string `json:"urls"`
	Pins   []string `json:"pins"`
	Trust  string   `json:"trust"`
	SID    string   `json:"sid"`
	Tenant string   `json:"tenant"`
	Token  string   `json:"token"`
	Name   string   `json:"name"`
}

const prefix = "zetru://pair?v=1&d="

// Validate applies the same rules as the app's parser.
func (p Payload) Validate() error {
	if p.V != 1 {
		return errors.New("version must be 1")
	}
	if err := (config.Server{Version: 1, Name: p.Name, URLs: p.URLs, Trust: p.Trust}).Validate(); err != nil {
		return err
	}
	if len(p.Pins) < 1 || len(p.Pins) > 3 {
		return errors.New("1-3 pins required")
	}
	for _, pin := range p.Pins {
		if raw, err := base64.StdEncoding.DecodeString(pin); err != nil || len(raw) != 32 {
			return errors.New("pins must be base64 SHA-256 values")
		}
	}
	if raw, err := base64.StdEncoding.DecodeString(p.SID); err != nil || len(raw) != 32 {
		return errors.New("sid must be a base64 Ed25519 public key")
	}
	if !registry.ValidUUID(p.Tenant) {
		return errors.New("tenant must be a UUID")
	}
	if p.Token == "" || len(p.Token) > 64 {
		return errors.New("token missing")
	}
	return nil
}

// URI returns the pairing link.
func (p Payload) URI() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// Parse decodes a pairing link (used by tests and for operator diagnostics).
func Parse(link string) (Payload, error) {
	var p Payload
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Scheme != "zetru" || u.Host != "pair" || u.Query().Get("v") != "1" {
		return p, errors.New("not a zetru pairing link")
	}
	raw, err := base64.RawURLEncoding.DecodeString(u.Query().Get("d"))
	if err != nil {
		return p, errors.New("payload is not base64url")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	return p, p.Validate()
}
