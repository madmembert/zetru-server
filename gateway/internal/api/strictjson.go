package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode"
)

var errStrictJSON = errors.New("not a strict JSON object")

// foldKey maps a key to the representative of its case-folding class (the smallest rune of each
// unicode.SimpleFold orbit), so foldKey(a) == foldKey(b) exactly when strings.EqualFold(a, b),
// which is how encoding/json matches object keys to struct fields.
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			low = min(low, f)
		}
		b.WriteRune(low)
	}
	return b.String()
}

// strictObject decodes exactly one JSON object into its raw member values. It rejects duplicate
// keys and keys that differ only in case: encoding/json matches those case-insensitively to the
// same struct field (the last one wins), while a case-sensitive reader such as the app's decoder
// or Python's json module sees the first. What the gateway validates must be exactly what the next
// reader sees (GO-07).
func strictObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, errStrictJSON
	}
	out := map[string]json.RawMessage{}
	folded := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errStrictJSON
		}
		key, ok := tok.(string)
		if !ok || folded[foldKey(key)] {
			return nil, errStrictJSON
		}
		folded[foldKey(key)] = true
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, errStrictJSON
		}
		out[key] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errStrictJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errStrictJSON
	}
	return out, nil
}

// exactKeys reports whether every key of obj that case-folds to one of the known names is spelled
// exactly like it ("ID" next to a known "id" is refused, not matched).
func exactKeys(obj map[string]json.RawMessage, known ...string) bool {
	folded := make(map[string]string, len(known))
	for _, k := range known {
		folded[foldKey(k)] = k
	}
	for k := range obj {
		if want, ok := folded[foldKey(k)]; ok && k != want {
			return false
		}
	}
	return true
}

// decodeStrict decodes a JSON object into v after the checks of strictObject and exactKeys (with
// the names in known), so the struct sees exactly the members a case-sensitive reader sees.
func decodeStrict(data []byte, v any, known ...string) bool {
	obj, err := strictObject(data)
	if err != nil || !exactKeys(obj, known...) {
		return false
	}
	return json.Unmarshal(data, v) == nil
}
