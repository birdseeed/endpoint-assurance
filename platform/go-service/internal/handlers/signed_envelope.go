package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// signedEnvelope is the {signed_payload, signature, key_id} wire shape shared
// by the agent artifact metadata envelope and GET /v1/agent-config. It was
// first hardened for the retired signed catalogue (PAT-495, retired PAT-2246).
type signedEnvelope struct {
	SignedPayload string
	Signature     string
	KeyID         string
}

// decodeStrictEnvelope parses body into a signedEnvelope with EXACT-key JSON
// semantics: a top-level object containing precisely one occurrence each of
// "signed_payload", "signature", and "key_id" (each a JSON string), no other
// fields, and no trailing content after the closing brace.
//
// WHY NOT encoding/json.Unmarshal (found in PAT-495 review): Go's
// encoding/json matches JSON object keys to struct fields CASE-INSENSITIVELY
// when there is no exact match, and for a repeated key it silently keeps the
// LAST occurrence — but updater's verify-catalogue.py parses the identical
// wire shape with Python's json.loads, which is case-SENSITIVE (a key that
// doesn't literally match a lookup is just absent). So a body carrying both a
// bogus lowercase "signed_payload" AND a genuine "SIGNED_PAYLOAD" — or a
// literal duplicate "signed_payload" key — can decode HERE to the genuine
// value (verifies, stores, serves 200), while verify-catalogue.py on every
// endpoint reads the OTHER value and rejects it: server says verified,
// endpoint says forged, hash-pinning check silently skips. json.Decoder's
// DisallowUnknownFields does NOT close this gap on its own — it uses the same
// case-insensitive matching to decide what counts as "known", so a case
// variant of a real field is never flagged unknown, and it does not detect
// duplicate keys at all. Hence the explicit token-by-token walk below, which
// checks key equality with Go's plain "==" (ASCII-exact) rather than through
// reflect-based struct-tag matching.
func decodeStrictEnvelope(body []byte) (signedEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(body))

	tok, err := dec.Token()
	if err != nil {
		return signedEnvelope{}, fmt.Errorf("read envelope: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return signedEnvelope{}, errors.New("envelope must be a JSON object")
	}

	seen := map[string]bool{}
	var env signedEnvelope
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return signedEnvelope{}, fmt.Errorf("read envelope key: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return signedEnvelope{}, errors.New("envelope key is not a string")
		}
		switch key {
		case "signed_payload", "signature", "key_id":
			if seen[key] {
				return signedEnvelope{}, fmt.Errorf("envelope has a duplicate %q key", key)
			}
			seen[key] = true
		default:
			return signedEnvelope{}, fmt.Errorf("envelope has unexpected field %q", key)
		}

		valTok, err := dec.Token()
		if err != nil {
			return signedEnvelope{}, fmt.Errorf("read value for %q: %w", key, err)
		}
		val, ok := valTok.(string)
		if !ok {
			return signedEnvelope{}, fmt.Errorf("envelope field %q must be a JSON string", key)
		}
		switch key {
		case "signed_payload":
			env.SignedPayload = val
		case "signature":
			env.Signature = val
		case "key_id":
			env.KeyID = val
		}
	}

	tok, err = dec.Token() // closing '}'
	if err != nil {
		return signedEnvelope{}, fmt.Errorf("read envelope: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '}' {
		return signedEnvelope{}, errors.New("malformed envelope object")
	}

	// Reject any trailing content after the single top-level object —
	// matches Python json.loads, which raises on "Extra data" rather than
	// silently ignoring it.
	if _, err := dec.Token(); err != io.EOF {
		return signedEnvelope{}, errors.New("unexpected trailing data after envelope")
	}

	if !seen["signed_payload"] || !seen["signature"] || !seen["key_id"] {
		return signedEnvelope{}, errors.New("envelope must carry signed_payload, signature, and key_id")
	}
	if env.SignedPayload == "" || env.Signature == "" || env.KeyID == "" {
		return signedEnvelope{}, errors.New("envelope must carry non-empty signed_payload, signature, and key_id")
	}
	return env, nil
}
