package remediation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// buildMobileconfig renders a well-formed Apple configuration-profile plist
// (.mobileconfig) for the mapped rule in in.Rule.RuleKey. Returns
// ErrNoMapping when no macOSMappings entry exists.
//
// SIGNING: this produces the plist content only. It is NOT wrapped in a CMS
// (PKCS#7) signature — a genuinely Apple-trusted "signed .mobileconfig" (the
// kind macOS/Jamf will show as "Verified" rather than "Not Verified") needs
// a real code-signing certificate and an S/MIME/CMS signing step, which is
// a distinct undertaking from the Ed25519 signing this codebase already has
// (internal/agentconfig — a different mechanism the agent verifies itself,
// not one macOS's profile installer or Jamf recognise). See this ticket's
// final report for the follow-up recommendation. content_hash in the DB
// row is a content-integrity hash, not a claim of Apple/CMS trust.
func buildMobileconfig(in GenerateInput) ([]byte, error) {
	spec, ok := macOSMappings[in.Rule.RuleKey]
	if !ok {
		return nil, ErrNoMapping
	}

	topUUID := deterministicUUID(in.TenantID, in.DeviceID, in.Rule.RuleKey, "top")
	innerUUID := deterministicUUID(in.TenantID, in.DeviceID, in.Rule.RuleKey, "payload")
	identifier := fmt.Sprintf("im.patched.remediation.%s.%s", in.Rule.RuleKey, in.DeviceID)

	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString(`<dict>` + "\n")

	b.WriteString("\t<key>PayloadContent</key>\n\t<array>\n\t\t<dict>\n")
	writeStringKV(&b, 3, "PayloadDisplayName", "Patched: "+in.Rule.Title)
	writeStringKV(&b, 3, "PayloadIdentifier", identifier+".payload")
	writeStringKV(&b, 3, "PayloadType", spec.PayloadType)
	writeStringKV(&b, 3, "PayloadUUID", innerUUID)
	writeIntKV(&b, 3, "PayloadVersion", "1")
	for _, s := range spec.Settings {
		switch s.Kind {
		case "bool":
			writeBoolKV(&b, 3, s.Key, s.Value == "true")
		case "int":
			writeIntKV(&b, 3, s.Key, s.Value)
		default:
			writeStringKV(&b, 3, s.Key, s.Value)
		}
	}
	b.WriteString("\t\t</dict>\n\t</array>\n")

	writeStringKV(&b, 1, "PayloadDescription", fmt.Sprintf(
		"Patched remediation for %s (%s). %s Generated %s from rule pack %s; benchmark rule %s.",
		in.Rule.RuleKey, in.Rule.Title, spec.Rationale, in.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"),
		in.Rule.BenchmarkVersion, in.Rule.RuleKey,
	))
	writeStringKV(&b, 1, "PayloadDisplayName", "Patched: "+in.Rule.Title)
	writeStringKV(&b, 1, "PayloadIdentifier", identifier)
	writeStringKV(&b, 1, "PayloadOrganization", "Patched.im Ltd")
	b.WriteString("\t<key>PayloadRemovalDisallowed</key>\n\t<false/>\n")
	writeStringKV(&b, 1, "PayloadType", "Configuration")
	writeStringKV(&b, 1, "PayloadUUID", topUUID)
	writeIntKV(&b, 1, "PayloadVersion", "1")

	b.WriteString(`</dict>` + "\n")
	b.WriteString(`</plist>` + "\n")

	return b.Bytes(), nil
}

func writeStringKV(b *bytes.Buffer, indent int, key, value string) {
	tabs := stringOf(indent)
	fmt.Fprintf(b, "%s<key>%s</key>\n%s<string>%s</string>\n", tabs, escapePlist(key), tabs, escapePlist(value))
}

func writeIntKV(b *bytes.Buffer, indent int, key, value string) {
	tabs := stringOf(indent)
	fmt.Fprintf(b, "%s<key>%s</key>\n%s<integer>%s</integer>\n", tabs, escapePlist(key), tabs, value)
}

func writeBoolKV(b *bytes.Buffer, indent int, key string, value bool) {
	tabs := stringOf(indent)
	elem := "false"
	if value {
		elem = "true"
	}
	fmt.Fprintf(b, "%s<key>%s</key>\n%s<%s/>\n", tabs, escapePlist(key), tabs, elem)
}

// stringOf returns n tab characters, used for plist indentation.
func stringOf(n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = '\t'
	}
	return string(out)
}

// escapePlist escapes the five XML-reserved characters for safe inclusion in
// plist <string>/<key> element text. Field values here are drawn from
// compliance_rules content (title, rule_key) and identifiers we construct
// ourselves, not arbitrary user input, but escaping unconditionally is
// cheap and removes any dependency on that continuing to be true.
func escapePlist(s string) string {
	var b bytes.Buffer
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// deterministicUUID derives a stable, UUID-formatted string from the given
// parts (sha256, first 16 bytes, standard 8-4-4-4-12 hex grouping). Not a
// cryptographically meaningful UUID version/variant — Apple's profile
// installer only requires PayloadUUID to be a unique-looking UUID string,
// not a real RFC 4122 UUID. Deterministic (not crypto/rand-generated) so
// regenerating an artefact for the same (tenant, device, rule) with
// unchanged inputs is reproducible and testable; this codebase has no UUID
// library dependency today (IDs are otherwise always DB-generated), and
// this avoids adding one for a single derived string.
func deterministicUUID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	hexStr := hex.EncodeToString(sum[:16])
	return fmt.Sprintf("%s-%s-%s-%s-%s", hexStr[0:8], hexStr[8:12], hexStr[12:16], hexStr[16:20], hexStr[20:32])
}
