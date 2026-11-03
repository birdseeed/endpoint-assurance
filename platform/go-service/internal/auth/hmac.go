package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

var (
	ErrMissingSignature   = errors.New("missing X-Patched-Signature header")
	ErrMalformedSignature = errors.New("signature header is not valid hex")
	ErrInvalidSignature   = errors.New("signature does not match")
)

// hmacDomainV3 is the literal ASCII domain-separation prefix (including its
// trailing newline) prepended to every v3 signing input. hmacDomainV2 is
// retained only to verify installed PAT-1136 agents during the transition.
// See
// VerifyHMACSigned and contracts/agent-config-schema.md's "Request signing
// (v3)" section for the full canonical form and test vectors.
const (
	hmacDomainV3 = "patched-hmac-v3\n"
	hmacDomainV2 = "patched-hmac-v2\n"
)

// EndpointID is a stable, server-owned identifier for one signed agent
// operation. It is deliberately not the request URL: path parameters and
// query strings are transport detail, while these identifiers are the durable
// contract that both endpoint agents sign.
type EndpointID string

// HMACSigningForm identifies the compatibility branch that accepted a
// request. Values are deliberately a closed, low-cardinality vocabulary so
// callers can aggregate them without ever retaining a signature or signing
// input.
type HMACSigningForm string

const (
	HMACSigningFormUnknown      HMACSigningForm = "Unknown"
	HMACSigningFormV3           HMACSigningForm = "v3"
	HMACSigningFormTargetlessV2 HMACSigningForm = "targetless_v2"
	HMACSigningFormBodyOnly     HMACSigningForm = "body_only"
)

const (
	EndpointInventory  EndpointID = "inventory"
	EndpointProvenance EndpointID = "provenance"
	// EndpointEvents is POST /v1/events (PAT-1022/PAT-499): SIEM-style audit
	// events. Must stay in sync with the "events" literal both agents already
	// sign with — Windows HmacSigner.EndpointEvents
	// (updater/windows/src/Shared/Auth/HmacSigner.cs) and macOS
	// compute_hmac's second argument at every call site
	// (updater/endpoint/patched-update.sh).
	EndpointEvents                  EndpointID = "events"
	EndpointAgentConfig             EndpointID = "agent_config"
	EndpointAgentDecommissionStatus EndpointID = "agent_decommission_status"
	EndpointMandatoryInstallStatus  EndpointID = "mandatory_install_status"
	EndpointPendingRemovals         EndpointID = "pending_removals"
	EndpointPendingInstalls         EndpointID = "pending_installs"
	EndpointPosture                 EndpointID = "posture"
	EndpointAgentLogs               EndpointID = "agent_logs"
	EndpointAgentArtifact           EndpointID = "agent_artifact"
	// EndpointAgentArtifactDownload is GET /v1/agent/artifact/download
	// (PAT-1260): the actual artifact-bytes download that follows the
	// EndpointAgentArtifact metadata fetch, once patched-api-01 starts
	// serving the MSI/tarball itself instead of a GitHub Releases URL a
	// device can't reach (the updater repo is private — 404 unauthenticated).
	// Deliberately its own ID, not a reuse of EndpointAgentArtifact: endpoint
	// binding in the v3 signing input is what stops a signature captured for
	// the metadata GET from being replayed against the byte download, or
	// vice versa. Windows HmacSigner and the macOS agent sign this identical
	// literal string.
	EndpointAgentArtifactDownload     EndpointID = "agent_artifact_download"
	EndpointEnforcementAudit          EndpointID = "enforcement_audit"
	EndpointDeviceRemovalTasksPending EndpointID = "device_removal_tasks_pending"
	EndpointDeviceRemovalTasksReport  EndpointID = "device_removal_tasks_report"
	// EndpointDeviceIdentity is GET /v1/device/identity (PAT-2424). The
	// Windows agent signs this same literal (HmacSigner.EndpointDeviceIdentity).
	EndpointDeviceIdentity EndpointID = "device_identity"
)

// AllowTargetlessV2HMAC gates whether VerifyHMACSigned accepts the PAT-1136
// targetless v2 form after a v3 mismatch. It defaults true so a server-first
// PAT-1154 rollout preserves already-installed agents. Disable it only after
// telemetry confirms every agent sends v3.
var AllowTargetlessV2HMAC = true

// VerifyHMAC computes HMAC-SHA256(body, secret) and constant-time-compares
// against the hex-decoded signatureHeader.
//
// Caller is expected to pass the entire raw request body (not a parsed JSON
// representation) so we hash exactly what the client signed.
//
// This is the legacy body-only primitive (PAT-1136): it does not bind
// timestamp or nonce into the signature, so a captured signed body can be
// replayed with fresh replay headers. VerifyHMACSigned is the primitive
// agent-auth call sites should use; this function remains only as a
// historical primitive for non-agent uses; signed agent verification never
// delegates to it.
func VerifyHMAC(secret, body []byte, signatureHeader string) error {
	if signatureHeader == "" {
		return ErrMissingSignature
	}
	expected, err := hex.DecodeString(signatureHeader)
	if err != nil {
		return ErrMalformedSignature
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	computed := mac.Sum(nil)

	if !hmac.Equal(expected, computed) {
		return ErrInvalidSignature
	}
	return nil
}

// VerifyHMACSigned verifies the PAT-1154 v3 signature, which binds
// HTTP method + stable endpoint ID + timestamp + nonce + body into the HMAC
// so a captured signed request cannot be replayed, moved between operations,
// or replayed with a fresh timestamp/nonce pair.
//
// signing_input = "patched-hmac-v3\n" + method + "\n" + endpointID + "\n" + ts + "\n" + nonce + "\n" + body
//
// ts and nonce must be the exact, verbatim header string values (the same
// ones passed to ValidateTimestamp / CheckAndStoreNonce) — never reparsed or
// reformatted. See contracts/agent-config-schema.md for the full contract
// and authoritative test vectors.
//
// During the explicit transition window, verification fails closed in this
// order: v3, then targetless PAT-1136 v2 when AllowTargetlessV2HMAC is true.
// Targetless v2 binds timestamp and nonce, but does not bind method or endpoint
// ID. Body-only signatures are never accepted because they omit replay headers.
func VerifyHMACSigned(secret []byte, method string, endpointID EndpointID, ts, nonce string, body []byte, signatureHeader string) error {
	_, err := VerifyHMACSignedWithForm(secret, method, endpointID, ts, nonce, body, signatureHeader)
	return err
}

// VerifyHMACSignedWithForm has exactly the same acceptance behaviour as
// VerifyHMACSigned and additionally reports which accepted compatibility form
// matched. The returned form is metadata only: callers must never use it to
// make an authentication decision. On every rejection the form is Unknown.
//
// Keeping VerifyHMACSigned as a thin delegate lets existing call sites retain
// their byte-for-byte API while the inventory path records compatibility
// evidence after the request has otherwise been accepted.
func VerifyHMACSignedWithForm(secret []byte, method string, endpointID EndpointID, ts, nonce string, body []byte, signatureHeader string) (HMACSigningForm, error) {
	if signatureHeader == "" {
		return HMACSigningFormUnknown, ErrMissingSignature
	}
	expected, err := hex.DecodeString(signatureHeader)
	if err != nil {
		return HMACSigningFormUnknown, ErrMalformedSignature
	}

	if hmac.Equal(expected, signedHMAC(secret, hmacDomainV3, method, endpointID, ts, nonce, body)) {
		return HMACSigningFormV3, nil
	}
	if AllowTargetlessV2HMAC && hmac.Equal(expected, targetlessV2HMAC(secret, ts, nonce, body)) {
		return HMACSigningFormTargetlessV2, nil
	}

	return HMACSigningFormUnknown, ErrInvalidSignature
}

// VerifyHMACSignedStrict accepts only the v3 form that binds method, endpoint
// id, timestamp, nonce and body. It deliberately ignores the package-wide v2
// transition flag. New security-sensitive routes must use this
// instead of inheriting compatibility intended for already-installed agents.
func VerifyHMACSignedStrict(secret []byte, method string, endpointID EndpointID, ts, nonce string, body []byte, signatureHeader string) error {
	if signatureHeader == "" {
		return ErrMissingSignature
	}
	expected, err := hex.DecodeString(signatureHeader)
	if err != nil {
		return ErrMalformedSignature
	}
	if !hmac.Equal(expected, signedHMAC(secret, hmacDomainV3, method, endpointID, ts, nonce, body)) {
		return ErrInvalidSignature
	}
	return nil
}

func signedHMAC(secret []byte, domain, method string, endpointID EndpointID, ts, nonce string, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(domain))
	mac.Write([]byte(method))
	mac.Write([]byte("\n"))
	mac.Write([]byte(endpointID))
	mac.Write([]byte("\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return mac.Sum(nil)
}

func targetlessV2HMAC(secret []byte, ts, nonce string, body []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(hmacDomainV2))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write([]byte(nonce))
	mac.Write([]byte("\n"))
	mac.Write(body)
	return mac.Sum(nil)
}
