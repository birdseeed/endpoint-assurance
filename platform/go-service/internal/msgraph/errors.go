package msgraph

import (
	"errors"
	"fmt"
	"time"
)

// Sentinel errors distinguish the operationally-distinct failure modes of
// this integration. Callers (a later reconciliation job) are expected to
// switch on these with errors.Is rather than string-matching, since each
// one implies a different remediation:
//
//   - ErrConsentRequired: a customer admin needs to (re-)grant consent.
//   - ErrTenantNotFound: the configured tenant id is wrong or the tenant
//     was deleted.
//   - ErrCertificateInvalid: our certificate is expired, untrusted, or the
//     signed assertion was otherwise rejected — an us-side problem, not a
//     customer-side one.
//   - ErrPermissionDenied: consent exists but the granted app permissions
//     don't cover the resource being requested.
//   - ErrThrottled: Entra/Graph asked us to back off; see ThrottledError
//     for how long.
var (
	ErrConsentRequired    = errors.New("msgraph: admin consent missing or revoked for this tenant")
	ErrTenantNotFound     = errors.New("msgraph: tenant id not recognised by Entra")
	ErrCertificateInvalid = errors.New("msgraph: certificate expired, untrusted, or assertion rejected")
	ErrPermissionDenied   = errors.New("msgraph: application permission not granted for this resource")
	ErrThrottled          = errors.New("msgraph: request throttled")
)

// aadstsErrorClass maps the numeric AADSTS error codes Entra returns on the
// token endpoint (in the standard OAuth2 error_codes array) to the sentinel
// above they represent. These codes are public Microsoft protocol
// documentation, not anything tenant- or credential-specific.
var aadstsErrorClass = map[int]error{
	// Tenant id wrong / not found / not a valid directory.
	90002:  ErrTenantNotFound,
	900023: ErrTenantNotFound,
	// Consent missing or revoked, or the app registration isn't found in
	// that particular tenant (which for a multi-tenant app means it was
	// never consented into).
	65001:  ErrConsentRequired,
	700016: ErrConsentRequired,
	// Client assertion / certificate rejected: invalid signature, expired
	// or not-yet-valid assertion, thumbprint mismatch.
	700027: ErrCertificateInvalid,
	700024: ErrCertificateInvalid,
	701002: ErrCertificateInvalid,
}

// TokenError wraps a failed token-endpoint response, preserving the raw
// AADSTS code/description for logs while still classifying into one of the
// sentinel errors above so callers can branch on it. Err is nil when the
// response didn't match a known class — callers should still treat that as
// a hard failure, just an unclassified one.
type TokenError struct {
	Code        string // e.g. "invalid_client"
	Description string // full AADSTS description from Entra
	Err         error
}

func (e *TokenError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("msgraph: token request failed (%s): %s: %v", e.Code, e.Description, e.Err)
	}
	return fmt.Sprintf("msgraph: token request failed (%s): %s", e.Code, e.Description)
}

func (e *TokenError) Unwrap() error {
	return e.Err
}

// classifyTokenError inspects the error_codes Entra returned and picks the
// matching sentinel. The first matching code wins; Entra can return several
// but they describe the same underlying condition in practice.
func classifyTokenError(oauthError, description string, codes []int) *TokenError {
	te := &TokenError{Code: oauthError, Description: description}
	for _, c := range codes {
		if cls, ok := aadstsErrorClass[c]; ok {
			te.Err = cls
			return te
		}
	}
	return te
}

// GraphError wraps a failed Graph resource-endpoint response (as opposed to
// a token-endpoint failure — see TokenError). Err is ErrPermissionDenied for
// a 403, otherwise nil (unclassified, still a hard failure).
type GraphError struct {
	Status  int
	Code    string
	Message string
	Err     error
}

func (e *GraphError) Error() string {
	return fmt.Sprintf("msgraph: graph request failed (status %d, code %s): %s", e.Status, e.Code, e.Message)
}

func (e *GraphError) Unwrap() error {
	return e.Err
}

func classifyGraphError(status int, code, message string) *GraphError {
	ge := &GraphError{Status: status, Code: code, Message: message}
	if status == 403 {
		ge.Err = ErrPermissionDenied
	}
	return ge
}

// ThrottledError is returned when Entra or Graph responds 429. RetryAfter is
// the exact duration the server asked us to wait, parsed from the
// Retry-After header (defaultRetryAfter when the header is missing or
// unparsable).
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("msgraph: throttled, retry after %s", e.RetryAfter)
}

func (e *ThrottledError) Unwrap() error {
	return ErrThrottled
}
