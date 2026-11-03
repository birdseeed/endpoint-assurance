// Package portalauth authenticates customer-portal requests on the PUBLIC
// listener (PAT-693, auth model locked in PAT-330).
//
// Trust chain:
//
//  1. Cloudflare Access fronts app.patched.im and asserts the visitor's
//     identity in a Cf-Access-Jwt-Assertion header (RS256 JWT).
//  2. This package validates that JWT against the team's JWKS
//     (https://<team>.cloudflareaccess.com/cdn-cgi/access/certs): signature,
//     issuer, audience, exp, nbf. Any failure → reject (fail closed, 401).
//  3. The verified email claim — and ONLY that — maps to a tenant via the
//     portal_users table. No client-supplied tenant identifier exists
//     anywhere on the portal surface.
//
// If PORTAL_ACCESS_TEAM_DOMAIN / PORTAL_ACCESS_AUD are unset the portal
// surface fails CLOSED with 503 (same posture as ADMIN_API_TOKEN on the
// internal listener).
package portalauth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verification failure modes. All map to 401 at the HTTP layer; the split
// exists so logs and tests can tell them apart.
var (
	ErrNoToken       = errors.New("missing Cf-Access-Jwt-Assertion")
	ErrInvalidToken  = errors.New("invalid access token")
	ErrUnknownKeyID  = errors.New("token signed by unknown key")
	ErrNoEmailClaim  = errors.New("token has no email claim")
	ErrNotConfigured = errors.New("portal access auth not configured")
)

// jwksMinRefreshInterval rate-limits forced JWKS refreshes triggered by
// unknown kids, so a flood of garbage tokens can't hammer the certs endpoint.
const jwksMinRefreshInterval = time.Minute

// jwksTTL is how long a fetched key set is trusted before a background-free,
// on-demand refetch. Cloudflare rotates Access signing keys ~every 6 weeks;
// 1h keeps rotation lag negligible without meaningful load.
const jwksTTL = time.Hour

// Verifier validates Cloudflare Access JWTs against a cached JWKS.
type Verifier struct {
	issuer   string // https://<team>.cloudflareaccess.com
	audience string // Access application AUD tag
	certsURL string // <issuer>/cdn-cgi/access/certs
	client   *http.Client

	// service is the allowlisted read-only service identity (PAT-2257),
	// nil when the feature is off. Set once at startup via WithService.
	service *ServiceIdentity

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey // kid → key
	fetchedAt   time.Time
	lastAttempt time.Time
}

// NewFromEnv builds a Verifier from PORTAL_ACCESS_TEAM_DOMAIN and
// PORTAL_ACCESS_AUD. Returns (nil, nil) when either is unset — the caller
// must treat a nil Verifier as "feature not configured" and fail closed.
func NewFromEnv() (*Verifier, error) {
	team := strings.TrimSpace(os.Getenv("PORTAL_ACCESS_TEAM_DOMAIN"))
	aud := strings.TrimSpace(os.Getenv("PORTAL_ACCESS_AUD"))
	if team == "" || aud == "" {
		return nil, nil
	}
	// Accept either the bare team name ("patchedim") or the full domain
	// ("example-team.cloudflareaccess.com").
	if !strings.Contains(team, ".") {
		team += ".cloudflareaccess.com"
	}
	issuer := "https://" + team
	return New(issuer, aud, issuer+"/cdn-cgi/access/certs"), nil
}

// New builds a Verifier with explicit issuer, audience, and certs URL.
// Split out from NewFromEnv so tests can point certsURL at an httptest JWKS.
func New(issuer, audience, certsURL string) *Verifier {
	return &Verifier{
		issuer:   issuer,
		audience: audience,
		certsURL: certsURL,
		client:   &http.Client{Timeout: 10 * time.Second},
		keys:     map[string]*rsa.PublicKey{},
	}
}

// accessClaims is the subset of the CF Access identity JWT we consume.
type accessClaims struct {
	Email string `json:"email"`
	// CommonName is set on a service-token JWT (the token's client id);
	// such a token carries no email (PAT-2257).
	CommonName string `json:"common_name"`
	jwt.RegisteredClaims
}

// Principal is the verified subject of an Access JWT: a person (Email set)
// or, only for an email-less token, a service token (CommonName set).
type Principal struct {
	Email      string
	CommonName string
}

// Verify validates the raw JWT and returns the asserted email address.
// Every validation failure returns a non-nil error — never a partial result.
// A service-token JWT (no email) is ErrNoEmailClaim here; the middleware
// uses VerifyPrincipal, which applies the same validation.
func (v *Verifier) Verify(raw string) (string, error) {
	p, err := v.VerifyPrincipal(raw)
	if err != nil {
		return "", err
	}
	if p.Email == "" {
		return "", ErrNoEmailClaim
	}
	return p.Email, nil
}

// VerifyPrincipal validates the raw JWT exactly as Verify always has
// (signature against the JWKS, RS256 only, issuer, audience, exp, nbf) and
// returns who it asserts. An email wins: a token with one is a person's.
// Only an email-less token yields a CommonName, and only when the claim is
// non-empty; whether that common name is allowlisted is the middleware's
// decision (Verifier.serviceFor), not this function's.
func (v *Verifier) VerifyPrincipal(raw string) (Principal, error) {
	if raw == "" {
		return Principal{}, ErrNoToken
	}

	claims := &accessClaims{}
	token, err := jwt.ParseWithClaims(raw, claims, v.keyFor,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpirationRequired(),
		// exp and nbf are checked (with zero leeway) by the library defaults.
	)
	if err != nil {
		if errors.Is(err, ErrUnknownKeyID) {
			return Principal{}, ErrUnknownKeyID
		}
		return Principal{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid {
		return Principal{}, ErrInvalidToken
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email != "" {
		return Principal{Email: email}, nil
	}
	if claims.CommonName != "" {
		return Principal{CommonName: claims.CommonName}, nil
	}
	return Principal{}, ErrNoEmailClaim
}

// keyFor is the jwt.Keyfunc: resolve the token's kid against the cached JWKS,
// force-refreshing (rate-limited) when the kid is unknown — that is exactly
// what a legitimate key rotation looks like.
func (v *Verifier) keyFor(token *jwt.Token) (any, error) {
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, ErrUnknownKeyID
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if key, ok := v.keys[kid]; ok && time.Since(v.fetchedAt) < jwksTTL {
		return key, nil
	}
	if time.Since(v.lastAttempt) >= jwksMinRefreshInterval || v.fetchedAt.IsZero() {
		v.lastAttempt = time.Now()
		if err := v.refreshLocked(); err != nil {
			// Keep serving previously-fetched keys if the refresh failed and
			// we still have a match; otherwise surface the failure.
			if key, ok := v.keys[kid]; ok {
				return key, nil
			}
			return nil, fmt.Errorf("jwks refresh: %w", err)
		}
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, ErrUnknownKeyID
}

// jwk is one RSA key from the /cdn-cgi/access/certs response.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// refreshLocked fetches the JWKS. Caller must hold v.mu.
func (v *Verifier) refreshLocked() error {
	resp, err := v.client.Get(v.certsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("certs endpoint returned %d", resp.StatusCode)
	}

	var body struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("decode jwks: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(body.Keys))
	for _, k := range body.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := rsaKeyFromJWK(k)
		if err != nil {
			continue // skip malformed entries; don't fail the whole set
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return errors.New("jwks contained no usable RSA keys")
	}
	v.keys = keys
	v.fetchedAt = time.Now()
	return nil
}

func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 1 {
		return nil, errors.New("invalid exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}
