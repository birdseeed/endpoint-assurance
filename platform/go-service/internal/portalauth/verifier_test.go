package portalauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// --- test JWKS infrastructure ------------------------------------------------

type testIdP struct {
	key      *rsa.PrivateKey
	kid      string
	issuer   string
	audience string
	server   *httptest.Server
	verifier *Verifier
}

// newTestIdP generates an RSA key, serves it as a CF-style JWKS from an
// httptest server, and builds a Verifier pointed at it.
func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	idp := &testIdP{
		key:      key,
		kid:      "test-key-1",
		issuer:   "https://testteam.cloudflareaccess.com",
		audience: "aud-tag-0123456789abcdef",
	}
	idp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kid": idp.kid,
				"kty": "RSA",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		})
	}))
	t.Cleanup(idp.server.Close)
	idp.verifier = New(idp.issuer, idp.audience, idp.server.URL)
	return idp
}

type tokenOpts struct {
	iss   string
	aud   string
	email string
	exp   time.Time
	nbf   time.Time
	kid   string
	key   *rsa.PrivateKey
	alg   jwt.SigningMethod
	// commonName sets the service-token common_name claim (PAT-2257).
	commonName string
}

func (idp *testIdP) sign(t *testing.T, o tokenOpts) string {
	t.Helper()
	if o.iss == "" {
		o.iss = idp.issuer
	}
	if o.aud == "" {
		o.aud = idp.audience
	}
	if o.exp.IsZero() {
		o.exp = time.Now().Add(10 * time.Minute)
	}
	if o.kid == "" {
		o.kid = idp.kid
	}
	if o.key == nil {
		o.key = idp.key
	}
	if o.alg == nil {
		o.alg = jwt.SigningMethodRS256
	}
	claims := jwt.MapClaims{
		"iss": o.iss,
		"aud": o.aud,
		"exp": o.exp.Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	if o.email != "" {
		claims["email"] = o.email
	}
	if o.commonName != "" {
		claims["common_name"] = o.commonName
		claims["sub"] = ""
		claims["type"] = "app"
	}
	if !o.nbf.IsZero() {
		claims["nbf"] = o.nbf.Unix()
	}
	tok := jwt.NewWithClaims(o.alg, claims)
	tok.Header["kid"] = o.kid
	signed, err := tok.SignedString(o.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// --- tests ---------------------------------------------------------------------

func TestVerifyValidToken(t *testing.T) {
	idp := newTestIdP(t)
	email, err := idp.verifier.Verify(idp.sign(t, tokenOpts{email: "User@Customer.example"}))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if email != "user@customer.example" {
		t.Errorf("email = %q, want lowercased user@customer.example", email)
	}
}

func TestVerifyRejectsBadIssuer(t *testing.T) {
	idp := newTestIdP(t)
	_, err := idp.verifier.Verify(idp.sign(t, tokenOpts{
		iss: "https://evilteam.cloudflareaccess.com", email: "a@b.c",
	}))
	if err == nil {
		t.Fatal("expected error for wrong issuer")
	}
}

func TestVerifyRejectsBadAudience(t *testing.T) {
	idp := newTestIdP(t)
	_, err := idp.verifier.Verify(idp.sign(t, tokenOpts{
		aud: "some-other-application-aud", email: "a@b.c",
	}))
	if err == nil {
		t.Fatal("expected error for wrong audience")
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	idp := newTestIdP(t)
	_, err := idp.verifier.Verify(idp.sign(t, tokenOpts{
		exp: time.Now().Add(-time.Minute), email: "a@b.c",
	}))
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyRejectsNotYetValidToken(t *testing.T) {
	idp := newTestIdP(t)
	_, err := idp.verifier.Verify(idp.sign(t, tokenOpts{
		nbf: time.Now().Add(time.Hour), email: "a@b.c",
	}))
	if err == nil {
		t.Fatal("expected error for nbf in the future")
	}
}

func TestVerifyRejectsWrongSignature(t *testing.T) {
	idp := newTestIdP(t)
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Same kid, different private key — signature must not verify.
	_, err = idp.verifier.Verify(idp.sign(t, tokenOpts{key: otherKey, email: "a@b.c"}))
	if err == nil {
		t.Fatal("expected error for wrong signature")
	}
}

func TestVerifyRejectsUnknownKid(t *testing.T) {
	idp := newTestIdP(t)
	_, err := idp.verifier.Verify(idp.sign(t, tokenOpts{kid: "no-such-kid", email: "a@b.c"}))
	if err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestVerifyRejectsMissingEmailClaim(t *testing.T) {
	idp := newTestIdP(t)
	_, err := idp.verifier.Verify(idp.sign(t, tokenOpts{}))
	if !errors.Is(err, ErrNoEmailClaim) {
		t.Fatalf("err = %v, want ErrNoEmailClaim", err)
	}
}

func TestVerifyRejectsEmptyToken(t *testing.T) {
	idp := newTestIdP(t)
	if _, err := idp.verifier.Verify(""); !errors.Is(err, ErrNoToken) {
		t.Fatalf("err = %v, want ErrNoToken", err)
	}
}

func TestVerifyRejectsGarbageToken(t *testing.T) {
	idp := newTestIdP(t)
	if _, err := idp.verifier.Verify("not.a.jwt"); err == nil {
		t.Fatal("expected error for garbage token")
	}
}

func TestVerifyRejectsNoneAlgorithm(t *testing.T) {
	idp := newTestIdP(t)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss":   idp.issuer,
		"aud":   idp.audience,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"email": "a@b.c",
	})
	tok.Header["kid"] = idp.kid
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idp.verifier.Verify(signed); err == nil {
		t.Fatal("expected error for alg=none token")
	}
}

func TestVerifyPicksUpRotatedKeyOnColdCache(t *testing.T) {
	// A verifier that has never fetched must fetch on first use — proving the
	// JWKS is loaded lazily rather than requiring construction-time network.
	idp := newTestIdP(t)
	v := New(idp.issuer, idp.audience, idp.server.URL)
	if _, err := v.Verify(idp.sign(t, tokenOpts{email: "a@b.c"})); err != nil {
		t.Fatalf("cold-cache verify: %v", err)
	}
}

func TestNewFromEnvUnsetFailsClosed(t *testing.T) {
	t.Setenv("PORTAL_ACCESS_TEAM_DOMAIN", "")
	t.Setenv("PORTAL_ACCESS_AUD", "")
	v, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}
	if v != nil {
		t.Fatal("expected nil verifier when env unset")
	}
}

func TestNewFromEnvDerivesIssuer(t *testing.T) {
	t.Setenv("PORTAL_ACCESS_TEAM_DOMAIN", "patchedim")
	t.Setenv("PORTAL_ACCESS_AUD", "aud123")
	v, err := NewFromEnv()
	if err != nil || v == nil {
		t.Fatalf("NewFromEnv: v=%v err=%v", v, err)
	}
	if v.issuer != "https://example-team.cloudflareaccess.com" {
		t.Errorf("issuer = %q", v.issuer)
	}
	if v.certsURL != "https://example-team.cloudflareaccess.com/cdn-cgi/access/certs" {
		t.Errorf("certsURL = %q", v.certsURL)
	}
}
