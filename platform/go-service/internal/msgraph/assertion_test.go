package msgraph

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestBuildClientAssertion_HeaderAndClaims(t *testing.T) {
	cert := generateTestCertificate(t, time.Now().Add(365*24*time.Hour))
	// jwt.ParseWithClaims validates exp/nbf against the real wall clock, so
	// this must be anchored to "now" rather than an arbitrary fixed date.
	now := time.Now().Truncate(time.Second)
	const (
		clientID = "11111111-1111-1111-1111-111111111111"
		audience = "https://login.microsoftonline.com/tenant-a/oauth2/v2.0/token"
	)

	signed, err := buildClientAssertion(cert, clientID, audience, now)
	if err != nil {
		t.Fatalf("buildClientAssertion: %v", err)
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(signed, claims, func(tok *jwt.Token) (interface{}, error) {
		if tok.Method.Alg() != "RS256" {
			t.Fatalf("unexpected signing alg: %s", tok.Method.Alg())
		}
		return &cert.privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse signed assertion: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("assertion did not validate against its own certificate")
	}

	if got := parsed.Header["x5t"]; got != cert.Thumbprint() {
		t.Errorf("x5t header = %v, want %s", got, cert.Thumbprint())
	}
	if got := parsed.Header["alg"]; got != "RS256" {
		t.Errorf("alg header = %v, want RS256", got)
	}

	if got, _ := claims.GetIssuer(); got != clientID {
		t.Errorf("iss = %s, want %s", got, clientID)
	}
	if got, _ := claims.GetSubject(); got != clientID {
		t.Errorf("sub = %s, want %s", got, clientID)
	}
	aud, _ := claims.GetAudience()
	if len(aud) != 1 || aud[0] != audience {
		t.Errorf("aud = %v, want [%s]", aud, audience)
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Error("jti claim missing or empty")
	}

	exp, _ := claims.GetExpirationTime()
	nbf, _ := claims.GetNotBefore()
	if !exp.Time.Equal(now.Add(assertionValidity)) {
		t.Errorf("exp = %v, want %v", exp.Time, now.Add(assertionValidity))
	}
	if !nbf.Time.Equal(now) {
		t.Errorf("nbf = %v, want %v", nbf.Time, now)
	}
}

func TestBuildClientAssertion_UniqueJTIPerCall(t *testing.T) {
	cert := generateTestCertificate(t, time.Now().Add(24*time.Hour))
	now := time.Now()

	a, err := buildClientAssertion(cert, "client-id", "https://example.invalid/token", now)
	if err != nil {
		t.Fatalf("first assertion: %v", err)
	}
	b, err := buildClientAssertion(cert, "client-id", "https://example.invalid/token", now)
	if err != nil {
		t.Fatalf("second assertion: %v", err)
	}
	if a == b {
		t.Error("two assertions built at the same instant must not be byte-identical (jti must differ)")
	}
}
