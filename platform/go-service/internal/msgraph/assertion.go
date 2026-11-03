package msgraph

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// assertionValidity is how long a signed client assertion is valid for.
// Entra requires it be short-lived; 5 minutes is comfortably inside the
// documented 10-minute maximum and matches Microsoft's own MSAL client
// libraries' default.
const assertionValidity = 5 * time.Minute

// buildClientAssertion signs a JWT-bearer client assertion per
// https://learn.microsoft.com/entra/identity-platform/certificate-credentials.
// audience is the full token endpoint URL being called
// (https://login.microsoftonline.com/{tenantID}/oauth2/v2.0/token) — Entra
// requires the assertion's aud claim match the endpoint it's presented to
// exactly, including the tenant id, even though the certificate and client
// id are shared across every tenant.
func buildClientAssertion(cert *Certificate, clientID, audience string, now time.Time) (string, error) {
	jti, err := randomJTI()
	if err != nil {
		return "", fmt.Errorf("msgraph: generate assertion jti: %w", err)
	}

	claims := jwt.RegisteredClaims{
		Issuer:    clientID,
		Subject:   clientID,
		Audience:  jwt.ClaimStrings{audience},
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(assertionValidity)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// x5t (base64url SHA-1 certificate thumbprint) is how Entra identifies
	// which of the app registration's certificates signed this assertion.
	token.Header["x5t"] = cert.Thumbprint()

	signed, err := token.SignedString(cert.privateKey)
	if err != nil {
		return "", fmt.Errorf("msgraph: sign client assertion: %w", err)
	}
	return signed, nil
}

func randomJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
