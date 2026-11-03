package msgraph

import (
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // required: Entra's x5t header is defined as a SHA-1 thumbprint, not a choice of ours.
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"
)

// Certificate is the org's single Entra app-registration certificate, used
// to sign client assertions for every tenant. It is not per-tenant and it
// is not a secret store keyed by customer — one value, held once, passed to
// NewTokenSource.
type Certificate struct {
	cert       *x509.Certificate
	privateKey *rsa.PrivateKey
	thumbprint string
}

// NewCertificate wraps an already-parsed certificate and RSA private key,
// precomputing the base64url SHA-1 thumbprint Entra expects in the client
// assertion's x5t header.
func NewCertificate(cert *x509.Certificate, key *rsa.PrivateKey) *Certificate {
	sum := sha1.Sum(cert.Raw) //nolint:gosec // see import comment
	return &Certificate{
		cert:       cert,
		privateKey: key,
		thumbprint: base64.RawURLEncoding.EncodeToString(sum[:]),
	}
}

// LoadCertificatePEM parses a PEM-encoded certificate and RSA private key
// (PKCS#1 or PKCS#8) into a Certificate. Callers own how the PEM bytes are
// stored/retrieved (e.g. from a filesystem path or secret manager) — this
// package has no opinion on that and never persists key material itself.
func LoadCertificatePEM(certPEM, keyPEM []byte) (*Certificate, error) {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("msgraph: no PEM certificate block found")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("msgraph: parse certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("msgraph: no PEM private key block found")
	}

	key, err := parseRSAPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("msgraph: parse private key: %w", err)
	}

	return NewCertificate(cert, key), nil
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

// Thumbprint returns the base64url-encoded SHA-1 thumbprint of the
// certificate's DER encoding, as required by the client assertion's x5t
// header (RFC 7515 / Entra's client-credential-with-certificate flow).
func (c *Certificate) Thumbprint() string {
	return c.thumbprint
}

// NotAfter returns the certificate's expiry time.
func (c *Certificate) NotAfter() time.Time {
	return c.cert.NotAfter
}

// Expired reports whether the certificate is no longer valid at t. Checking
// this locally lets the token client fail fast with ErrCertificateInvalid
// instead of spending a round trip to Entra to learn the same thing.
func (c *Certificate) Expired(t time.Time) bool {
	return t.After(c.cert.NotAfter)
}
