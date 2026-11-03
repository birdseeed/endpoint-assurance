package oscve

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
)

// appleIncRootCAPEM is Apple's official Apple Root CA converted from DER to PEM.
// Source: https://www.apple.com/appleca/AppleIncRootCertificate.cer
// Subject/issuer CN: Apple Root CA
// Valid through: 2035-02-09 21:40:36 UTC
// SHA-256: B0:B1:73:0E:CB:C7:FF:45:05:14:2C:49:F1:29:5E:6E:DA:6B:CA:ED:7E:2C:68:C5:BE:91:B5:A1:10:01:F0:24
//
//go:embed apple_inc_root_ca.pem
var appleIncRootCAPEM []byte

const appleIncRootCASHA256 = "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"

func newGDMFHTTPClient(base *http.Client) (*http.Client, error) {
	return newHTTPClientWithPinnedAdditionalRoot(base, appleIncRootCAPEM, appleIncRootCASHA256)
}

// newHTTPClientWithPinnedAdditionalRoot clones an ordinary net/http client and
// transport, retaining proxy/dial/test overrides, then adds one fingerprint-
// pinned CA to the system pool. Standard chain and hostname verification remain
// enabled; this function never installs a custom verifier or InsecureSkipVerify.
func newHTTPClientWithPinnedAdditionalRoot(base *http.Client, rootPEM []byte, expectedSHA256 string) (*http.Client, error) {
	if base == nil {
		return nil, fmt.Errorf("GDMF HTTP client is nil")
	}
	block, rest := pem.Decode(rootPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("parse pinned Apple root PEM: expected exactly one certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pinned Apple root certificate: %w", err)
	}
	expectedFingerprint, err := hex.DecodeString(expectedSHA256)
	if err != nil || len(expectedFingerprint) != sha256.Size {
		return nil, fmt.Errorf("parse pinned Apple root SHA-256 fingerprint")
	}
	actualFingerprint := sha256.Sum256(certificate.Raw)
	if subtle.ConstantTimeCompare(actualFingerprint[:], expectedFingerprint) != 1 {
		return nil, fmt.Errorf("pinned Apple root SHA-256 fingerprint mismatch")
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid || certificate.Subject.String() != certificate.Issuer.String() {
		return nil, fmt.Errorf("pinned Apple root is not a valid root CA")
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate pool: %w", err)
	}
	if roots == nil {
		return nil, fmt.Errorf("load system certificate pool: empty pool")
	}
	roots.AddCert(certificate)

	var transport *http.Transport
	switch configured := base.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, fmt.Errorf("GDMF HTTP client transport %T cannot be safely cloned with scoped TLS roots", base.Transport)
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("GDMF HTTP client refuses InsecureSkipVerify")
	}
	transport.TLSClientConfig.RootCAs = roots

	client := *base
	client.Transport = transport
	configuredRedirectPolicy := base.CheckRedirect
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if !bytes.EqualFold([]byte(request.URL.Scheme), []byte("https")) || !bytes.EqualFold([]byte(request.URL.Hostname()), []byte("gdmf.apple.com")) {
			return fmt.Errorf("GDMF client refuses redirect to %s", request.URL.Redacted())
		}
		if configuredRedirectPolicy != nil {
			return configuredRedirectPolicy(request, via)
		}
		if len(via) >= 10 {
			return fmt.Errorf("GDMF client stopped after 10 redirects")
		}
		return nil
	}
	return &client, nil
}
