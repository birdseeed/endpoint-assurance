package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCertificateExpiryBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 500000000, time.UTC)
	for _, tc := range []struct {
		delta  time.Duration
		want   int
		status string
	}{
		{-time.Nanosecond, -1, "expired"}, {0, 0, "critical"}, {8*24*time.Hour - time.Nanosecond, 7, "critical"},
		{8 * 24 * time.Hour, 8, "warning"}, {31*24*time.Hour - time.Nanosecond, 30, "warning"}, {31 * 24 * time.Hour, 31, "healthy"},
	} {
		got, status := certificateExpiry(now.Add(tc.delta), now)
		if got == nil || *got != tc.want || status != tc.status {
			t.Errorf("%v = %v/%s, want %d/%s", tc.delta, got, status, tc.want, tc.status)
		}
	}
	if days, status := certificateExpiry(time.Time{}, now); days != nil || status != "unknown" {
		t.Fatal("missing date must be unknown")
	}
	far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	if days, status := certificateExpiry(far, now); days == nil || *days < 2000000 || status != "healthy" {
		t.Fatal("distant dates overflow duration")
	}
}

func TestUploadedCertificateEnvelopeAndClassification(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.example"}, NotBefore: now, NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 2, 3, 4}}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pub := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	for name, raw := range map[string][]byte{
		"prefix":                  append([]byte("untrusted text\n"), pub...),
		"malformed earlier block": append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n"), pub...),
		"extra cert":              append(append([]byte{}, pub...), pub...),
		"PEM headers":             pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Comment": "untrusted"}, Bytes: der}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseUploadedCertificate(raw); err == nil {
				t.Fatal("accepted non-single-certificate input")
			}
		})
	}
	got, err := parseUploadedCertificate(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CA || !got.SelfSigned || len(got.EKU) != 2 || got.EKU[0] != "1.3.6.1.5.5.7.3.1" || got.EKU[1] != "1.2.3.4" {
		t.Fatalf("classification metadata missing: %+v", got)
	}
	// Same issuer name is insufficient evidence that the signature is self-signed.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err = x509.CreateCertificate(rand.Reader, template, template, &other.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err = parseUploadedCertificate(der)
	if err != nil || got.SelfSigned {
		t.Fatalf("issuer name mistaken for verified self-signature: %v %+v", err, got)
	}
}
