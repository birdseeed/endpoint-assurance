package oscve

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type testTLSAuthority struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	pem         []byte
	fingerprint string
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newTestTLSAuthority(t *testing.T, commonName string) testTLSAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test CA: %v", err)
	}
	certificate, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("parse test CA: %v", err)
	}
	fingerprint := sha256.Sum256(raw)
	return testTLSAuthority{
		certificate: certificate,
		privateKey:  key,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}),
		fingerprint: hex.EncodeToString(fingerprint[:]),
	}
}

func newTestTLSServer(t *testing.T, authority testTLSAuthority, hostname string) (*httptest.Server, *http.Client, string) {
	t.Helper()
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, authority.certificate, &serverKey.PublicKey, authority.privateKey)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	serverCertificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})
	serverKeyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	serverPrivateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverKeyDER})
	tlsCertificate, err := tls.X509KeyPair(serverCertificate, serverPrivateKey)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCertificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	serverAddress := server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, serverAddress)
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	port := strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)
	return server, client, "https://" + hostname + ":" + port
}

func TestGDMFScopedTrustRequiresAddedRootAndCorrectHostname(t *testing.T) {
	authority := newTestTLSAuthority(t, "Apple Root CA Test")
	_, baseClient, endpoint := newTestTLSServer(t, authority, "gdmf.apple.com")

	if _, err := baseClient.Get(endpoint); err == nil {
		t.Fatal("default system roots unexpectedly trusted the test Apple chain")
	}
	scopedClient, err := newHTTPClientWithPinnedAdditionalRoot(baseClient, authority.pem, authority.fingerprint)
	if err != nil {
		t.Fatalf("construct scoped client: %v", err)
	}
	response, err := scopedClient.Get(endpoint)
	if err != nil {
		t.Fatalf("scoped client rejected correct hostname and chain: %v", err)
	}
	response.Body.Close()

	wrongHostname := "https://wrong.example:" + response.Request.URL.Port()
	if _, err := scopedClient.Get(wrongHostname); err == nil {
		t.Fatal("scoped client accepted a certificate for the wrong hostname")
	}
}

func TestGDMFScopedTrustRejectsUntrustedChain(t *testing.T) {
	trustedAuthority := newTestTLSAuthority(t, "Apple Root CA Test")
	untrustedAuthority := newTestTLSAuthority(t, "Untrusted Root CA Test")
	_, baseClient, endpoint := newTestTLSServer(t, untrustedAuthority, "gdmf.apple.com")
	scopedClient, err := newHTTPClientWithPinnedAdditionalRoot(baseClient, trustedAuthority.pem, trustedAuthority.fingerprint)
	if err != nil {
		t.Fatalf("construct scoped client: %v", err)
	}
	if _, err := scopedClient.Get(endpoint); err == nil {
		t.Fatal("scoped client accepted a chain under an unrelated root")
	}
}

func TestGDMFEmbeddedRootFingerprintIsFailClosed(t *testing.T) {
	client, err := newGDMFHTTPClient(&http.Client{Timeout: time.Second})
	if err != nil {
		t.Fatalf("embedded Apple root rejected: %v", err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("GDMF client disabled normal TLS verification")
	}
	if _, err := newHTTPClientWithPinnedAdditionalRoot(&http.Client{}, appleIncRootCAPEM, "00"+appleIncRootCASHA256[2:]); err == nil {
		t.Fatal("changed Apple root fingerprint was accepted")
	}
	insecureBase := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec -- deliberate rejection test
	if _, err := newGDMFHTTPClient(insecureBase); err == nil {
		t.Fatal("inherited InsecureSkipVerify was accepted")
	}
	redirectURL, err := url.Parse("https://example.invalid/redirect")
	if err != nil {
		t.Fatalf("parse redirect URL: %v", err)
	}
	if err := client.CheckRedirect(&http.Request{URL: redirectURL}, nil); err == nil {
		t.Fatal("GDMF client allowed its scoped trust onto a redirected hostname")
	}
}

func TestFetchGDMFPreservesHTTPFixtureOverride(t *testing.T) {
	originalClient := httpClient
	t.Cleanup(func() { httpClient = originalClient })
	called := false
	httpClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		called = true
		if request.Header.Get("Accept") != "application/json" {
			t.Fatalf("Accept = %q", request.Header.Get("Accept"))
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"fixture":true}`)),
			Request:    request,
		}, nil
	})}
	body, err := fetchGDMF(context.Background(), "http://fixture.invalid/gdmf")
	if err != nil {
		t.Fatalf("fetch HTTP fixture override: %v", err)
	}
	if !called || string(body) != `{"fixture":true}` {
		t.Fatalf("fixture override not preserved: called=%v body=%s", called, body)
	}
}
