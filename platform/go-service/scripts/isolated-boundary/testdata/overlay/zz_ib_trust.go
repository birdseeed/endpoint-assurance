package main

// Build-time overlay used only by the isolated boundary harness (never part of
// the repository build). The platform verifies Access JWTs against
// https://<team>/cdn-cgi/access/certs and darwin ignores SSL_CERT_FILE, so the
// harness's throwaway CA must be trusted for the process's outbound HTTPS. The
// pool holds ONLY that CA: the binary under test trusts the local issuer and
// nothing else. No product source file is changed.

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
)

func init() {
	path := os.Getenv("IB_EXTRA_CA_FILE")
	if path == "" {
		return
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		panic("IB_EXTRA_CA_FILE unreadable: " + err.Error())
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		panic("IB_EXTRA_CA_FILE holds no certificate")
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	http.DefaultTransport = t
}
