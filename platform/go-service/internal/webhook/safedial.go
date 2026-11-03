package webhook

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

// SSRF hardening for outbound webhook delivery (PAT-134).
//
// Webhook URLs are tenant-supplied. Without controls, a tenant could point one
// at an internal address — cloud metadata (169.254.169.254), the loopback admin
// listener (127.0.0.1:8081/admin), or a Tailscale peer (100.64.0.0/10) — and
// use our egress as an SSRF pivot. We defend at three layers:
//
//  1. ValidateDestination — reject non-https and literal-internal-IP URLs at
//     config time (fast feedback; not authoritative — DNS can rebind).
//  2. safeControl on the dialer — runs AFTER DNS resolution, on the concrete IP
//     about to be dialed, so it defeats DNS-rebinding. This is authoritative and
//     covers every delivery path (Fire, FireDirect, retries, test-ping).
//  3. CheckRedirect — redirects are not followed, so a 3xx to an internal
//     address can't bypass (1)/(2) either.

// ErrBlockedDestination is returned when a webhook target resolves to an address
// we refuse to connect to.
var ErrBlockedDestination = errors.New("webhook: destination address is not permitted")

// isBlockedIP reports whether ip is in a range we refuse to POST to: loopback,
// RFC1918 / ULA private, link-local (incl. 169.254.169.254 metadata),
// unspecified, multicast, and the 100.64.0.0/10 CGNAT range used by the
// Tailscale admin tailnet.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	// CGNAT 100.64.0.0/10 — Tailscale addresses (not covered by IsPrivate).
	if ip4 := ip.To4(); ip4 != nil && ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127 {
		return true
	}
	return false
}

// safeControl is the net.Dialer.Control hook. It receives the resolved ip:port
// immediately before the TCP connection is made, so validating here catches
// DNS rebinding that a config-time check would miss.
func safeControl(_ /*network*/ string, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("%w: unresolved host %q", ErrBlockedDestination, host)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
	}
	return nil
}

// ValidateDestination performs the config-time check: the URL must be https and
// must not be a literal internal IP. Hostnames are allowed through here (the
// dialer's safeControl enforces the IP policy authoritatively at connect time).
func ValidateDestination(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("url must use https://")
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("url has no host")
	}
	if ip := net.ParseIP(host); ip != nil && isBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedDestination, ip)
	}
	return nil
}

// httpClient is the hardened outbound HTTP client used for ALL webhook
// delivery. No global timeout — timeout is enforced per-request via context.
// The dialer's Control hook blocks internal destinations (SSRF), and redirects
// are not followed so a 3xx cannot escape that policy.
var httpClient = &http.Client{
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   safeControl,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return fmt.Errorf("%w: redirects are not followed", ErrBlockedDestination)
	},
}
