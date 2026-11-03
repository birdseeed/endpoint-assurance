package webhook

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",       // loopback
		"::1",             // loopback v6
		"10.1.2.3",        // RFC1918
		"172.16.5.6",      // RFC1918
		"192.168.1.1",     // RFC1918
		"169.254.169.254", // link-local / cloud metadata
		"100.64.0.1",      // CGNAT / Tailscale
		"100.100.100.100", // CGNAT / Tailscale
		"0.0.0.0",         // unspecified
		"fe80::1",         // link-local v6
		"fc00::1",         // ULA (private v6)
		"224.0.0.1",       // multicast
	}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be blocked", s)
		}
	}

	allowed := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34", // example.com
		"2606:2800:220:1:248:1893:25c8:1946",
	}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be allowed", s)
		}
	}

	// nil (unresolvable) must be blocked.
	if !isBlockedIP(nil) {
		t.Error("nil IP must be blocked")
	}
}

func TestValidateDestination(t *testing.T) {
	bad := []string{
		"http://example.com/hook",      // not https
		"ftp://example.com",            // wrong scheme
		"https://127.0.0.1/hook",       // literal loopback
		"https://169.254.169.254/meta", // metadata
		"https://100.64.0.1/x",         // tailnet CGNAT
		"https://[::1]/x",              // loopback v6
		"https://",                     // no host
		"::not a url",                  // unparseable
	}
	for _, s := range bad {
		if err := ValidateDestination(s); err == nil {
			t.Errorf("expected %q to be rejected", s)
		}
	}

	good := []string{
		"https://example.com/hook",
		"https://hooks.slack.com/services/T/B/xxx",
		"https://8.8.8.8/ok", // public literal IP is allowed
	}
	for _, s := range good {
		if err := ValidateDestination(s); err != nil {
			t.Errorf("expected %q to be accepted, got %v", s, err)
		}
	}
}
