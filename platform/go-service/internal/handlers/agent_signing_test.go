package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// agentV3TestSignature signs the exact operation and replay headers sent by
// agent request fixtures. Body-only signatures must not authenticate agents.
func agentV3TestSignature(secret []byte, method, endpoint, ts, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("patched-hmac-v3\n" + method + "\n" + endpoint + "\n" + ts + "\n" + nonce + "\n"))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestAgentV3TestSignature_AuthoritativeVector(t *testing.T) {
	got := agentV3TestSignature([]byte("patched-test-secret"), "POST", "inventory", "1730000000", "abc123nonce", []byte(`{"hello":"world"}`))
	const want = "e4825ff7d3d56103fb9904615eebb2a317cef582256f066a443bc66974cd75d4"
	if got != want {
		t.Fatalf("v3 fixture signature = %q, want authoritative vector %q", got, want)
	}
}
