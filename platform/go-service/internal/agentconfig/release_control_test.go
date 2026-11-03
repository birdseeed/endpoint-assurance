package agentconfig

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDeviceChannelOverridesAreSigned(t *testing.T) {
	key := testKey(t)
	body := DefaultConfigBody()
	body.DeviceChannelOverrides = map[string]string{"00000000-0000-0000-0000-000000000002": "beta", "00000000-0000-0000-0000-000000000001": "beta"}
	body.UpdateChannelSource = ""
	sig, _, raw, err := Sign(key, body, 2, "2026-09-27T00:00:00Z", "tenant", "", 3, AppControlPolicy{}, DecommissionPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public, raw, decoded) {
		t.Fatal("signature invalid")
	}
	if !bytes.Contains(raw, []byte(`"device_channel_overrides":{"00000000-0000-0000-0000-000000000001":"beta","00000000-0000-0000-0000-000000000002":"beta"},"device_id"`)) {
		t.Fatalf("canonical ordering %s", raw)
	}
	altered := bytes.Replace(raw, []byte(`":"beta"`), []byte(`":"stable"`), 1)
	if ed25519.Verify(key.Public, altered, decoded) {
		t.Fatal("changed override verified")
	}
	stored, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("device_channel_overrides")) {
		t.Fatal("response-only map persisted")
	}
}

func TestUpdateChannelSourceIsOptionalAndSigned(t *testing.T) {
	key := testKey(t)
	for _, tc := range []struct {
		name, source string
		want         string
	}{
		{"tenant-wide", "", `"update_channel_source"`},
		{"tenant-device", "tenant", `"update_channel_source":"tenant"`},
		{"override-device", "device_override", `"update_channel_source":"device_override"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := DefaultConfigBody()
			body.UpdateChannelSource = tc.source
			sig, _, raw, err := Sign(key, body, 2, "2026-09-27T00:00:00Z", "tenant", "device", 3, AppControlPolicy{}, DecommissionPolicy{})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(raw, []byte(tc.want)) != (tc.source != "") {
				t.Fatalf("unexpected signed source: %s", raw)
			}
			decoded, _ := base64.StdEncoding.DecodeString(sig)
			if !ed25519.Verify(key.Public, raw, decoded) {
				t.Fatal("signature invalid")
			}
			stored, _ := json.Marshal(body)
			if bytes.Contains(stored, []byte("update_channel_source")) {
				t.Fatal("response-only source persisted")
			}
		})
	}
}
