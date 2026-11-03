package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"testing"
)

func TestVerifyHMAC_ValidSignature(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"hello":"world"}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	if err := VerifyHMAC(secret, body, hex.EncodeToString(mac.Sum(nil))); err != nil {
		t.Fatalf("VerifyHMAC() = %v, want nil", err)
	}
}

func TestVerifyHMAC_RejectsMissingMalformedAndInvalid(t *testing.T) {
	for _, signature := range []string{"", "not-hex-zz", "00"} {
		if err := VerifyHMAC([]byte("secret"), []byte("body"), signature); err == nil {
			t.Fatalf("VerifyHMAC(%q) = nil, want error", signature)
		}
	}
}

// Authoritative PAT-1154 vectors. secret is literal ASCII, not base64-decoded.
const (
	vecSecret = "patched-test-secret"
	vecTS     = "1730000000"
	vecNonce  = "abc123nonce"
	vecABody  = `{"hello":"world"}`

	// POST inventory, body = {"hello":"world"}.
	vecInventoryV3 = "e4825ff7d3d56103fb9904615eebb2a317cef582256f066a443bc66974cd75d4"
	// GET agent_config, body = empty.
	vecAgentConfigV3           = "868b6e53c5c2ba9cbf72d0af25e06157eed1fff7ca68148412c2dd0952295d3f"
	vecInventoryTargetlessV2   = "f537f9764d38d0cd9b08cb53e451d86b83f25f69b528aaeffcaacd4f4cbfb13e"
	vecAgentConfigTargetlessV2 = "7705fc67c585db5ba3dbc35dbafa587a4d79532dafb68b33d8fcda9f6846e983"
	vecLegacyV1                = "222b3a159945641dd1b04edd3cb18e8feba8b8e619534d9dcb639294f76566cc"
)

func TestVerifyHMACSigned_AuthoritativeVectorsAccepted(t *testing.T) {
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), vecInventoryV3); err != nil {
		t.Fatalf("v3 inventory vector = %v, want nil", err)
	}
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodGet, EndpointAgentConfig, vecTS, vecNonce, nil, vecAgentConfigV3); err != nil {
		t.Fatalf("v3 agent-config vector = %v, want nil", err)
	}
}

func TestVerifyHMACSignedWithForm_ReportsAcceptedBranchWithoutChangingAcceptance(t *testing.T) {
	origTargetlessV2 := AllowTargetlessV2HMAC
	defer func() {
		AllowTargetlessV2HMAC = origTargetlessV2
	}()
	AllowTargetlessV2HMAC = true

	for _, tc := range []struct {
		name      string
		signature string
		wantForm  HMACSigningForm
	}{
		{"v3", vecInventoryV3, HMACSigningFormV3},
		{"targetless v2", vecInventoryTargetlessV2, HMACSigningFormTargetlessV2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form, err := VerifyHMACSignedWithForm([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), tc.signature)
			if err != nil {
				t.Fatalf("VerifyHMACSignedWithForm() = %v, want nil", err)
			}
			if form != tc.wantForm {
				t.Fatalf("form = %q, want %q", form, tc.wantForm)
			}
			if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), tc.signature); err != nil {
				t.Fatalf("existing VerifyHMACSigned() rejected the same input: %v", err)
			}
		})
	}

	form, err := VerifyHMACSignedWithForm([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), "00")
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("invalid signature error = %v, want ErrInvalidSignature", err)
	}
	if form != HMACSigningFormUnknown {
		t.Fatalf("rejected signature form = %q, want Unknown", form)
	}
}

func TestVerifyHMACSignedStrict_AcceptsOnlyExactV3Binding(t *testing.T) {
	secret, body := []byte(vecSecret), []byte(vecABody)
	sig := hex.EncodeToString(signedHMAC(secret, hmacDomainV3, http.MethodPost, EndpointMandatoryInstallStatus, vecTS, vecNonce, body))
	if err := VerifyHMACSignedStrict(secret, http.MethodPost, EndpointMandatoryInstallStatus, vecTS, vecNonce, body, sig); err != nil {
		t.Fatalf("exact strict v3 signature = %v", err)
	}
	for name, tc := range map[string]struct {
		method    string
		endpoint  EndpointID
		ts, nonce string
	}{
		"method":    {http.MethodPut, EndpointMandatoryInstallStatus, vecTS, vecNonce},
		"endpoint":  {http.MethodPost, EndpointEvents, vecTS, vecNonce},
		"timestamp": {http.MethodPost, EndpointMandatoryInstallStatus, "1730000001", vecNonce},
		"nonce":     {http.MethodPost, EndpointMandatoryInstallStatus, vecTS, "other-nonce"},
	} {
		if err := VerifyHMACSignedStrict(secret, tc.method, tc.endpoint, tc.ts, tc.nonce, body, sig); !errors.Is(err, ErrInvalidSignature) {
			t.Errorf("changed %s = %v, want ErrInvalidSignature", name, err)
		}
	}
	legacy := hmac.New(sha256.New, secret)
	legacy.Write(body)
	if err := VerifyHMACSignedStrict(secret, http.MethodPost, EndpointMandatoryInstallStatus, vecTS, vecNonce, body, hex.EncodeToString(legacy.Sum(nil))); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("legacy body-only = %v, want ErrInvalidSignature", err)
	}
	targetless := hex.EncodeToString(targetlessV2HMAC(secret, vecTS, vecNonce, body))
	if err := VerifyHMACSignedStrict(secret, http.MethodPost, EndpointMandatoryInstallStatus, vecTS, vecNonce, body, targetless); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("targetless v2 = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyHMACSigned_TargetlessV2CompatibilityIsExplicit(t *testing.T) {
	origTargetlessV2 := AllowTargetlessV2HMAC
	defer func() {
		AllowTargetlessV2HMAC = origTargetlessV2
	}()

	AllowTargetlessV2HMAC = true
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), vecInventoryTargetlessV2); err != nil {
		t.Fatalf("targetless v2 signature allowed = %v, want nil", err)
	}
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodGet, EndpointAgentConfig, vecTS, vecNonce, nil, vecAgentConfigTargetlessV2); err != nil {
		t.Fatalf("targetless v2 empty-body signature allowed = %v, want nil", err)
	}
	AllowTargetlessV2HMAC = false
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), vecInventoryTargetlessV2); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("targetless v2 signature disabled = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyHMACSigned_BindsMethodAndEndpoint(t *testing.T) {
	origTargetlessV2 := AllowTargetlessV2HMAC
	AllowTargetlessV2HMAC = false
	defer func() {
		AllowTargetlessV2HMAC = origTargetlessV2
	}()

	secret := []byte(vecSecret)
	body := []byte(vecABody)
	if err := VerifyHMACSigned(secret, http.MethodPost, EndpointProvenance, vecTS, vecNonce, body, vecInventoryV3); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("inventory signature accepted by provenance = %v, want ErrInvalidSignature", err)
	}
	if err := VerifyHMACSigned(secret, http.MethodGet, EndpointInventory, vecTS, vecNonce, body, vecInventoryV3); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("POST inventory signature accepted as GET = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyHMACSigned_ReplayHeadersRemainBound(t *testing.T) {
	origTargetlessV2 := AllowTargetlessV2HMAC
	AllowTargetlessV2HMAC = false
	defer func() {
		AllowTargetlessV2HMAC = origTargetlessV2
	}()
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, "1730000999", "different-nonce", []byte(vecABody), vecInventoryV3); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("replayed signature = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyHMACSigned_RejectsMissingMalformedAndWrongSecret(t *testing.T) {
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), ""); !errors.Is(err, ErrMissingSignature) {
		t.Fatalf("missing signature = %v, want ErrMissingSignature", err)
	}
	if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), "not-hex-zz"); !errors.Is(err, ErrMalformedSignature) {
		t.Fatalf("malformed signature = %v, want ErrMalformedSignature", err)
	}
	origTargetlessV2 := AllowTargetlessV2HMAC
	AllowTargetlessV2HMAC = false
	defer func() {
		AllowTargetlessV2HMAC = origTargetlessV2
	}()
	if err := VerifyHMACSigned([]byte("wrong-secret"), http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(vecABody), vecInventoryV3); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("wrong secret = %v, want ErrInvalidSignature", err)
	}
}

// A captured body-only signature must never authenticate, even when replay
// headers are original or replaced with fresh values.
func TestVerifyHMACSigned_RejectsCapturedBodyOnlyReplay(t *testing.T) {
	for _, headers := range []struct{ name, ts, nonce string }{
		{"original", vecTS, vecNonce},
		{"fresh timestamp", "1730000999", vecNonce},
		{"fresh nonce", vecTS, "fresh-nonce"},
		{"fresh replay headers", "1730000999", "fresh-nonce"},
	} {
		t.Run(headers.name, func(t *testing.T) {
			if err := VerifyHMACSigned([]byte(vecSecret), http.MethodPost, EndpointInventory, headers.ts, headers.nonce, []byte(vecABody), vecLegacyV1); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("captured body-only signature = %v, want ErrInvalidSignature", err)
			}
			form, err := VerifyHMACSignedWithForm([]byte(vecSecret), http.MethodPost, EndpointInventory, headers.ts, headers.nonce, []byte(vecABody), vecLegacyV1)
			if !errors.Is(err, ErrInvalidSignature) || form != HMACSigningFormUnknown {
				t.Errorf("captured body-only signature form = %q, error = %v; want Unknown, ErrInvalidSignature", form, err)
			}
		})
	}
}

func TestVerifyHMACSignedWithForm_RejectsTamperedV3Binding(t *testing.T) {
	for name, tc := range map[string]struct {
		method    string
		endpoint  EndpointID
		ts, nonce string
		body      []byte
	}{
		"method":    {http.MethodGet, EndpointInventory, vecTS, vecNonce, []byte(vecABody)},
		"endpoint":  {http.MethodPost, EndpointProvenance, vecTS, vecNonce, []byte(vecABody)},
		"timestamp": {http.MethodPost, EndpointInventory, "1730000999", vecNonce, []byte(vecABody)},
		"nonce":     {http.MethodPost, EndpointInventory, vecTS, "fresh-nonce", []byte(vecABody)},
		"body":      {http.MethodPost, EndpointInventory, vecTS, vecNonce, []byte(`{"hello":"changed"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			form, err := VerifyHMACSignedWithForm([]byte(vecSecret), tc.method, tc.endpoint, tc.ts, tc.nonce, tc.body, vecInventoryV3)
			if !errors.Is(err, ErrInvalidSignature) || form != HMACSigningFormUnknown {
				t.Errorf("tampered v3 form = %q, error = %v; want Unknown, ErrInvalidSignature", form, err)
			}
			if err := VerifyHMACSigned([]byte(vecSecret), tc.method, tc.endpoint, tc.ts, tc.nonce, tc.body, vecInventoryV3); !errors.Is(err, ErrInvalidSignature) {
				t.Errorf("tampered v3 = %v, want ErrInvalidSignature", err)
			}
		})
	}
}
