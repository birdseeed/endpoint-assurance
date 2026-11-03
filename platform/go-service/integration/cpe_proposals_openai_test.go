//go:build integration

package integration

// PAT-2227: the OpenAI-compatible chooser (NVIDIA NIM today, OpenAI once in
// production) must uphold the same PAT-2138 invariant as AnthropicChooser: a
// product whose identity rests on its name alone is never auto-published,
// however confident the model, because nothing independently corroborates
// the vendor. This reuses the proposerHarness plumbing from
// cpe_proposals_test.go (fake NVD, postSignedAppsPayload, runProposer,
// proposalFor), swapping only the Chooser for an OpenAICompatibleChooser
// against a fake chat/completions server.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"patched.im/api/internal/cpepropose"
)

// fakeChatCompletionsModel answers the OpenAI-compatible chat/completions
// shape NVIDIA NIM and OpenAI both expose. Unlike fakeModel's Anthropic
// Messages shape, the user turn is not necessarily messages[0]: the system
// prompt is its own message ahead of it.
type fakeChatCompletionsModel struct {
	mu       sync.Mutex
	answer   func(user string, candidates []map[string]any) (string, string)
	requests []string
}

func newFakeChatCompletionsModel(t *testing.T) (*fakeChatCompletionsModel, *httptest.Server) {
	f := &fakeChatCompletionsModel{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(raw, &req)
		var user string
		for _, m := range req.Messages {
			if m.Role == "user" {
				user = m.Content
			}
		}
		var cands []map[string]any
		if m := candidateBlock.FindStringSubmatch(user); m != nil {
			_ = json.Unmarshal([]byte(m[1]), &cands)
		}
		f.mu.Lock()
		f.requests = append(f.requests, string(raw))
		answer := f.answer
		f.mu.Unlock()
		choice, conf := "none", "low"
		if answer != nil {
			choice, conf = answer(user, cands)
		}
		text, _ := json.Marshal(map[string]string{"choice": choice, "confidence": conf, "rationale": "fake model"})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{
				"finish_reason": "stop",
				"message":       map[string]any{"role": "assistant", "content": string(text)},
			}},
		})
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

// newProposerHarnessOpenAICompatible is newProposerHarness with an
// OpenAICompatibleChooser wired in place of AnthropicChooser, for the given
// provider name ("nvidia" or "openai" both take the identical code path).
func newProposerHarnessOpenAICompatible(t *testing.T, provider string) (proposerHarness, *fakeChatCompletionsModel) {
	t.Helper()
	nvd, nvdSrv := newFakeNVD(t)
	model, modelSrv := newFakeChatCompletionsModel(t)
	w := &cpepropose.Worker{
		Pool: env.pool,
		Dict: &cpepropose.Dictionary{BaseURL: nvdSrv.URL, HTTP: nvdSrv.Client(), Cache: nil,
			Sleep: func(context.Context, time.Duration) error { return nil }},
		Config: cpepropose.Config{AutoPublish: true, BatchSize: 1000, MaxNVDAttempts: 3, ModelRetryAfter: time.Hour},
		Chooser: &cpepropose.OpenAICompatibleChooser{Provider: provider, BaseURL: modelSrv.URL,
			APIKey: "test-" + provider + "-key", Model: "test-model", HTTP: modelSrv.Client()},
	}
	return proposerHarness{nvd: nvd, worker: w}, model
}

// Mirrors TestCPEProposalNameOnlyNeverAutoPublishes exactly, but through the
// nvidia provider: a name-only product is never published even at high
// model confidence, whichever chooser answered.
func TestCPEProposalNameOnlyNeverAutoPublishesOpenAICompatible(t *testing.T) {
	sfx := randomHex(4)
	tn := newCVETestTenant(t, "pat2227-nameonly-"+sfx)
	h, model := newProposerHarnessOpenAICompatible(t, "nvidia")
	vendor := "pat2227n" + sfx
	app := "Pat2227 Nameonly " + sfx
	setNVD(h.nvd, app, "cpe:2.3:a:"+vendor+":pat2227_nameonly_"+sfx+":1.0:*:*:*:*:*:*:*")
	model.answer = pickVendor(vendor, "high")

	hw := strings.ToUpper(sfx + "-2227-4000-8000-000000000001")
	postSignedAppsPayload(t, tn, hw, []signedApp{{app, "1.0", "com.example.pat2227.n." + sfx, "", ""}}, time.Now())
	p := runProposer(t, h, app)
	if p.State != cpepropose.StateNeedsReview || derefStr(p.Reason) != cpepropose.ReasonSingleTenant || p.MappingID != nil {
		t.Fatalf("name-only proposal = %+v reason %s, want needs_review/single_tenant", p, derefStr(p.Reason))
	}
	seedFeedEntry(t, "CVE-2099-"+sfx+"O", vendor, "pat2227_nameonly_"+sfx, "2.0", false)
	alsoReportedBy(t, app, "com.example.pat2227.n."+sfx, "")
	if _, err := env.pool.Exec(context.Background(), `UPDATE cpe_mapping_proposals SET next_attempt_at = now() - interval '1 second' WHERE id = $1`, p.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.worker.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	p, _ = proposalFor(t, "macos", app)
	if p.State != cpepropose.StateNeedsReview || derefStr(p.Reason) != cpepropose.ReasonNoSignerEvidence || p.MappingID != nil {
		t.Fatalf("two-tenant name-only proposal = %+v reason %s, want needs_review/no_signer_evidence", p, derefStr(p.Reason))
	}
	if n := countRows(t, `SELECT count(*) FROM app_cpe_mappings WHERE match_name = $1`, app); n != 0 {
		t.Fatal("a name-only proposal created a mapping through the OpenAI-compatible chooser")
	}
}
