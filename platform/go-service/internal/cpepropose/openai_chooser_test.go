package cpepropose

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeChatCompletions serves the OpenAI-compatible chat/completions shape
// both NVIDIA NIM and OpenAI expose, so one fake stands in for either
// provider's base URL.
func fakeChatCompletions(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body map[string]any)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" || r.Method != http.MethodPost {
			http.Error(w, "unexpected", http.StatusNotFound)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		handler(w, r, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func chatCompletionBody(finishReason, content string) []byte {
	b, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{
			"finish_reason": finishReason,
			"message":       map[string]any{"role": "assistant", "content": content},
		}},
	})
	return b
}

func TestOpenAICompatibleChooserNVIDIAPicksValidCandidate(t *testing.T) {
	var gotAuth, gotFormat string
	srv := fakeChatCompletions(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		gotAuth = r.Header.Get("Authorization")
		if rf, ok := body["response_format"].(map[string]any); ok {
			gotFormat, _ = rf["type"].(string)
		}
		if body["model"] != "meta/llama-3.1-70b-instruct" {
			t.Errorf("model = %v", body["model"])
		}
		_, _ = w.Write(chatCompletionBody("stop", `{"choice":"C1","confidence":"high","rationale":"name and signer agree"}`))
	})
	c := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: srv.URL, APIKey: "nvidia-key",
		Model: "meta/llama-3.1-70b-instruct", HTTP: srv.Client(), Sleep: noSleep}
	got, err := c.Choose(context.Background(), ProductEvidence{Name: "acme widget"}, testCandidates())
	if err != nil {
		t.Fatal(err)
	}
	if got.Choice != "acme:widget" || got.Confidence != ConfidenceHigh {
		t.Fatalf("got %+v", got)
	}
	if got.Model != "nvidia:meta/llama-3.1-70b-instruct" {
		t.Fatalf("Model = %q, want the provider-prefixed model id", got.Model)
	}
	if gotAuth != "Bearer nvidia-key" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if gotFormat != "json_object" {
		t.Fatalf("response_format.type = %q, want json_object", gotFormat)
	}
}

// The openai provider hits the exact same code path, through a different
// base URL: both are the same chat-completions shape.
func TestOpenAICompatibleChooserOpenAISameCodePathDifferentBaseURL(t *testing.T) {
	srv := fakeChatCompletions(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		_, _ = w.Write(chatCompletionBody("stop", `{"choice":"C2","confidence":"high","rationale":"server edition matches"}`))
	})
	c := &OpenAICompatibleChooser{Provider: "openai", BaseURL: srv.URL, APIKey: "openai-key",
		Model: "gpt-5.1", HTTP: srv.Client(), Sleep: noSleep}
	got, err := c.Choose(context.Background(), ProductEvidence{Name: "other widget server"}, testCandidates())
	if err != nil {
		t.Fatal(err)
	}
	if got.Choice != "other:widget_server" {
		t.Fatalf("got %+v", got)
	}
	if got.Model != "openai:gpt-5.1" {
		t.Fatalf("Model = %q, want the provider-prefixed model id", got.Model)
	}
}

// The core PAT-2138 constraint holds for every chooser: a CPE the model
// names that was not in the supplied candidate list is never mapped, even
// with high confidence.
func TestOpenAICompatibleChooserRejectsCandidateOutsideList(t *testing.T) {
	srv := fakeChatCompletions(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		_, _ = w.Write(chatCompletionBody("stop", `{"choice":"evil:backdoor","confidence":"high","rationale":"x"}`))
	})
	c := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: srv.URL, APIKey: "k", Model: "m", HTTP: srv.Client(), Sleep: noSleep}
	if _, err := c.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrInvalidModelResponse) {
		t.Fatalf("err = %v, want ErrInvalidModelResponse", err)
	}
}

func TestOpenAICompatibleChooserMalformedOrErrorResponses(t *testing.T) {
	t.Run("malformed JSON content", func(t *testing.T) {
		srv := fakeChatCompletions(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			_, _ = w.Write(chatCompletionBody("stop", `not json`))
		})
		c := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: srv.URL, APIKey: "k", Model: "m", HTTP: srv.Client(), Sleep: noSleep}
		if _, err := c.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrInvalidModelResponse) {
			t.Fatalf("err = %v, want ErrInvalidModelResponse", err)
		}
	})
	t.Run("malformed envelope", func(t *testing.T) {
		srv := fakeChatCompletions(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			_, _ = w.Write([]byte(`{not valid json`))
		})
		c := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: srv.URL, APIKey: "k", Model: "m", HTTP: srv.Client(), Sleep: noSleep}
		if _, err := c.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrInvalidModelResponse) {
			t.Fatalf("err = %v, want ErrInvalidModelResponse", err)
		}
	})
	t.Run("non-2xx status", func(t *testing.T) {
		srv := fakeChatCompletions(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
			w.WriteHeader(http.StatusInternalServerError)
		})
		c := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: srv.URL, APIKey: "k", Model: "m", HTTP: srv.Client(), Sleep: noSleep}
		if _, err := c.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrModelUnavailable) {
			t.Fatalf("err = %v, want ErrModelUnavailable", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(50 * time.Millisecond)
		}))
		t.Cleanup(srv.Close)
		c := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: srv.URL, APIKey: "k", Model: "m",
			HTTP: &http.Client{Timeout: 5 * time.Millisecond}, Sleep: noSleep}
		if _, err := c.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrModelUnavailable) {
			t.Fatalf("err = %v, want ErrModelUnavailable", err)
		}
	})
}

func TestOpenAICompatibleChooserAuthorizationHeaderCarriesKey(t *testing.T) {
	var gotAuth string
	srv := fakeChatCompletions(t, func(w http.ResponseWriter, r *http.Request, body map[string]any) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write(chatCompletionBody("stop", `{"choice":"none","confidence":"low","rationale":"x"}`))
	})
	c := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: srv.URL, APIKey: "secret-key-123", Model: "m", HTTP: srv.Client(), Sleep: noSleep}
	if _, err := c.Choose(context.Background(), ProductEvidence{}, testCandidates()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer secret-key-123" {
		t.Fatalf("Authorization = %q, want the key never logged, only sent as a bearer token", gotAuth)
	}
}

// A nil chooser, or one missing its key or model, degrades exactly like
// AnthropicChooser: ErrModelUnavailable, never a panic.
func TestOpenAICompatibleChooserUnconfiguredIsModelUnavailable(t *testing.T) {
	var nilChooser *OpenAICompatibleChooser
	if _, err := nilChooser.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("nil chooser: err = %v, want ErrModelUnavailable", err)
	}
	noKey := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: "http://127.0.0.1:1", Model: "m"}
	if _, err := noKey.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("no key: err = %v, want ErrModelUnavailable", err)
	}
	noModel := &OpenAICompatibleChooser{Provider: "nvidia", BaseURL: "http://127.0.0.1:1", APIKey: "k"}
	if _, err := noModel.Choose(context.Background(), ProductEvidence{}, testCandidates()); !errors.Is(err, ErrModelUnavailable) {
		t.Fatalf("no model: err = %v, want ErrModelUnavailable", err)
	}
}
