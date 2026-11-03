package cpepropose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"patched.im/api/internal/httpretry"
)

// Default base URLs for CPE_MODEL_PROVIDER, used when CPE_MODEL_BASE_URL is
// unset.
const (
	DefaultNVIDIABaseURL = "https://integrate.api.nvidia.com/v1"
	DefaultOpenAIBaseURL = "https://api.openai.com/v1"
)

// Provider names for CPE_MODEL_PROVIDER.
const (
	ProviderAnthropic = "anthropic"
	ProviderNVIDIA    = "nvidia"
	ProviderOpenAI    = "openai"
)

// OpenAICompatibleChooser calls an OpenAI-compatible chat-completions API
// (POST {base}/chat/completions, response_format json_object) with the same
// evidence and candidate prompt AnthropicChooser sends (buildUserContent),
// and validates the answer with the identical strict rule
// (decodeAndValidateAnswer): a candidate id outside the supplied list is
// rejected, never mapped. Both NVIDIA NIM and OpenAI expose this shape, so
// one implementation serves either, selected by Provider/BaseURL/Model.
//
// json_object mode has no per-request schema/enum constraint (the widest
// support across NVIDIA NIM and OpenAI), so the allowed choice ids are
// spelled out in the system prompt instead; the answer is still validated
// strictly afterwards, exactly as AnthropicChooser's schema-constrained
// answer is validated again rather than trusted outright.
type OpenAICompatibleChooser struct {
	// Provider is "nvidia" or "openai". It prefixes the model id recorded
	// on the proposal (e.g. "nvidia:meta/llama-3.1-70b-instruct"), so a
	// mapping's provenance survives a provider switch.
	Provider string
	BaseURL  string
	APIKey   string
	Model    string
	HTTP     *http.Client
	Logger   *slog.Logger
	Sleep    func(context.Context, time.Duration) error // retry wait override (tests)
}

// newOpenAICompatibleChooser builds a chooser with a bounded HTTP client
// timeout, for the resolved provider/base URL/key/model. Callers (NewWorker)
// validate the inputs first; this constructor assumes they are already
// non-empty.
func newOpenAICompatibleChooser(provider, apiKey, baseURL, model string, logger *slog.Logger) *OpenAICompatibleChooser {
	return &OpenAICompatibleChooser{
		Provider: provider,
		BaseURL:  baseURL,
		APIKey:   apiKey,
		Model:    model,
		HTTP:     &http.Client{Timeout: 45 * time.Second},
		Logger:   logger,
	}
}

// jsonModeInstructions tells the model the exact JSON shape to answer with,
// since json_object mode (unlike AnthropicChooser's json_schema) carries no
// per-request field or enum constraint. This is a hint only: the answer is
// validated strictly regardless (decodeAndValidateAnswer).
func jsonModeInstructions(ids []string) string {
	quoted := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		quoted = append(quoted, `"`+id+`"`)
	}
	quoted = append(quoted, `"`+ChoiceNone+`"`)
	return "Respond with a single JSON object and nothing else: no markdown, no code fences, no " +
		"commentary before or after it. It must have exactly these fields: \"choice\" (one of: " +
		strings.Join(quoted, ", ") + "), \"confidence\" (\"high\", \"medium\" or \"low\"), " +
		"\"rationale\" (a short string). No other fields."
}

// buildOpenAIRequest returns the chat/completions body and the id -> key
// map the answer is validated against. Same evidence and candidates as
// buildModelRequest (buildUserContent), same system prompt, plus the
// json-mode field instructions since there is no schema enum here.
func buildOpenAIRequest(model string, ev ProductEvidence, candidates []Candidate) ([]byte, map[string]string, error) {
	shown, allowed, ids := promptCandidates(candidates)
	user, err := buildUserContent(ev, shown)
	if err != nil {
		return nil, nil, err
	}
	system := systemPrompt + "\n\n" + jsonModeInstructions(ids)
	req := map[string]any{
		"model":       model,
		"max_tokens":  modelMaxTokens,
		"temperature": 0,
		"messages": []map[string]any{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]any{"type": "json_object"},
	}
	body, err := json.Marshal(req)
	return body, allowed, err
}

// Choose asks the model and validates its answer exactly as
// AnthropicChooser.Choose does: every error wraps either ErrModelUnavailable
// or ErrInvalidModelResponse, and a malformed reply, a candidate outside the
// supplied list, a non-2xx status or a timeout is never mapped to a CPE.
func (c *OpenAICompatibleChooser) Choose(ctx context.Context, ev ProductEvidence, candidates []Candidate) (ModelChoice, error) {
	if c == nil || c.APIKey == "" || c.Model == "" {
		return ModelChoice{}, fmt.Errorf("%w: OpenAI-compatible chooser not configured", ErrModelUnavailable)
	}
	if len(candidates) == 0 {
		return ModelChoice{}, fmt.Errorf("%w: no candidates", ErrInvalidModelResponse)
	}
	reqBody, allowed, err := buildOpenAIRequest(c.Model, ev, candidates)
	if err != nil {
		return ModelChoice{}, fmt.Errorf("%w: build request: %v", ErrInvalidModelResponse, err)
	}
	body, err := httpretry.Do(ctx, httpretry.Options{
		MaxAttempts: 3,
		OverallCap:  2 * time.Minute,
		Backoff:     []time.Duration{2 * time.Second, 10 * time.Second},
		IsRetryable: httpretry.IsRetryable,
		RetryAfter: func(err error) time.Duration {
			var he *httpretry.HTTPError
			if errors.As(err, &he) {
				return he.RetryAfter
			}
			return 0
		},
		Status: func(err error) int {
			var he *httpretry.HTTPError
			if errors.As(err, &he) {
				return he.StatusCode
			}
			return 0
		},
		Logger:    c.logger(),
		LogAction: "cpe proposer model call",
		Source:    c.Provider,
		Document:  "chat_completions",
		Sleep:     c.Sleep,
	}, func(ctx context.Context) ([]byte, error) { return c.post(ctx, reqBody) })
	if err != nil {
		return ModelChoice{}, fmt.Errorf("%w: %v", ErrModelUnavailable, err)
	}
	choice, err := parseChatCompletionsResponse(body, allowed)
	if err != nil {
		return ModelChoice{}, err
	}
	choice.Model = c.Provider + ":" + c.Model
	return choice, nil
}

func (c *OpenAICompatibleChooser) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.Default()
}

// post sends the request and returns the raw response body. The API key is
// carried only in the Authorization header, never logged (httpretry logs
// source/document/status/attempt only, never the request or its headers).
func (c *OpenAICompatibleChooser) post(ctx context.Context, body []byte) ([]byte, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, &httpretry.HTTPError{StatusCode: resp.StatusCode,
			RetryAfter: httpretry.ParseRetryAfter(resp.Header.Get("retry-after"), 30*time.Second)}
	}
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxModelResponseBytes+1))
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	if len(out) > maxModelResponseBytes {
		return nil, fmt.Errorf("model response exceeds %d bytes", maxModelResponseBytes)
	}
	return out, nil
}

// chatCompletionsResponse is the OpenAI-compatible chat/completions reply
// shape (NVIDIA NIM and OpenAI both use it).
type chatCompletionsResponse struct {
	Choices []struct {
		FinishReason string `json:"finish_reason"`
		Message      struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// parseChatCompletionsResponse validates a chat/completions reply strictly:
// exactly one choice, a normal stop (finish_reason "stop"), then the same
// strict-JSON answer validation AnthropicChooser uses
// (decodeAndValidateAnswer): unknown fields, trailing data, an unknown
// confidence, or a choice outside the supplied candidates are all rejected.
func parseChatCompletionsResponse(body []byte, allowed map[string]string) (ModelChoice, error) {
	var resp chatCompletionsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return ModelChoice{}, fmt.Errorf("%w: decode: %v", ErrInvalidModelResponse, err)
	}
	if len(resp.Choices) != 1 {
		return ModelChoice{}, fmt.Errorf("%w: %d choices", ErrInvalidModelResponse, len(resp.Choices))
	}
	ch := resp.Choices[0]
	if ch.FinishReason != "stop" {
		return ModelChoice{}, fmt.Errorf("%w: finish_reason %q", ErrInvalidModelResponse, capRunes(ch.FinishReason, 20))
	}
	return decodeAndValidateAnswer(ch.Message.Content, allowed)
}
