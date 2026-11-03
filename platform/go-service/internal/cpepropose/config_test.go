package cpepropose

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The model is called only once zero data retention is confirmed: a key
// alone leaves the proposer on the no-model path, degraded with its own
// reason.
func TestNewWorkerRequiresZDRConfirmation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("ANTHROPIC_API_KEY", "test-key")
	t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "")
	w := NewWorker(nil, LoadConfig(logger), logger)
	if w.Chooser != nil {
		t.Fatal("a model chooser was configured without CPE_MODEL_ZDR_CONFIRMED=true")
	}
	if w.NoModelReason != ReasonModelZDRUnconfirmed {
		t.Fatalf("NoModelReason = %q, want %s", w.NoModelReason, ReasonModelZDRUnconfirmed)
	}
	t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "true")
	if w := NewWorker(nil, LoadConfig(logger), logger); w.Chooser == nil {
		t.Fatal("no chooser with a key and ZDR confirmed")
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	if w := NewWorker(nil, LoadConfig(logger), logger); w.Chooser != nil || w.NoModelReason != ReasonModelUnavailable {
		t.Fatalf("no key: chooser %v reason %q", w.Chooser, w.NoModelReason)
	}
	t.Setenv("CPE_PROPOSER_ENABLED", "false")
	if rc := LoadConfig(logger); !rc.Worker.ProposeDisabled {
		t.Fatal("CPE_PROPOSER_ENABLED=false did not disable proposing")
	}
}

// PAT-2227: CPE_MODEL_PROVIDER selects nvidia/openai/anthropic. With no
// ANTHROPIC_API_KEY set, an unset provider resolves to nothing configured
// (back-compat: only ANTHROPIC_API_KEY alone defaults to anthropic), a
// missing CPE_MODEL and an unrecognised provider both degrade to
// model_unavailable, and none of it ever panics.
func TestNewWorkerProviderResolution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("missing CPE_MODEL degrades to model_unavailable", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("CPE_MODEL_PROVIDER", "nvidia")
		t.Setenv("CPE_MODEL_API_KEY", "nvidia-key")
		t.Setenv("CPE_MODEL", "")
		t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "true")
		w := NewWorker(nil, LoadConfig(logger), logger)
		if w.Chooser != nil || w.NoModelReason != ReasonModelUnavailable {
			t.Fatalf("missing CPE_MODEL: chooser %v reason %q", w.Chooser, w.NoModelReason)
		}
	})

	t.Run("unknown provider degrades to model_unavailable", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("CPE_MODEL_PROVIDER", "azure")
		t.Setenv("CPE_MODEL_API_KEY", "k")
		t.Setenv("CPE_MODEL", "m")
		t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "true")
		w := NewWorker(nil, LoadConfig(logger), logger)
		if w.Chooser != nil || w.NoModelReason != ReasonModelUnavailable {
			t.Fatalf("unknown provider: chooser %v reason %q", w.Chooser, w.NoModelReason)
		}
	})

	t.Run("nvidia with key, model and ZDR confirmed configures a chooser", func(t *testing.T) {
		t.Setenv("ANTHROPIC_API_KEY", "")
		t.Setenv("CPE_MODEL_PROVIDER", "nvidia")
		t.Setenv("CPE_MODEL_API_KEY", "nvidia-key")
		t.Setenv("CPE_MODEL", "meta/llama-3.1-70b-instruct")
		t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "true")
		w := NewWorker(nil, LoadConfig(logger), logger)
		if w.Chooser == nil {
			t.Fatal("nvidia provider with key, model and ZDR confirmed: no chooser")
		}
	})

	t.Run("ANTHROPIC_API_KEY alone still defaults to anthropic", func(t *testing.T) {
		t.Setenv("CPE_MODEL_PROVIDER", "")
		t.Setenv("CPE_MODEL_API_KEY", "")
		t.Setenv("ANTHROPIC_API_KEY", "test-key")
		t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "true")
		w := NewWorker(nil, LoadConfig(logger), logger)
		if w.Chooser == nil {
			t.Fatal("ANTHROPIC_API_KEY alone, no CPE_MODEL_PROVIDER: want the back-compat anthropic default")
		}
		if _, ok := w.Chooser.(*AnthropicChooser); !ok {
			t.Fatalf("chooser = %T, want *AnthropicChooser", w.Chooser)
		}
	})
}

// A non-https, non-loopback CPE_MODEL_BASE_URL must not configure a
// chooser: the model call would otherwise ship product identity data over a
// plaintext connection to a public host.
func TestNewWorkerModelBaseURLMustBeHTTPSUnlessLoopback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CPE_MODEL_PROVIDER", "nvidia")
	t.Setenv("CPE_MODEL_API_KEY", "k")
	t.Setenv("CPE_MODEL", "m")
	t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "true")
	t.Setenv("CPE_MODEL_BASE_URL", "http://example.com")
	w := NewWorker(nil, LoadConfig(logger), logger)
	if w.Chooser != nil {
		t.Fatal("a non-https, non-loopback CPE_MODEL_BASE_URL must not configure a chooser")
	}
}

// The degraded log line names the specific missing environment variable, so
// a misconfigured box can be fixed without reading the source.
func TestNewWorkerMissingCPEModelLogsWhichVarIsMissing(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CPE_MODEL_PROVIDER", "openai")
	t.Setenv("CPE_MODEL_API_KEY", "openai-key")
	t.Setenv("CPE_MODEL", "")
	t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "true")
	w := NewWorker(nil, LoadConfig(logger), logger)
	if w.Chooser != nil || w.NoModelReason != ReasonModelUnavailable {
		t.Fatalf("chooser %v reason %q", w.Chooser, w.NoModelReason)
	}
	if !strings.Contains(buf.String(), "CPE_MODEL") {
		t.Fatalf("degraded log does not name the missing variable:\n%s", buf.String())
	}
}

// The ZDR gate applies to every provider, not only Anthropic: with it
// unconfirmed, NewWorker never wires up a Chooser at all, so nothing can
// ever reach the network, however the provider is configured.
func TestNewWorkerZDRGateAppliesToEveryProvider(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
	}))
	defer srv.Close()

	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("CPE_MODEL_PROVIDER", "nvidia")
	t.Setenv("CPE_MODEL_API_KEY", "nvidia-key")
	t.Setenv("CPE_MODEL", "meta/llama-3.1-70b-instruct")
	t.Setenv("CPE_MODEL_BASE_URL", srv.URL)
	t.Setenv("CPE_MODEL_ZDR_CONFIRMED", "")
	w := NewWorker(nil, LoadConfig(logger), logger)
	if w.Chooser != nil {
		t.Fatal("a chooser was configured without CPE_MODEL_ZDR_CONFIRMED=true")
	}
	if w.NoModelReason != ReasonModelZDRUnconfirmed {
		t.Fatalf("NoModelReason = %q, want %s", w.NoModelReason, ReasonModelZDRUnconfirmed)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("HTTP calls = %d, want 0: ZDR unconfirmed must never reach the network", calls)
	}
}
