package cpepropose

import (
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Environment (documented in docs/SETUP.md and api-vps-artefacts/OPERATIONS.md):
//
//	CPE_PROPOSER_ENABLED      true | false (default true). false stops
//	                          proposing (no NVD or model call); the
//	                          maintenance sweeps (re-check, reconciliation,
//	                          expiry) still run. Recording proposals at
//	                          ingest is always on; it only writes the
//	                          database.
//	CPE_AUTO_PUBLISH_ENABLED  true | false (default true). false sends every
//	                          proposal to staff review whatever the evidence.
//	CPE_PROPOSER_INTERVAL     Go duration between proposer runs (default 2m).
//	CPE_PROPOSER_BATCH        proposals per run (default 10, max 100).
//	CPE_MODEL_PROVIDER        nvidia | openai | anthropic. Unset defaults to
//	                          anthropic only when ANTHROPIC_API_KEY alone is
//	                          set (back-compat); otherwise it must be set
//	                          explicitly. An unrecognised value degrades the
//	                          proposer (model_unavailable, warning logged),
//	                          never crashes the extractor.
//	CPE_MODEL_API_KEY         the model key for nvidia and openai. For
//	                          anthropic, ANTHROPIC_API_KEY still works (see
//	                          below); CPE_MODEL_API_KEY is not read for it.
//	ANTHROPIC_API_KEY         the anthropic provider's key. Unset (any
//	                          provider): proposals get candidates only, go to
//	                          staff review as model_unavailable, and the
//	                          proposer reports itself degraded.
//	CPE_MODEL_BASE_URL        optional; defaults to
//	                          https://integrate.api.nvidia.com/v1 (nvidia) or
//	                          https://api.openai.com/v1 (openai). Must be
//	                          https unless the host is loopback (tests use
//	                          httptest); anything else degrades the proposer
//	                          with a warning rather than sending product
//	                          identity data in the clear.
//	CPE_MODEL                 the model id for nvidia and openai. Required
//	                          for those providers, no silent default (the
//	                          right id depends on the account): missing, the
//	                          worker degrades to model_unavailable with a log
//	                          line naming CPE_MODEL. For anthropic,
//	                          CPE_PROPOSER_MODEL below still works.
//	CPE_PROPOSER_MODEL        anthropic model id (default
//	                          claude-haiku-4-5-20251001). Anthropic only,
//	                          kept for back-compat; nvidia/openai use
//	                          CPE_MODEL, which has no default.
//	CPE_MODEL_ZDR_CONFIRMED   true only once the operator has confirmed the
//	                          configured provider's data-retention terms are
//	                          acceptable for software-identity data.
//	                          Anything else: the model is never called, even
//	                          with a key; proposals take the no-model path and
//	                          the proposer reports degraded /
//	                          model_zdr_unconfirmed. Applies to every
//	                          provider identically.
//	NVD_API_KEY               the existing NVD key. The proposer's share of
//	                          NVD's limit is one request per 6 s with a key,
//	                          60 s without, across every proposer process
//	                          (NVDBudget).
//	LINEAR_API_TOKEN          the review digest's Linear key (patched-cve-sync).
//	LINEAR_TEAM_KEY           default PAT.

// RuntimeConfig is the proposer's resolved environment.
type RuntimeConfig struct {
	Enabled  bool
	Interval time.Duration
	Worker   Config
	// Model is the anthropic model id (CPE_PROPOSER_MODEL or DefaultModel).
	// Kept separate from ModelID (CPE_MODEL) because only the latter is
	// required-with-no-default.
	Model        string
	AnthropicKey string
	// Provider is the resolved CPE_MODEL_PROVIDER: "nvidia", "openai",
	// "anthropic", or "" when neither was set explicitly nor defaulted
	// (no ANTHROPIC_API_KEY either) — NewWorker then has no model,
	// exactly as an unset ANTHROPIC_API_KEY always has.
	Provider string
	// ModelAPIKey is CPE_MODEL_API_KEY, the nvidia/openai key.
	ModelAPIKey string
	// ModelID is CPE_MODEL, the nvidia/openai model id. No default: the
	// right id depends on the account.
	ModelID string
	// ModelBaseURL is CPE_MODEL_BASE_URL, raw and possibly empty (NewWorker
	// applies the provider's default and validates it).
	ModelBaseURL string
	// ModelZDRConfirmed is CPE_MODEL_ZDR_CONFIRMED.
	ModelZDRConfirmed bool
	NVDKey            string
}

// LoadConfig reads the environment. Booleans are parsed explicitly: an
// unrecognised value keeps the default and is logged, never read by
// truthiness.
func LoadConfig(logger *slog.Logger) RuntimeConfig {
	if logger == nil {
		logger = slog.Default()
	}
	rc := RuntimeConfig{
		Enabled:      envBool(logger, "CPE_PROPOSER_ENABLED", true),
		Interval:     envDuration(logger, "CPE_PROPOSER_INTERVAL", 2*time.Minute),
		Worker:       DefaultConfig(),
		Model:        strings.TrimSpace(os.Getenv("CPE_PROPOSER_MODEL")),
		AnthropicKey: strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")),
		ModelAPIKey:  strings.TrimSpace(os.Getenv("CPE_MODEL_API_KEY")),
		ModelID:      strings.TrimSpace(os.Getenv("CPE_MODEL")),
		ModelBaseURL: strings.TrimSpace(os.Getenv("CPE_MODEL_BASE_URL")),
		NVDKey:       strings.TrimSpace(os.Getenv("NVD_API_KEY")),
	}
	rc.Worker.AutoPublish = envBool(logger, "CPE_AUTO_PUBLISH_ENABLED", true)
	rc.ModelZDRConfirmed = envBool(logger, "CPE_MODEL_ZDR_CONFIRMED", false)
	rc.Worker.ProposeDisabled = !rc.Enabled
	if v := strings.TrimSpace(os.Getenv("CPE_PROPOSER_BATCH")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			rc.Worker.BatchSize = n
		} else {
			logger.Warn("ignoring invalid CPE_PROPOSER_BATCH", "value", v)
		}
	}
	if rc.Model == "" {
		rc.Model = DefaultModel
	}
	if rc.Interval < 10*time.Second {
		rc.Interval = 10 * time.Second
	}

	// Provider resolution: an explicit CPE_MODEL_PROVIDER always wins.
	// Unset resolves to anthropic only when ANTHROPIC_API_KEY alone is set
	// (back-compat with every deployment from before this variable
	// existed); otherwise it stays unresolved, and NewWorker has no model,
	// exactly as an unset ANTHROPIC_API_KEY always degraded on its own.
	rc.Provider = strings.ToLower(strings.TrimSpace(os.Getenv("CPE_MODEL_PROVIDER")))
	if rc.Provider == "" && rc.AnthropicKey != "" {
		rc.Provider = ProviderAnthropic
	}
	return rc
}

// NewWorker builds a Worker from the resolved environment. The chooser is
// nil when the resolved provider has no usable key/model configured, or when
// zero data retention has not been confirmed (CPE_MODEL_ZDR_CONFIRMED):
// product data is sent to a model only under zero retention, whichever
// provider it is.
func NewWorker(pool *pgxpool.Pool, rc RuntimeConfig, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	w := &Worker{
		Pool:   pool,
		Dict:   NewDictionary(rc.NVDKey, pool, logger),
		Config: rc.Worker,
		Logger: logger,
	}
	chooser, reason := buildChooser(rc, logger)
	switch {
	case chooser == nil:
		w.NoModelReason = reason
	case !rc.ModelZDRConfirmed:
		w.NoModelReason = ReasonModelZDRUnconfirmed
	default:
		w.Chooser = chooser
	}
	return w
}

// buildChooser resolves rc.Provider to a Chooser, or nil with the degraded
// reason to report. It never panics: an unrecognised provider, or a
// provider missing its key/model/base-URL, degrades to model_unavailable
// with a warning naming the problem, exactly like an unset ANTHROPIC_API_KEY
// always has.
func buildChooser(rc RuntimeConfig, logger *slog.Logger) (Chooser, string) {
	switch rc.Provider {
	case ProviderAnthropic, "":
		// "" only reaches here when neither CPE_MODEL_PROVIDER nor
		// ANTHROPIC_API_KEY was set; NewAnthropicChooser("", ...) already
		// returns nil silently for that case, same as before this ticket.
		c := NewAnthropicChooser(rc.AnthropicKey, rc.Model, logger)
		if c == nil {
			return nil, ReasonModelUnavailable
		}
		return c, ""
	case ProviderNVIDIA, ProviderOpenAI:
		if rc.ModelAPIKey == "" {
			logger.Warn("cpe proposer degraded: CPE_MODEL_API_KEY not set", "provider", rc.Provider)
			return nil, ReasonModelUnavailable
		}
		if rc.ModelID == "" {
			logger.Warn("cpe proposer degraded: CPE_MODEL not set", "provider", rc.Provider)
			return nil, ReasonModelUnavailable
		}
		base := rc.ModelBaseURL
		if base == "" {
			base = defaultModelBaseURL(rc.Provider)
		}
		if !httpsOrLoopback(base) {
			logger.Warn("cpe proposer degraded: CPE_MODEL_BASE_URL must be https or a loopback host",
				"provider", rc.Provider, "value", base)
			return nil, ReasonModelUnavailable
		}
		return newOpenAICompatibleChooser(rc.Provider, rc.ModelAPIKey, base, rc.ModelID, logger), ""
	default:
		logger.Warn("cpe proposer degraded: unrecognised CPE_MODEL_PROVIDER", "provider", rc.Provider)
		return nil, ReasonModelUnavailable
	}
}

func defaultModelBaseURL(provider string) string {
	if provider == ProviderNVIDIA {
		return DefaultNVIDIABaseURL
	}
	return DefaultOpenAIBaseURL
}

// httpsOrLoopback reports whether base is safe to send product identity
// data to: an https URL, or any scheme against a loopback host (so tests can
// point CPE_MODEL_BASE_URL at an httptest.Server).
func httpsOrLoopback(base string) bool {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func envBool(logger *slog.Logger, key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	logger.Warn("ignoring unrecognised boolean", "key", key, "value", v, "default", def)
	return def
}

func envDuration(logger *slog.Logger, key string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		logger.Warn("ignoring invalid duration", "key", key, "value", v)
		return def
	}
	return d
}
