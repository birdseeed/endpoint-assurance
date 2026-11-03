// Package main is the patched.im extraction worker.
//
// Polls raw_payloads for rows with extracted_at IS NULL, parses the schema_v2
// macOS payload, and upserts into devices / device_apps / compliance_signals.
// Runs as its own systemd unit alongside patched-api so an extractor crash
// doesn't take ingestion down.
//
// Configuration is via environment file /etc/patched-extractor/env, loaded by
// systemd. No CLI flags.
//
// PAT-1377: also serves its own Prometheus /metrics on a loopback-only
// listener (LISTEN_METRICS, default 127.0.0.1:8083). The extraction loop in
// internal/extractor is the only place that observes ExtractorBatchSize /
// ExtractorRowsProcessed, so those metrics have to be registered and
// exposed here, in this process. patched-api's :8081 previously registered
// the same package-level collectors but never incremented them, which is
// why ExtractorStalled and DeadLetterRows never matched a live series.
//
// Port chosen deliberately: :8082 on this box is already Caddy, bound to
// the Tailscale interface and reverse-proxying to patched-api's :8081 (see
// Caddyfile.api and the "tag:main -> tag:api:8082" ACL grant). A loopback
// bind on :8082 would not collide at the socket level (Caddy only binds the
// Tailscale IP), but it would make ":8082 on api-01" mean two different
// things depending on which interface you ask, and it would be one
// Caddyfile edit (a move to 0.0.0.0 or a bare :8082 site) away from Caddy
// silently taking the port and the extractor failing to start. :8083 is
// unused on this box; keep it that way for this listener.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"patched.im/api/internal/cpepropose"
	"patched.im/api/internal/db"
	"patched.im/api/internal/extractor"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/notify"
)

const version = "0.1.0"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := loadConfig()

	pool, err := db.Connect(context.Background(), cfg.DatabaseURL)
	if err != nil {
		logger.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	metrics.RegisterExtractor()

	logger.Info("patched-extractor starting",
		"version", version,
		"batch_size", cfg.BatchSize,
		"poll_every", cfg.PollEvery.String(),
		"metrics_listen", cfg.ListenMetrics,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		logger.Info("shutdown signal received")
		cancel()
	}()

	// Loopback-only, same posture as patched-api's internal :8081 listener:
	// scraped locally by Prometheus on this box, never proxied by Caddy or
	// reachable over Tailscale.
	metricsServer := &http.Server{
		Addr:         cfg.ListenMetrics,
		Handler:      promhttp.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	go func() {
		logger.Info("metrics server listening", "addr", cfg.ListenMetrics)
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "err", err)
		}
	}()

	w := &extractor.Worker{
		Pool:      pool,
		Logger:    logger,
		BatchSize: cfg.BatchSize,
		PollEvery: cfg.PollEvery,
		Notifier:  notify.New(),
	}

	// PAT-2138: the CPE mapping proposer runs beside the extraction loop, in
	// its own goroutine, never inside an ingest transaction: it is the only
	// part of this binary that calls out to NVD and the model API.
	proposerDone := make(chan struct{})
	go func() {
		defer close(proposerDone)
		runCPEProposer(ctx, pool, logger)
	}()

	runErr := w.Run(ctx)
	cancel()
	<-proposerDone

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = metricsServer.Shutdown(shutdownCtx)

	if runErr != nil && runErr != context.Canceled {
		logger.Error("worker exited with error", "err", runErr)
		os.Exit(1)
	}
	logger.Info("patched-extractor stopped")
}

// runCPEProposer runs the proposer every CPE_PROPOSER_INTERVAL until ctx is
// cancelled. A failed run is logged and retried on the next tick; it never
// stops extraction. Disabled by CPE_PROPOSER_ENABLED=false, which is logged
// at startup so a disabled proposer is never mistaken for an idle one.
func runCPEProposer(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) {
	rc := cpepropose.LoadConfig(logger)
	log := logger.With("component", "cpe_proposer")
	w := cpepropose.NewWorker(pool, rc, log)
	if !rc.Enabled {
		// Proposing stops (no NVD or model call), but the maintenance sweeps
		// keep running: deleted-mapping reconciliation, the automatic-mapping
		// re-check and expiry must not lapse because proposing is off.
		log.Warn("cpe proposer disabled (CPE_PROPOSER_ENABLED=false): unmapped products are recorded but never proposed; maintenance sweeps still run")
	}
	logModel := rc.Model
	if rc.Provider == cpepropose.ProviderNVIDIA || rc.Provider == cpepropose.ProviderOpenAI {
		logModel = rc.ModelID
	}
	log.Info("cpe proposer starting", "interval", rc.Interval.String(), "batch", rc.Worker.BatchSize,
		"auto_publish", rc.Worker.AutoPublish, "provider", rc.Provider, "model", logModel,
		"model_configured", w.Chooser != nil, "nvd_key_configured", rc.NVDKey != "")
	if w.Chooser == nil && rc.Enabled {
		log.Warn("cpe proposer degraded: no model (ANTHROPIC_API_KEY unset for anthropic, or CPE_MODEL_PROVIDER/CPE_MODEL_API_KEY/CPE_MODEL unset or invalid for nvidia/openai, or CPE_MODEL_ZDR_CONFIRMED not true), every proposal goes to staff review with candidates only",
			"reason", w.NoModelReason)
	}
	ticker := time.NewTicker(rc.Interval)
	defer ticker.Stop()
	for {
		if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			log.Warn("cpe proposer run failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type config struct {
	DatabaseURL   string
	BatchSize     int
	PollEvery     time.Duration
	ListenMetrics string
}

func loadConfig() config {
	return config{
		DatabaseURL:   getenv("DATABASE_URL", ""),
		BatchSize:     getenvInt("EXTRACTOR_BATCH_SIZE", 50),
		PollEvery:     getenvDuration("EXTRACTOR_POLL_EVERY", 5*time.Second),
		ListenMetrics: getenv("LISTEN_METRICS", "127.0.0.1:8083"),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getenvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
