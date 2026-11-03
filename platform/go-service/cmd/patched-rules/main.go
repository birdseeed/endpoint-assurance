// Package main is the patched.im rule-pack management CLI.
//
// Usage:
//
//	patched-rules import [--dry-run] <pack.yaml>
//
// Configuration is via environment variables:
//
//	DATABASE_URL — PostgreSQL connection string (required for import)
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"patched.im/api/internal/db"
	"patched.im/api/internal/rulepack"
)

const version = "0.1.0"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: patched-rules <command> [flags]\n\ncommands:\n  import [--dry-run] <pack.yaml>\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "import":
		runImport(logger, os.Args[2:])
	case "--version", "-version", "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "patched-rules: unknown command %q\n\ncommands:\n  import [--dry-run] <pack.yaml>\n", os.Args[1])
		os.Exit(1)
	}
}

func runImport(logger *slog.Logger, args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "validate and report planned changes without writing to the database")
	fs.Parse(args) //nolint:errcheck

	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: patched-rules import [--dry-run] <pack.yaml>\n")
		os.Exit(1)
	}
	packPath := fs.Arg(0)

	pack, err := rulepack.LoadPack(packPath)
	if err != nil {
		logger.Error("failed to load pack", "path", packPath, "err", err)
		os.Exit(1)
	}

	logger.Info("pack loaded",
		"benchmark", pack.Benchmark,
		"version", pack.BenchmarkVersion,
		"platform", pack.Platform,
		"rules", len(pack.Rules),
	)

	if errs := rulepack.Validate(pack); len(errs) > 0 {
		for _, e := range errs {
			logger.Error("validation", "error", e)
		}
		logger.Error("validation failed", "error_count", len(errs))
		os.Exit(1)
	}
	logger.Info("validation passed")

	pool, err := db.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		logger.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	result, err := rulepack.Import(context.Background(), pool, pack, *dryRun)
	if err != nil {
		logger.Error("import failed", "err", err)
		os.Exit(1)
	}

	for _, r := range result.Rules {
		logger.Info("rule", "action", r.Action, "rule_key", r.RuleKey)
	}

	if *dryRun {
		logger.Info("dry-run complete — no changes written",
			"would_insert", result.Inserted,
			"would_update", result.Updated,
		)
	} else {
		logger.Info("import complete",
			"inserted", result.Inserted,
			"updated", result.Updated,
		)
	}
}
