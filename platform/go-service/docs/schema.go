// Package docs embeds the canonical /v1/inventory payload contract so server
// code can consume it mechanically instead of hand-mirroring its contents.
//
// This package exists because go:embed cannot traverse ".." — the schema file
// lives here, so the embed directive must too (PAT-913 gate round 4). It
// deliberately exports raw bytes only: parsing and interpretation belong to
// the consumers (internal/extractor derives the finding-control enum from it
// at init).
package docs

import _ "embed"

// PayloadSchemaJSON is docs/payload.schema.json — the authoritative wire
// contract for POST /v1/inventory — embedded verbatim at compile time. The
// binary can never disagree with the schema file it was built from.
//
//go:embed payload.schema.json
var PayloadSchemaJSON []byte
