package handlers

// PAT-1316: the go-service compiles every extension-removal scope
// (one_profile, one_user, all_profiles, all_devices) into a literal
// "one_observation" directive before serving it from the live per-device
// GET /v1/agent-config handler (dbGetExtensionRemovalsForDevice, below).
// The updater agent's known-scope set did not include "one_observation",
// so it silently dropped every directive — no log, no health signal, no
// audit event. contracts/extension-removal-scopes.json is now the shared
// vocabulary, duplicated verbatim in Patched-LTD/updater at the same
// relative path (see that file's own note). Neither repo's CI can see the
// other, so this test only closes half the loop: it fails a PR in THIS
// repo if the server starts emitting a scope the contract doesn't list.
// It cannot detect the updater's copy of the contract falling out of sync
// on its own — that drift is still invisible from here.
//
// Deriving "every scope the server can emit" honestly matters more than
// this test passing. Traced by hand (2026-08-13, PAT-1316):
//   - dbGetExtensionRemovals (this file) projects the tenant's requested
//     scope straight from the tenant_extension_removal_requests.scope
//     column (one of the four legacy values, enforced by that table's CHECK
//     constraint) into agentConfigRow.ExtensionRemovals via dbGetAgentConfig.
//   - AgentConfigHandler's newAgentConfigHandler ALWAYS overwrites that
//     value before signing whenever pool != nil (see agent_config.go
//     around line 302): either row.ExtensionRemovals is reset to an empty
//     slice (AppControlEnabled false, or a tenant-wide credential with no
//     deviceID), or it is replaced wholesale by
//     dbGetExtensionRemovalsForDevice's result. pool is nil only in unit
//     tests that stub getFn directly (see newAgentConfigHandler's doc
//     comment) — AgentConfigHandler, the production entry point, always
//     passes a real pool. So dbGetExtensionRemovals's column-sourced scope
//     values never reach a real signed response; only
//     dbGetExtensionRemovalsForDevice's do.
//   - AdminAgentConfigPutHandler's getExistingFn also calls dbGetAgentConfig,
//     but the PUT handler only reads existingRow.Body.RingPromotions /
//     RingPromotionsScoped / UpdateChannel from it — it never reads or
//     re-emits existingRow.ExtensionRemovals.
//
// That leaves dbGetExtensionRemovalsForDevice's SQL as the one and only
// place a scope value is written into an extension_removals[].scope the
// live handler ever serves, and it is a single hardcoded SQL string
// literal ('one_observation'), not a Go constant — there was nothing to
// reference by symbol. TestExtensionRemovalScope_DeviceDirectiveWithinContract
// below parses that literal directly out of the source (go/parser, not a
// second hand-typed copy of the string) so the assertion tracks the actual
// code instead of a guess about it. TestExtensionRemovalScope_NoStrayScopeLiteral
// is a whole-module safety net, mirroring the pattern in
// internal/extractor/no_ring_mutation_test.go, in case a future change adds
// a second production site that hardcodes a scope value some other way.
//
// This is a SUBSET assertion, not equality: the contract deliberately lists
// more scopes than the server currently emits, because the updater agent
// still has to accept the four legacy values on older/in-flight directives.
// Do not "tighten" this into an equality check — that would pass today and
// break the agent's compatibility with anything still using a legacy scope.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// extensionRemovalScopeContract mirrors contracts/extension-removal-scopes.json.
type extensionRemovalScopeContract struct {
	ContractVersion int      `json:"contract_version"`
	Note            string   `json:"note"`
	Scopes          []string `json:"scopes"`
}

func (c extensionRemovalScopeContract) has(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// loadExtensionRemovalScopeContract reads the vendored contract file relative
// to the repo root, the same way other tests in this module locate
// migrations/fixtures relative to their own package directory (see e.g.
// internal/extractor/browser_extensions_test.go, integration/helpers_test.go).
// internal/handlers sits two directories below the go-service module root,
// which itself sits one directory below the repo root that contracts/ lives
// in — hence the three ".." segments.
func loadExtensionRemovalScopeContract(t *testing.T) extensionRemovalScopeContract {
	t.Helper()
	path := filepath.Join("..", "..", "..", "contracts", "extension-removal-scopes.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var c extensionRemovalScopeContract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	if len(c.Scopes) == 0 {
		t.Fatalf("%s has an empty scopes list; contract file is malformed", path)
	}
	return c
}

// TestExtensionRemovalScope_DeviceDirectiveWithinContract parses the actual
// production source of dbGetExtensionRemovalsForDevice (this package,
// agent_config.go) and extracts the literal scope value(s) hardcoded into
// its SQL SELECT list, then asserts each one is a member of the vendored
// contract's scopes list. This is the one function that composes the scope
// field of every extension_removals[] entry the live GET /v1/agent-config
// handler actually serves — see the file-level comment for how that was
// derived. The assertion is structural: it reads the literal out of the
// parsed source rather than re-typing "one_observation" as a second,
// independently-maintained copy, so a future change to the SQL is what this
// test reacts to, not a stale expectation someone forgot to update.
func TestExtensionRemovalScope_DeviceDirectiveWithinContract(t *testing.T) {
	contract := loadExtensionRemovalScopeContract(t)

	fset := token.NewFileSet()
	srcPath := filepath.Join(".", "agent_config.go")
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", srcPath, err)
	}

	var fn *ast.FuncDecl
	for _, decl := range file.Decls {
		if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "dbGetExtensionRemovalsForDevice" {
			fn = fd
		}
	}
	if fn == nil {
		t.Fatalf("dbGetExtensionRemovalsForDevice not found in %s; this test's premise (it is the sole live scope-emission site) needs re-deriving, not just a path fix", srcPath)
	}

	var queryLiterals []string
	ast.Inspect(fn, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Query" || len(call.Args) < 2 {
			return true
		}
		lit, ok := call.Args[1].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		unquoted, err := strconv.Unquote(lit.Value)
		if err != nil {
			t.Fatalf("unquote SQL literal in dbGetExtensionRemovalsForDevice: %v", err)
		}
		queryLiterals = append(queryLiterals, unquoted)
		return true
	})

	if len(queryLiterals) != 1 {
		t.Fatalf("found %d q.Query(...) call(s) with a literal query string in dbGetExtensionRemovalsForDevice; want exactly 1 (the SELECT that projects scope)", len(queryLiterals))
	}

	scopeLiteralRe := regexp.MustCompile(`'([a-z_]+)'`)
	matches := scopeLiteralRe.FindAllStringSubmatch(queryLiterals[0], -1)
	if len(matches) == 0 {
		t.Fatalf("dbGetExtensionRemovalsForDevice's query no longer has a hardcoded scope literal in single quotes; if it now selects a real `scope` column instead of compiling one down, this test needs redesigning (not deleting) to cover the new source of truth — PAT-1316 exists because that compile-down went undetected once already")
	}

	for _, m := range matches {
		scope := m[1]
		if !contract.has(scope) {
			t.Errorf("dbGetExtensionRemovalsForDevice emits scope %q, which is not in contracts/extension-removal-scopes.json's scopes list %v; the updater agent's known-scope set is built from that file (PAT-1316) — anything the server emits outside it is silently dropped with no log, no health signal, no audit event", scope, contract.Scopes)
		}
	}
}

// TestExtensionRemovalScope_NoStrayScopeLiteral is a whole-module safety net
// for the test above, in the same spirit as
// internal/extractor/no_ring_mutation_test.go's second-caller scan: the AST
// test only proves dbGetExtensionRemovalsForDevice's own literal is
// contract-compliant, it can't see a future second production site that
// hardcodes an ExtensionRemovalEntry.Scope some other way (a Go struct
// literal, a different SQL query, a fmt.Sprintf). This greps every
// non-test .go file in the module for that shape and checks any match
// against the contract too. It is a heuristic (regex over source text, not
// a type-aware scan of everywhere an ExtensionRemovalEntry gets built), so
// it can miss a sufficiently indirect construction — see the file-level
// comment for what was actually verified by hand.
func TestExtensionRemovalScope_NoStrayScopeLiteral(t *testing.T) {
	contract := loadExtensionRemovalScopeContract(t)

	moduleRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}

	// Matches a Go struct-literal or assignment form: Scope: "x" / Scope = "x".
	structLiteralRe := regexp.MustCompile(`Scope\s*[:=]\s*"([a-z_]+)"`)

	var offenders []string
	err = filepath.WalkDir(moduleRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range structLiteralRe.FindAllStringSubmatch(string(raw), -1) {
			scope := m[1]
			if !contract.has(scope) {
				offenders = append(offenders, path+": "+scope)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("found hardcoded ExtensionRemovalEntry.Scope literal(s) outside contracts/extension-removal-scopes.json's scopes list %v: %v", contract.Scopes, offenders)
	}
}
