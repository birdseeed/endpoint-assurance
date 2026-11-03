package metrics

// PAT-1417 review Fix 2: deviceCredentialRequiredHandlers (metrics.go) is a
// hand-maintained list that Register() trusts to pre-materialize every
// "handler" label DeviceCredentialRequiredTotal can take. A list that drifts
// from the real call sites reproduces the exact dead-series bug this whole
// change exists to prevent (PAT-1377): a sixth LookupDeviceByBearer caller
// added without updating the list gets no zero-valued series until its first
// rejection, so an alert keyed on it is structurally unable to fire until the
// event it exists to catch has already happened once. This test does not
// trust the comment on deviceCredentialRequiredHandlers; it statically
// extracts every label value that can actually reach
// DeviceCredentialRequiredTotal from the production handlers package and
// asserts the two sets are exactly equal, in both directions:
//   - a handler label used by real code but missing from the list (the
//     dead-series bug above), and
//   - a list entry no real call site uses anymore (masks a removed handler,
//     the mirror-image staleness bug).
//
// Two label sources exist in that package today: a literal argument directly
// at a "*.DeviceCredentialRequiredTotal.WithLabelValues(...)" call site
// (enforcement_audit.go, agent_logs.go, agent_decommission.go), and a literal
// passed one level removed through a shared helper's parameter
// (device_removals_agent.go's authenticateRemovalAgent, dismissed for a
// derive-from-endpointID rewrite in the PAT-1417 review specifically because
// this test is the thing that catches drift there instead). This scan
// resolves both shapes generically, by parameter position, rather than
// special-casing that one helper's name — so it also catches drift if a
// future helper introduces the same one-hop pattern.
//
// Only non-test .go files are scanned: _test.go files never ship, so a label
// literal that only exists in a test (as this package's own
// TestRegisterPreMaterializesDeviceCredentialRequiredHandlers does, and
// enforcement_audit_test.go's wire-unchanged test does) proves nothing about
// what a running binary can actually increment.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const handlersPkgDir = "../handlers"

func TestDeviceCredentialRequiredHandlersMatchesCallSites(t *testing.T) {
	found := scanDeviceCredentialRequiredLabels(t, handlersPkgDir)

	want := make(map[string]bool, len(deviceCredentialRequiredHandlers))
	for _, h := range deviceCredentialRequiredHandlers {
		want[h] = true
	}

	// missingFromList: a real call site's label that deviceCredentialRequiredHandlers
	// does not know about — this label gets no pre-materialized zero series
	// (the PAT-1377 dead-series bug, reintroduced through this list drifting).
	// staleInList: a deviceCredentialRequiredHandlers entry no real call site
	// uses anymore — masks a removed/renamed handler (the mirror-image bug).
	var missingFromList, staleInList []string
	for h := range found {
		if !want[h] {
			missingFromList = append(missingFromList, h)
		}
	}
	for h := range want {
		if !found[h] {
			staleInList = append(staleInList, h)
		}
	}
	sort.Strings(missingFromList)
	sort.Strings(staleInList)

	if len(missingFromList) > 0 {
		t.Errorf("deviceCredentialRequiredHandlers is missing label(s) that %s actually uses "+
			"(these get no pre-materialized zero series, reproducing the PAT-1377 dead-series bug): %v",
			handlersPkgDir, missingFromList)
	}
	if len(staleInList) > 0 {
		t.Errorf("deviceCredentialRequiredHandlers has label(s) no call site in %s uses anymore "+
			"(stale entry masking a removed/renamed handler): %v",
			handlersPkgDir, staleInList)
	}
}

// scanDeviceCredentialRequiredLabels statically extracts every label value
// that can reach DeviceCredentialRequiredTotal.WithLabelValues from the
// non-test .go files in dir. It resolves two shapes:
//
//  1. A string literal directly at the WithLabelValues call.
//  2. A string literal passed to a helper function, at the same positional
//     argument the helper itself forwards into WithLabelValues — resolved by
//     finding every call site of that helper in the package.
//
// Anything it cannot resolve statically (a WithLabelValues argument that is
// neither a literal nor a plain parameter reference, or a call to a resolved
// helper that passes a non-literal at the label-bearing position) is a test
// failure in its own right: a label source this test cannot see is exactly
// the kind of thing that lets deviceCredentialRequiredHandlers drift silently.
func scanDeviceCredentialRequiredLabels(t *testing.T, dir string) map[string]bool {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatalf("no non-test .go files found in %s; scan is misconfigured", dir)
	}

	found := map[string]bool{}

	// A label source one hop away through a helper parameter: the helper's
	// name and the zero-based index of the parameter that flows into
	// WithLabelValues.
	type paramSource struct {
		funcName string
		argIdx   int
	}
	var pending []paramSource

	for _, f := range files {
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "WithLabelValues" {
					return true
				}
				recv, ok := sel.X.(*ast.SelectorExpr)
				if !ok || recv.Sel.Name != "DeviceCredentialRequiredTotal" {
					return true
				}
				if len(call.Args) != 1 {
					t.Fatalf("%s: DeviceCredentialRequiredTotal.WithLabelValues must take exactly one arg, got %d",
						fset.Position(call.Pos()), len(call.Args))
				}
				switch arg := call.Args[0].(type) {
				case *ast.BasicLit:
					if arg.Kind != token.STRING {
						t.Fatalf("%s: WithLabelValues literal arg is not a string", fset.Position(arg.Pos()))
					}
					v, err := strconv.Unquote(arg.Value)
					if err != nil {
						t.Fatalf("%s: unquote label literal: %v", fset.Position(arg.Pos()), err)
					}
					found[v] = true
				case *ast.Ident:
					idx := funcParamIndex(fn, arg.Name)
					if idx < 0 {
						t.Fatalf("%s: WithLabelValues arg %q in func %s is not one of its own parameters; "+
							"cannot statically resolve where this label comes from",
							fset.Position(arg.Pos()), arg.Name, fn.Name.Name)
					}
					pending = append(pending, paramSource{funcName: fn.Name.Name, argIdx: idx})
				default:
					t.Fatalf("%s: WithLabelValues arg is neither a string literal nor a simple identifier; "+
						"cannot statically resolve this label source", fset.Position(call.Pos()))
				}
				return true
			})
		}
	}

	// Resolve each one-hop parameter source by finding every call site of
	// that function in the package and reading the literal at the same
	// argument position.
	for _, src := range pending {
		resolvedAny := false
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != src.funcName {
					return true
				}
				if src.argIdx >= len(call.Args) {
					return true
				}
				lit, ok := call.Args[src.argIdx].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s: call to %s passes a non-literal at the label-bearing argument position (%d); "+
						"cannot statically resolve this label source",
						fset.Position(call.Pos()), src.funcName, src.argIdx)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: unquote label literal: %v", fset.Position(lit.Pos()), err)
				}
				found[v] = true
				resolvedAny = true
				return true
			})
		}
		if !resolvedAny {
			t.Fatalf("no call site of %s found to resolve its label-bearing parameter (index %d)",
				src.funcName, src.argIdx)
		}
	}

	return found
}

// funcParamIndex returns the zero-based positional index of parameter name
// within fn's parameter list, or -1 if fn has no parameter by that name.
func funcParamIndex(fn *ast.FuncDecl, name string) int {
	idx := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			// Unnamed parameter (e.g. an interface method signature) — still
			// occupies a positional slot.
			idx++
			continue
		}
		for _, n := range field.Names {
			if n.Name == name {
				return idx
			}
			idx++
		}
	}
	return -1
}
