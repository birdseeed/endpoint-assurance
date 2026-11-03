package extractor

// Retained legacy rollout automation is permanently quarantined. The AST scan
// catches a future production caller even if it is added outside Worker.Run.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSchedulerDoesNotCallLegacyRolloutAutomation(t *testing.T) {
	fset := token.NewFileSet()
	path := filepath.Join(".", "extractor.go")
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	var found []string
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if ok {
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if ok {
				pkgIdent, ok := sel.X.(*ast.Ident)
				if ok && pkgIdent.Name == "rings" && sel.Sel.Name == "ObserveNewVersions" {
					found = append(found, fset.Position(call.Pos()).String())
				}
			}
		}
		return true
	})

	if len(found) != 0 {
		t.Fatalf("found %d calls to rings.ObserveNewVersions in extractor.go: %v; want none", len(found), found)
	}
}

func TestSchedulerGatesAutomaticLegacyRollouts(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	if (&Worker{}).shouldRunLegacyRingTick(now) {
		t.Fatal("extractor must never observe, advance, or publish legacy rollouts")
	}
}

// TestObserveNewVersionsHasNoProductionCaller checks the entire module, not
// only the extractor scheduler.
func TestObserveNewVersionsHasNoProductionCaller(t *testing.T) {
	moduleRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}

	var matches []string
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
		if strings.Contains(string(raw), "rings.ObserveNewVersions") {
			matches = append(matches, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module: %v", err)
	}

	if len(matches) != 0 {
		t.Fatalf("rings.ObserveNewVersions mentioned in non-test file(s): %v; want none", matches)
	}
}
