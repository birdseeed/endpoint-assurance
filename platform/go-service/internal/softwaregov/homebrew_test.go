package softwaregov

import "testing"

// PAT-2058: bringing Homebrew formulae and casks into the software approval
// model. These are pure-function tests for the identity/key layer; the
// resolver and write-path integration are covered by DB-backed and
// integration tests (internal/handlers, integration/).

func TestNormalizeHomebrewTapCollapsesDefaultTap(t *testing.T) {
	cases := []struct {
		kind, tap, want string
	}{
		{"formula", "", ""},
		{"formula", "homebrew/core", ""},
		{"formula", "Homebrew/Core", ""},
		{"formula", "  homebrew/core  ", ""},
		{"formula", "acme/tools", "acme/tools"},
		{"cask", "", ""},
		{"cask", "homebrew/cask", ""},
		{"cask", "homebrew/core", "homebrew/core"}, // a formula's default is not a cask's default
		{"cask", "acme/tools", "acme/tools"},
	}
	for _, c := range cases {
		if got := NormalizeHomebrewTap(c.kind, c.tap); got != c.want {
			t.Errorf("NormalizeHomebrewTap(%q, %q) = %q, want %q", c.kind, c.tap, got, c.want)
		}
	}
}

func TestHomebrewFormulaKeyTapQualifiesOnlyWhenNotDefault(t *testing.T) {
	cases := []struct {
		name, tap, want string
	}{
		{"openssl@3", "homebrew/core", "homebrew:formula:openssl@3"},
		{"openssl@3", "", "homebrew:formula:openssl@3"},
		{"OpenSSL@3", "", "homebrew:formula:openssl@3"}, // name is lower-cased
		{"acme-cli", "acme/tools", "homebrew:formula:acme/tools/acme-cli"},
	}
	for _, c := range cases {
		if got := HomebrewFormulaKey(c.name, c.tap); got != c.want {
			t.Errorf("HomebrewFormulaKey(%q, %q) = %q, want %q", c.name, c.tap, got, c.want)
		}
	}
}

func TestHomebrewCaskKeyTapQualifiesOnlyWhenNotDefault(t *testing.T) {
	cases := []struct {
		name, tap, want string
	}{
		{"firefox", "homebrew/cask", "homebrew:cask:firefox"},
		{"firefox", "", "homebrew:cask:firefox"},
		{"acme-app", "acme/tools", "homebrew:cask:acme/tools/acme-app"},
	}
	for _, c := range cases {
		if got := HomebrewCaskKey(c.name, c.tap); got != c.want {
			t.Errorf("HomebrewCaskKey(%q, %q) = %q, want %q", c.name, c.tap, got, c.want)
		}
	}
}

// Two formulae of the same name in different taps must never collide -- the
// whole point of tap-qualifying a non-default tap (AGENTS.md "identity is
// not packaging").
func TestHomebrewFormulaKeyDistinguishesThirdPartyTaps(t *testing.T) {
	a := HomebrewFormulaKey("acme-cli", "acme/tools")
	b := HomebrewFormulaKey("acme-cli", "other/tools")
	if a == b {
		t.Fatalf("same-named formula in two different taps produced the same key: %q", a)
	}
}

func TestObservationPolicyIdentityIsExactAndAllowlisted(t *testing.T) {
	if !ObservationPolicyKind("mcp_server") || ObservationPolicyKind("mcp_server_unnamed") || ObservationPolicyKind("homebrew_formula") {
		t.Fatal("observation policy kind allowlist is not exact")
	}
	a := ObservationKey("npm_package", "@scope/tool", "registry.example")
	b := ObservationKey("npm_package", "@scope/tool", "registry.other")
	if a == b {
		t.Fatalf("different observation sources collided: %q", a)
	}
	p := policies{observations: map[string]observationPolicyRow{
		observationPolicyKey("npm_package", "@scope/tool", "registry.example"): {policy: "unapproved"},
	}}
	if state, _ := p.resolveObservation("npm_package", "@scope/tool", "registry.example"); state != StateUnapproved {
		t.Fatalf("exact observation policy = %q, want unapproved", state)
	}
	if state, _ := p.resolveObservation("npm_package", "@scope/tool", "registry.other"); state != StateUnreviewed {
		t.Fatalf("different source resolved policy: %q", state)
	}
	if state, _ := p.resolveObservation("npm_package_unidentified", "@scope/tool", "registry.example"); state != StateUnreviewed {
		t.Fatalf("unidentified kind resolved policy: %q", state)
	}
}

// homebrewPolicies builds a policies value holding one homebrew row, keyed
// the same way loadPolicies does.
func homebrewPolicies(kind, name, tap, policy string) policies {
	row := homebrewPolicyRow{kind: kind, name: name, tap: tap, policy: policy}
	return policies{homebrew: map[string]homebrewPolicyRow{homebrewPolicyKey(kind, name, tap): row}}
}

// TestResolveHomebrewNoRowIsUnreviewed: an identity with no policy row at
// all resolves to unreviewed and no row.
func TestResolveHomebrewNoRowIsUnreviewed(t *testing.T) {
	p := policies{homebrew: map[string]homebrewPolicyRow{}}
	state, row := p.resolveHomebrew("formula", "openssl@3", "")
	if state != StateUnreviewed || row != nil {
		t.Fatalf("state=%q row=%v, want unreviewed/nil", state, row)
	}
}

// TestResolveHomebrewPolicyMapping covers every stored policy value's
// mapping into the portal's approval-state vocabulary, the same mapping
// AppPolicyState already gives applications.
func TestResolveHomebrewPolicyMapping(t *testing.T) {
	cases := []struct {
		storedPolicy, wantState string
	}{
		{"approved", StateApproved},
		{"unapproved", StateUnapproved},
		{"unmanaged", StateIgnored}, // portal "ignored" stores as "unmanaged"
	}
	for _, c := range cases {
		t.Run(c.storedPolicy, func(t *testing.T) {
			p := homebrewPolicies("formula", "openssl@3", "", c.storedPolicy)
			state, row := p.resolveHomebrew("formula", "openssl@3", "")
			if state != c.wantState {
				t.Fatalf("state = %q, want %q", state, c.wantState)
			}
			if row == nil || row.policy != c.storedPolicy {
				t.Fatalf("row = %+v", row)
			}
		})
	}
}

// TestResolveHomebrewTapMatching: a row stored under the default-tap bucket
// (”) matches a lookup with no tap, an empty tap and the package's own
// explicit default tap alike, but never a custom tap -- and the reverse,
// a row stored under a custom tap matches only that exact tap, never the
// default bucket or a different custom tap. This is the exact identity
// discipline PAT-2058 uses for product_key qualification, exercised here at
// the resolver.
func TestResolveHomebrewTapMatching(t *testing.T) {
	t.Run("default tap bucket matches no-tap, empty-tap and explicit-default-tap lookups", func(t *testing.T) {
		p := homebrewPolicies("formula", "openssl@3", "", "approved")
		for _, lookupTap := range []string{"", "homebrew/core", "  homebrew/core  ", "Homebrew/Core"} {
			state, row := p.resolveHomebrew("formula", "openssl@3", lookupTap)
			if state != StateApproved || row == nil {
				t.Fatalf("lookup tap %q: state=%q row=%v, want approved", lookupTap, state, row)
			}
		}
		// A custom tap must not match the default-tap row.
		if state, row := p.resolveHomebrew("formula", "openssl@3", "acme/tools"); state != StateUnreviewed || row != nil {
			t.Fatalf("custom tap matched the default-tap row: state=%q row=%v", state, row)
		}
	})

	t.Run("cask default tap differs from formula default tap", func(t *testing.T) {
		// A cask's default is homebrew/cask, not homebrew/core: storing a
		// cask under an explicit homebrew/core tap must NOT collapse to the
		// default bucket, so it must not match a no-tap lookup.
		p := homebrewPolicies("cask", "firefox", "homebrew/core", "approved")
		if state, row := p.resolveHomebrew("cask", "firefox", ""); state != StateUnreviewed || row != nil {
			t.Fatalf("cask stored under homebrew/core matched a no-tap lookup: state=%q row=%v", state, row)
		}
		if state, row := p.resolveHomebrew("cask", "firefox", "homebrew/core"); state != StateApproved || row == nil {
			t.Fatalf("cask stored under homebrew/core did not match an explicit homebrew/core lookup: state=%q row=%v", state, row)
		}
	})

	t.Run("custom tap matches only itself", func(t *testing.T) {
		p := homebrewPolicies("formula", "acme-cli", "acme/tools", "unapproved")
		state, row := p.resolveHomebrew("formula", "acme-cli", "acme/tools")
		if state != StateUnapproved || row == nil {
			t.Fatalf("exact custom-tap lookup failed: state=%q row=%v", state, row)
		}
		for _, lookupTap := range []string{"", "homebrew/core", "other/tools"} {
			if state, row := p.resolveHomebrew("formula", "acme-cli", lookupTap); state != StateUnreviewed || row != nil {
				t.Fatalf("lookup tap %q wrongly matched a different tap's row: state=%q row=%v", lookupTap, state, row)
			}
		}
	})

	t.Run("kind is part of the identity: a formula and a cask of the same name never collide", func(t *testing.T) {
		p := homebrewPolicies("formula", "same-name", "", "approved")
		if state, row := p.resolveHomebrew("cask", "same-name", ""); state != StateUnreviewed || row != nil {
			t.Fatalf("cask lookup matched a formula's policy row: state=%q row=%v", state, row)
		}
	})
}
