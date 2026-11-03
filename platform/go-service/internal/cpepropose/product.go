package cpepropose

import (
	"regexp"
	"strings"
)

// ProductMatches is the gate's deterministic product-level corroboration
// (PAT-2138 security review, P1). The signer check pins the vendor only; a
// model steered by endpoint-reported text could still pick the wrong
// product under the right vendor (microsoft:office for "Microsoft Edge").
// This rule, outside the model, requires the chosen CPE product to name the
// installed product, by word tokens, in both directions:
//
//	name tokens     the normalised product name split on every character
//	                that is not a lower-case letter, a digit or "+" ("visual
//	                studio code" -> visual, studio, code; "node.js" -> node,
//	                js; "notepad++" -> notepad++, which is not "notepad").
//	product tokens  the CPE product split the same way, after NVD's
//	                backslash escapes are dropped ("visual_studio_code" ->
//	                visual, studio, code; "notepad\+\+" -> notepad++).
//	vendor tokens   the CPE vendor split the same way.
//
// Tokens that carry no identity are dropped from both sides before
// comparing: stop words (the, for, and, of), version-like tokens ("2024",
// "v3", "12.1" is already split), and architecture or platform words (x64,
// x86, arm64, amd64, bit, mac, macos, osx, win, windows). On the CPE side
// only, "browser" and "client" are dropped too: NVD names some products
// "opera_browser" or "zoom_client" where the installed name is "Opera" or
// "Zoom", and dropping them there can never let a name match a different
// product, only a more specific name of the same one. They are NOT dropped
// from the installed name, so "Docker Desktop" never matches docker:docker.
//
// The pair matches only when ALL of:
//
//  1. at least one product token remains, and at least one name token
//     remains;
//  2. every product token is a name token or a vendor token (the CPE product
//     is named by the installed name: microsoft:office is refused for
//     "Microsoft Edge");
//  3. every name token is a product token or a vendor token (the installed
//     name says nothing the CPE product does not: zoom:zoom is refused for
//     "Zoom Helper", microsoft:visual_studio for "Visual Studio Code");
//  4. at least one name token is a product token (a name made only of the
//     vendor's name never matches one of its products);
//  5. every version-like token of the CPE product ("7" in 7-zip) appears in
//     the installed name itself; the vendor never supplies it ("Zip" is
//     refused for 7-zip:7-zip, "7-Zip 26.03" is accepted).
//
// One special case: a name that is a single domain-shaped token ("zoom.us",
// the macOS Zoom client's bundle name) is read as its first label ("zoom").
//
// The rule is deliberately conservative: a correct pair it refuses only goes
// to staff review (product_name_mismatch), it never publishes. Measured
// against the 46 curated app_name mappings on patched-api-01 (2026-09-25),
// see TestProductMatchesCuratedProdPairs for the accepted and refused pairs.
func ProductMatches(normalizedName, vendor, product string) bool {
	nameRaw := domainName(normalizedName)
	name := significantTokens(nameRaw, false)
	allName := map[string]bool{}
	for _, t := range cpeTokens(nameRaw) {
		allName[t] = true
	}
	prod := significantTokens(unescapeCPE(product), true)
	vend := map[string]bool{}
	for _, t := range cpeTokens(unescapeCPE(vendor)) {
		vend[t] = true
	}
	if len(name) == 0 || len(prod) == 0 {
		return false
	}
	// A version-like token in the CPE product ("7" in 7-zip) is part of its
	// identity: only the installed name can supply it, never the vendor, so
	// "Zip" is refused for 7-zip:7-zip.
	for _, t := range cpeTokens(unescapeCPE(product)) {
		if versionToken.MatchString(t) && !allName[t] {
			return false
		}
	}
	nameSet := map[string]bool{}
	for _, t := range name {
		nameSet[t] = true
	}
	prodSet := map[string]bool{}
	for _, t := range prod {
		prodSet[t] = true
	}
	for _, t := range prod {
		if !nameSet[t] && !vend[t] {
			return false
		}
	}
	direct := false
	for _, t := range name {
		switch {
		case prodSet[t]:
			direct = true
		case vend[t]:
		default:
			return false
		}
	}
	return direct
}

var (
	// "+" is kept inside a token, so "notepad++" and "notepad" differ.
	cpeTokenSplit = regexp.MustCompile(`[^a-z0-9+]+`)
	hasAlnum      = regexp.MustCompile(`[a-z0-9]`)
	versionToken  = regexp.MustCompile(`^v?\d+[a-z]?$`)
	domainShaped  = regexp.MustCompile(`^([a-z0-9][a-z0-9-]*)\.(us|com|io|app|net|org|co)$`)
)

// noiseTokens carry no product identity on either side.
var noiseTokens = map[string]bool{
	"the": true, "for": true, "and": true, "of": true,
	"x64": true, "x86": true, "arm64": true, "amd64": true, "bit": true,
	"mac": true, "macos": true, "osx": true, "win": true, "windows": true,
}

// cpeOnlyNoise is dropped from the CPE product only (see ProductMatches).
var cpeOnlyNoise = map[string]bool{"browser": true, "client": true}

func cpeTokens(s string) []string {
	var out []string
	for _, t := range cpeTokenSplit.Split(strings.ToLower(s), -1) {
		if hasAlnum.MatchString(t) {
			out = append(out, t)
		}
	}
	return out
}

func significantTokens(s string, cpeSide bool) []string {
	var out []string
	for _, t := range cpeTokens(s) {
		if noiseTokens[t] || versionToken.MatchString(t) || (cpeSide && cpeOnlyNoise[t]) {
			continue
		}
		out = append(out, t)
	}
	return out
}

func unescapeCPE(s string) string { return strings.ReplaceAll(s, `\`, "") }

func domainName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	if m := domainShaped.FindStringSubmatch(n); m != nil {
		return m[1]
	}
	return n
}
