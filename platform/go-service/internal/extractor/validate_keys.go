package extractor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// PAT-2021 review P1: the validator reads the payload as a map with exact
// keys, but the extractor decodes the stored body into the payload struct,
// and encoding/json matches a struct field case-insensitively, Unicode
// folds included ("MCP_SERVERS" and "mcp_ſervers" both fill McpServers). A
// key that differs from a field only by case or folding would therefore skip
// every exact-key check, the MCP privacy guard included, and still be
// ingested. checkPayloadKeys walks the raw body alongside the payload type,
// before anything else runs, and rejects such a key at every level the
// struct decoder reads.
//
// Unknown keys that fold to no field stay accepted: the decoder ignores them,
// fixtures carry "_comment", and the Windows agent sends a top-level
// "installation_evidence" summary (with PAT-2116's "coverage" member), which
// has no field (apps[].installation_evidence is decoded since PAT-2113, and
// PAT-2116's signer_thumbprint, issuer, root_thumbprint, root_kind and
// executable_resolution are fields of it, so their fold variants are
// rejected like any other). Rejecting every unknown top-level key would 400
// those devices.
//
// Duplicate keys are rejected at the top level for the strictly validated
// blocks and anywhere inside them: the validator's map keeps the last copy
// while the struct decoder merges both into one value.

var strictBlockKeys = map[string]bool{
	"homebrew": true, "ide_extensions": true, "package_managers": true,
	"local_models": true, "mcp_servers": true, "browser_extensions_status": true,
	// PAT-2262: a second firmware object must not smuggle a status or value
	// past the validator, which only sees the last copy.
	"firmware": true,
	// PAT-2263: a second kernel_drivers object must not smuggle a hash or an
	// enforcement value past the validator, which only sees the last copy.
	"kernel_drivers": true,
	// PAT-2063: collection_status.apps grants or withholds application
	// absence authority (and, PAT-2067, safari_extensions grants Safari
	// extension absence authority), so a second collection_status object must not be
	// able to smuggle a value past the validator, which only sees the last.
	"collection_status": true,
}

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// foldKey mirrors encoding/json's case-insensitive field matching: ASCII
// letters upper-cased, every other rune replaced by the smallest rune of its
// Unicode simple-fold orbit (so "ſ" matches "s" and "K" (Kelvin) "k").
func foldKey(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		case r >= utf8.RuneSelf:
			for {
				r2 := unicode.SimpleFold(r)
				if r2 <= r {
					r = r2
					break
				}
				r = r2
			}
		}
		b.WriteRune(r)
	}
	return b.String()
}

type structKeys struct {
	exact map[string]reflect.Type
	fold  map[string]string // folded -> exact tag
}

var structKeysCache sync.Map // reflect.Type -> *structKeys

func keysFor(t reflect.Type) *structKeys {
	if v, ok := structKeysCache.Load(t); ok {
		return v.(*structKeys)
	}
	sk := &structKeys{exact: map[string]reflect.Type{}, fold: map[string]string{}}
	var walk func(rt reflect.Type)
	walk = func(rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			tag := f.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "-" && !strings.Contains(tag, ",") {
				continue
			}
			if f.Anonymous && name == "" {
				ft := f.Type
				if ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if ft.Kind() == reflect.Struct {
					walk(ft)
					continue
				}
			}
			if !f.IsExported() {
				continue
			}
			if name == "" {
				name = f.Name
			}
			sk.exact[name] = f.Type
			sk.fold[foldKey(name)] = name
		}
	}
	walk(t)
	structKeysCache.Store(t, sk)
	return sk
}

// decodedType strips pointers and reports whether the decoder descends into
// t field by field (false for json.Unmarshaler implementations and
// interfaces, which decode on their own terms).
func decodedType(t reflect.Type) (reflect.Type, bool) {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || t.Kind() == reflect.Interface {
		return nil, false
	}
	if t.Implements(jsonUnmarshalerType) || reflect.PointerTo(t).Implements(jsonUnmarshalerType) {
		return nil, false
	}
	return t, true
}

type keyWalker struct {
	dec *json.Decoder
}

type keyErr struct {
	path  string
	msg   string
	mcp   bool
	class string
}

func (e *keyErr) err() error {
	if e.mcp {
		return &MCPPrivacyGuardError{Entries: 1, Classes: map[string]int{e.class: 1}}
	}
	return fmt.Errorf("%s: %s", e.path, e.msg)
}

// checkPayloadKeys is the review P1 gate. See the file comment.
func checkPayloadKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	w := keyWalker{dec: dec}
	if ke := w.value(reflect.TypeOf(payload{}), "payload", 0, false); ke != nil {
		return ke.err()
	}
	return nil
}

// value reads one JSON value typed as t (nil when the decoder does not look
// inside it). depth 0 is the payload object. strict marks the inside of a
// strictly validated block; mcp the inside of mcp_servers.
func (w keyWalker) value(t reflect.Type, path string, depth int, strict bool) *keyErr {
	mcp := strings.HasPrefix(path, "mcp_servers")
	tok, err := w.dec.Token()
	if err != nil {
		return &keyErr{path: path, msg: "malformed JSON"}
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	dt, descend := decodedType(t)
	switch delim {
	case '[':
		var elem reflect.Type
		if descend && (dt.Kind() == reflect.Slice || dt.Kind() == reflect.Array) {
			elem = dt.Elem()
		}
		for i := 0; w.dec.More(); i++ {
			if ke := w.value(elem, fmt.Sprintf("%s[%d]", path, i), depth+1, strict); ke != nil {
				return ke
			}
		}
		_, _ = w.dec.Token()
		return nil
	case '{':
		var sk *structKeys
		var mapElem reflect.Type
		if descend {
			switch dt.Kind() {
			case reflect.Struct:
				sk = keysFor(dt)
			case reflect.Map:
				mapElem = dt.Elem()
			}
		}
		seen := map[string]bool{}
		for w.dec.More() {
			kt, err := w.dec.Token()
			if err != nil {
				return &keyErr{path: path, msg: "malformed JSON"}
			}
			key, _ := kt.(string)
			childStrict := strict || (depth == 0 && strictBlockKeys[key])
			if seen[key] && (strict || (depth == 0 && strictBlockKeys[key])) {
				return &keyErr{path: path, msg: "duplicate key", mcp: mcp || key == "mcp_servers", class: "duplicate_key"}
			}
			seen[key] = true
			var child reflect.Type
			childPath := path + ".?"
			switch {
			case sk != nil:
				if ft, ok := sk.exact[key]; ok {
					child = ft
					childPath = key
					if depth > 0 {
						childPath = path + "." + key
					}
				} else if canonical, ok := sk.fold[foldKey(key)]; ok {
					where := canonical
					if depth > 0 {
						where = path + "." + canonical
					}
					return &keyErr{
						path:  where,
						msg:   "a key that differs from this field only by case or Unicode folding is not allowed",
						mcp:   mcp || (depth == 0 && canonical == "mcp_servers"),
						class: "case_variant_key",
					}
				}
			case mapElem != nil:
				child = mapElem
				childPath = path + "." + key
				if mcp {
					childPath = path + ".*"
				}
			}
			if ke := w.value(child, childPath, depth+1, childStrict); ke != nil {
				return ke
			}
		}
		_, _ = w.dec.Token()
	}
	return nil
}
