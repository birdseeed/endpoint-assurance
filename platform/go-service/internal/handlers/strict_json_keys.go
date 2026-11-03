package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// decodeStrictJSON decodes body into out (a pointer to a struct) and refuses
// anything a plain json.Decoder would quietly accept:
//
//   - a key that is not exactly one of the struct's json tags at that level,
//     including a case or Unicode-fold variant of a real one ("STATE",
//     "ſtate"). encoding/json matches field names case-insensitively and
//     DisallowUnknownFields uses the same matching, so it does not catch
//     these (PAT-2021, AGENTS.md);
//   - a duplicate key, where encoding/json silently keeps the last copy;
//   - trailing content after the object.
//
// The walk runs over the raw bytes against the Go type before the real
// decode, at every nesting level the decoder would descend into.
func decodeStrictJSON(body []byte, out any) error {
	rt := reflect.TypeOf(out)
	if rt == nil || rt.Kind() != reflect.Pointer {
		return errors.New("decodeStrictJSON: out must be a pointer")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := walkExactKeys(dec, rt.Elem(), "body"); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("body: unexpected content after the JSON object")
	}

	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(out); err != nil {
		return fmt.Errorf("body: %w", err)
	}
	return nil
}

func exactJSONFields(t reflect.Type) map[string]reflect.Type {
	fields := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fields[name] = f.Type
	}
	return fields
}

// walkExactKeys consumes exactly one JSON value from dec. t is the Go type
// the value decodes into, or nil when the value is not inspected further.
func walkExactKeys(dec *json.Decoder, t reflect.Type, path string) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%s: malformed JSON", path)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '[':
		var elem reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if err := walkExactKeys(dec, elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	case '{':
		var fields map[string]reflect.Type
		if t != nil && t.Kind() == reflect.Struct {
			fields = exactJSONFields(t)
		}
		seen := map[string]bool{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return fmt.Errorf("%s: malformed JSON", path)
			}
			key, _ := kt.(string)
			if seen[key] {
				return fmt.Errorf("%s: duplicate key %q", path, key)
			}
			seen[key] = true
			var next reflect.Type
			if fields != nil {
				ft, ok := fields[key]
				if !ok {
					return fmt.Errorf("%s: unknown key %q", path, key)
				}
				next = ft
			}
			if err := walkExactKeys(dec, next, path+"."+key); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}
