package packagemetadata

import (
	"reflect"
	"strings"
	"testing"
)

// untypedFieldAllowlist holds package metadata fields that are allowed to carry untyped (interface) values.
// Values in these fields come straight from whatever a parser decoded, so they are not shaped by syft
// and can hold anything an encoder or hasher chokes on. Every entry is part of existing SBOM output and
// cannot be retyped without breaking it; new entries need a reason and a review.
var untypedFieldAllowlist = map[string]string{
	"GGUFFileHeader.RemainingKeyValues": "raw GGUF header key-values; retyping changes the header output and metadataHash",
}

// TestNoUntypedMetadataFields fails when a package metadata type gains a field typed any, []any,
// map[string]any (or any other interface) that is not on the allowlist.
func TestNoUntypedMetadataFields(t *testing.T) {
	var hits []string
	for _, ty := range AllTypes() {
		rt := reflect.TypeOf(ty)
		collectUntyped(rt, rt.Name(), map[reflect.Type]bool{}, &hits)
	}

	seen := map[string]bool{}
	for _, h := range hits {
		seen[h] = true
		if _, ok := untypedFieldAllowlist[h]; !ok {
			t.Errorf("untyped field %s: use a concrete type, or add it to untypedFieldAllowlist with a reason", h)
		}
	}
	for k := range untypedFieldAllowlist {
		if !seen[k] {
			t.Errorf("stale untypedFieldAllowlist entry %s: field no longer exists or is now typed", k)
		}
	}
}

// collectUntyped records "Struct.Field" for every field whose type reaches an interface, descending
// through pointers, slices, arrays, maps and nested syft-owned structs.
func collectUntyped(rt reflect.Type, path string, visited map[reflect.Type]bool, hits *[]string) {
	switch rt.Kind() {
	case reflect.Interface:
		*hits = append(*hits, path)
	case reflect.Pointer, reflect.Slice, reflect.Array:
		collectUntyped(rt.Elem(), path, visited, hits)
	case reflect.Map:
		collectUntyped(rt.Key(), path, visited, hits)
		collectUntyped(rt.Elem(), path, visited, hits)
	case reflect.Struct:
		if visited[rt] {
			return
		}
		if rt.Name() != "" && !strings.HasPrefix(rt.PkgPath(), "github.com/anchore/syft/") {
			// a third-party type in the model carries whatever shape the library gives it (the same leak as an
			// interface field), so it counts as untyped. The standard library is left alone.
			if strings.Contains(strings.Split(rt.PkgPath(), "/")[0], ".") {
				*hits = append(*hits, path)
			}
			return
		}
		visited[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			// unexported embedded structs still promote their exported fields to the encoders and the hasher. A
			// field is only out of reach when it is neither encoded nor hashed by SetID.
			if (!f.IsExported() && !f.Anonymous) || (f.Tag.Get("json") == "-" && f.Tag.Get("hash") == "ignore") {
				continue
			}
			collectUntyped(f.Type, rt.Name()+"."+f.Name, visited, hits)
		}
	}
}
