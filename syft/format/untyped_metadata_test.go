package format

import (
	"bytes"
	"fmt"
	"math"
	"testing"

	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// TestEncodersHandleUntypedMetadataValues pushes awkward values through the untyped metadata fields
// allowlisted in internal/packagemetadata (see untypedFieldAllowlist) and asserts that SetID and every
// encoder neither panic nor fail. A new allowlist entry should get a case here too.
func TestEncodersHandleUntypedMetadataValues(t *testing.T) {
	cases := []struct {
		name  string
		value any
		// encoding/json rejects non-finite floats, so syft-json returns an error for them. Producers
		// have to replace these before they reach the model (the GGUF cataloger does); the case stays
		// here so the expectation flips visibly if syft-json ever learns to encode them.
		syftJSONRejects bool
	}{
		{name: "NaN", value: math.NaN(), syftJSONRejects: true},
		{name: "+Inf float32", value: float32(math.Inf(1)), syftJSONRejects: true},
		{name: "-Inf", value: math.Inf(-1), syftJSONRejects: true},
		{name: "NaN in array", value: []any{1.0, math.NaN()}, syftJSONRejects: true},
		{name: "invalid utf-8", value: "\xff\xfe"},
		{name: "NUL and control characters", value: "a\x00b\x1b"},
		{name: "max uint64", value: uint64(math.MaxUint64)},
		{name: "deep array", value: nested(2000, func(v any) any { return []any{v} })},
		{name: "deep map", value: nested(2000, func(v any) any { return map[string]any{"k": v} })},
		{name: "large array", value: make([]any, 100_000)},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			p := pkg.Package{
				Name:    "model",
				Version: "1.0",
				Type:    pkg.ModelPkg,
				Metadata: pkg.GGUFFileHeader{
					RemainingKeyValues: map[string]any{"general.value": tt.value},
				},
			}
			if !noPanic(t, "SetID", p.SetID) {
				return
			}

			s := sbom.SBOM{
				Artifacts: sbom.Artifacts{Packages: pkg.NewCollection(p)},
				Source:    source.Description{Metadata: source.DirectoryMetadata{Path: "/models"}},
			}
			for _, enc := range Encoders() {
				id := fmt.Sprintf("%s@%s", enc.ID(), enc.Version())
				var buf bytes.Buffer
				noPanic(t, id, func() {
					err := enc.Encode(&buf, s)
					switch {
					case tt.syftJSONRejects && enc.ID() == syftjson.ID:
						if err == nil {
							t.Errorf("%s: expected an encode error for a non-finite float", id)
						}
					case err != nil:
						t.Errorf("%s: encode failed: %v", id, err)
					}
				})
			}
		})
	}
}

func nested(depth int, wrap func(any) any) any {
	var v any = "leaf"
	for range depth {
		v = wrap(v)
	}
	return v
}

func noPanic(t *testing.T, what string, fn func()) (ok bool) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panic: %v", what, r)
			ok = false
		}
	}()
	fn()
	return true
}
