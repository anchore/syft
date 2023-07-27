package packagemetadata

import (
	"github.com/anchore/syft/syft/pkg"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllNames(t *testing.T) {
	// note: this is a form of completion testing relative to the current code base.

	expected, err := DiscoverTypeNames()
	require.NoError(t, err)

	actual := AllNames()

	// ensure that the codebase (from ast analysis) reflects the latest code generated state
	if !assert.ElementsMatch(t, expected, actual) {
		t.Errorf("metadata types not fully represented: \n%s", cmp.Diff(expected, actual))
		t.Log("did you add a new pkg.*Metadata type without updating the JSON schema?")
		t.Log("if so, you need to update the schema version and regenerate the JSON schema (make generate-json-schema)")
	}

	for _, ty := range AllTypes() {
		assert.NotEmpty(t, JSONName(ty), "metadata type %q does not have a JSON name", ty)
	}
}

func TestReflectTypeFromJSONName(t *testing.T) {

	tests := []struct {
		name       string
		lookup     string
		wantRecord reflect.Type
	}{
		{
			name:       "exact match on ID",
			lookup:     "rust-cargo-lock",
			wantRecord: reflect.TypeOf(pkg.CargoPackageMetadata{}),
		},
		{
			name:       "exact match on former name",
			lookup:     "RustCargoPackageMetadata",
			wantRecord: reflect.TypeOf(pkg.CargoPackageMetadata{}),
		},
		{
			name:       "case insensitive on ID",
			lookup:     "RUST-CARGO-lock",
			wantRecord: reflect.TypeOf(pkg.CargoPackageMetadata{}),
		},
		{
			name:       "case insensitive on alias",
			lookup:     "rusTcArgopacKagEmEtadATa",
			wantRecord: reflect.TypeOf(pkg.CargoPackageMetadata{}),
		},
		{
			name: "consistent override",
			// there are two correct answers for this -- we should always get the same answer.
			lookup:     "HackageMetadataType",
			wantRecord: reflect.TypeOf(pkg.HackageStackYamlMetadata{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReflectTypeFromJSONName(tt.lookup)
			assert.Equal(t, tt.wantRecord, got)
		})
	}
}
