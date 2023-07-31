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

	actual := AllTypeNames()

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

func TestReflectTypeFromJSONName_LegacyValues(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected reflect.Type
	}{
		// these cases are always 1:1
		{
			name:     "map pkg.AlpmMetadata struct type",
			input:    "AlpmMetadata",
			expected: reflect.TypeOf(pkg.AlpmMetadata{}),
		},
		{
			name:     "map pkg.ApkMetadata struct type",
			input:    "ApkMetadata",
			expected: reflect.TypeOf(pkg.ApkMetadata{}),
		},
		{
			name:     "map pkg.BinaryMetadata struct type",
			input:    "BinaryMetadata",
			expected: reflect.TypeOf(pkg.BinaryMetadata{}),
		},
		{
			name:     "map pkg.CocoapodsMetadata struct type",
			input:    "CocoapodsMetadataType",
			expected: reflect.TypeOf(pkg.CocoapodsMetadata{}),
		},
		{
			name:     "map pkg.ConanLockMetadata struct type",
			input:    "ConanLockMetadataType",
			expected: reflect.TypeOf(pkg.ConanLockMetadata{}),
		},
		{
			name:     "map pkg.ConanMetadata struct type",
			input:    "ConanMetadataType",
			expected: reflect.TypeOf(pkg.ConanMetadata{}),
		},
		{
			name:     "map pkg.DartPubMetadata struct type",
			input:    "DartPubMetadata",
			expected: reflect.TypeOf(pkg.DartPubMetadata{}),
		},
		{
			name:     "map pkg.DotnetDepsMetadata struct type",
			input:    "DotnetDepsMetadata",
			expected: reflect.TypeOf(pkg.DotnetDepsMetadata{}),
		},
		{
			name:     "map pkg.DpkgMetadata struct type",
			input:    "DpkgMetadata",
			expected: reflect.TypeOf(pkg.DpkgMetadata{}),
		},
		{
			name:     "map pkg.GemMetadata struct type",
			input:    "GemMetadata",
			expected: reflect.TypeOf(pkg.GemMetadata{}),
		},
		{
			name:     "map pkg.GolangBinMetadata struct type",
			input:    "GolangBinMetadata",
			expected: reflect.TypeOf(pkg.GolangBinMetadata{}),
		},
		{
			name:     "map pkg.GolangModMetadata struct type",
			input:    "GolangModMetadata",
			expected: reflect.TypeOf(pkg.GolangModMetadata{}),
		},
		{
			name:     "map pkg.JavaMetadata struct type",
			input:    "JavaMetadata",
			expected: reflect.TypeOf(pkg.JavaMetadata{}),
		},
		{
			name:     "map pkg.KbPatchMetadata struct type",
			input:    "KbPatchMetadata",
			expected: reflect.TypeOf(pkg.KbPatchMetadata{}),
		},
		{
			name:     "map pkg.LinuxKernelMetadata struct type",
			input:    "LinuxKernelMetadata",
			expected: reflect.TypeOf(pkg.LinuxKernelMetadata{}),
		},
		{
			name:     "map pkg.LinuxKernelModuleMetadata struct type",
			input:    "LinuxKernelModuleMetadata",
			expected: reflect.TypeOf(pkg.LinuxKernelModuleMetadata{}),
		},
		{
			name:     "map pkg.MixLockMetadata struct type",
			input:    "MixLockMetadataType",
			expected: reflect.TypeOf(pkg.MixLockMetadata{}),
		},
		{
			name:     "map pkg.NixStoreMetadata struct type",
			input:    "NixStoreMetadata",
			expected: reflect.TypeOf(pkg.NixStoreMetadata{}),
		},
		{
			name:     "map pkg.NpmPackageJSONMetadata struct type",
			input:    "NpmPackageJsonMetadata",
			expected: reflect.TypeOf(pkg.NpmPackageJSONMetadata{}),
		},
		{
			name:     "map pkg.NpmPackageLockJSONMetadata struct type",
			input:    "NpmPackageLockJsonMetadata",
			expected: reflect.TypeOf(pkg.NpmPackageLockJSONMetadata{}),
		},
		{
			name:     "map pkg.PhpComposerInstalledMetadata struct type",
			input:    "PhpComposerJsonMetadata",
			expected: reflect.TypeOf(pkg.PhpComposerInstalledMetadata{}),
		},
		{
			name:     "map pkg.PortageMetadata struct type",
			input:    "PortageMetadata",
			expected: reflect.TypeOf(pkg.PortageMetadata{}),
		},
		{
			name:     "map pkg.PythonPackageMetadata struct type",
			input:    "PythonPackageMetadata",
			expected: reflect.TypeOf(pkg.PythonPackageMetadata{}),
		},
		{
			name:     "map pkg.PythonPipfileLockMetadata struct type",
			input:    "PythonPipfileLockMetadata",
			expected: reflect.TypeOf(pkg.PythonPipfileLockMetadata{}),
		},
		{
			name:     "map pkg.PythonRequirementsMetadata struct type",
			input:    "PythonRequirementsMetadata",
			expected: reflect.TypeOf(pkg.PythonRequirementsMetadata{}),
		},
		{
			name:     "map pkg.RebarLockMetadata struct type",
			input:    "RebarLockMetadataType",
			expected: reflect.TypeOf(pkg.RebarLockMetadata{}),
		},
		{
			name:     "map pkg.RDescriptionFileMetadata struct type",
			input:    "RDescriptionFileMetadataType",
			expected: reflect.TypeOf(pkg.RDescriptionFileMetadata{}),
		},
		{
			name:     "map pkg.RpmDBMetadata struct type",
			input:    "RpmdbMetadata",
			expected: reflect.TypeOf(pkg.RpmDBMetadata{}),
		},
		{
			name:     "map pkg.CargoPackageMetadata struct type",
			input:    "RustCargoPackageMetadata",
			expected: reflect.TypeOf(pkg.CargoPackageMetadata{}),
		},
		// these cases are 1:many
		{
			name:  "map pkg.RpmDBMetadata struct type - overlap with RpmArchiveMetadata",
			input: "RpmMetadata",
			// this used to be shared as a use case for both RpmArchiveMetadata and RpmDBMetadata
			// from a data-shape perspective either would be equally correct
			// however, the RPMDBMetadata has been around longer and may have been more widely used
			// so we'll map to that type for backwards compatibility.
			expected: reflect.TypeOf(pkg.RpmDBMetadata{}),
		},
		{
			name:  "map pkg.HackageStackYamlLockMetadata struct type - overlap with HackageStack*Metadata",
			input: "HackageMetadataType",
			// this used to be shared as a use case for both HackageStackYamlLockMetadata and HackageStackYamlMetadata
			// but the HackageStackYamlLockMetadata maps most closely to the original data shape.
			expected: reflect.TypeOf(pkg.HackageStackYamlLockMetadata{}),
		},
		// There is no way currently to infer the correct type for this case without additional information (say from the package).
		//{
		//	name:  "map pkg.PhpComposerLockMetadata struct type - overlap with PhpComposer*Metadata",
		//	input: "PhpComposerJsonMetadata",
		//	// this used to be shared as a use case for both PhpComposerLockMetadata and PhpComposerInstalledMetadata
		//	// neither of these is more correct over the other. These parsers were also introduced at the same time.
		//	expected: reflect.TypeOf(pkg.PhpComposerLockMetadata{}),
		//},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			result := ReflectTypeFromJSONName(testCase.input)
			assert.Equal(t, testCase.expected.Name(), result.Name())
		})
	}
}
