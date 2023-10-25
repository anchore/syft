package packagemetadata

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/pkg"
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
			wantRecord: reflect.TypeOf(pkg.HackageStackYamlLockMetadata{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReflectTypeFromJSONName(tt.lookup)
			assert.Equal(t, tt.wantRecord.Name(), got.Name())
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

func Test_JSONName_JSONLegacyName(t *testing.T) {
	// note: these are all the types and names covered by the v11.x and v12.x JSON schemas
	tests := []struct {
		name               string
		metadata           any
		expectedJSONName   string
		expectedLegacyName string
	}{
		{
			name:               "AlpmMetadata",
			metadata:           pkg.AlpmMetadata{},
			expectedJSONName:   "arch-alpm-db-record",
			expectedLegacyName: "AlpmMetadata",
		},
		{
			name:               "ApkMetadata",
			metadata:           pkg.ApkMetadata{},
			expectedJSONName:   "alpine-apk-db-record",
			expectedLegacyName: "ApkMetadata",
		},
		{
			name:               "BinaryMetadata",
			metadata:           pkg.BinaryMetadata{},
			expectedJSONName:   "binary-signature",
			expectedLegacyName: "BinaryMetadata",
		},
		{
			name:               "CocoapodsMetadata",
			metadata:           pkg.CocoapodsMetadata{},
			expectedJSONName:   "cocoa-podfile-lock",
			expectedLegacyName: "CocoapodsMetadataType",
		},
		{
			name:               "ConanLockMetadata",
			metadata:           pkg.ConanLockMetadata{},
			expectedJSONName:   "c-conan-lock",
			expectedLegacyName: "ConanLockMetadataType",
		},
		{
			name:               "ConanMetadata",
			metadata:           pkg.ConanMetadata{},
			expectedJSONName:   "c-conan",
			expectedLegacyName: "ConanMetadataType",
		},
		{
			name:               "DartPubMetadata",
			metadata:           pkg.DartPubMetadata{},
			expectedJSONName:   "dart-pubspec-lock",
			expectedLegacyName: "DartPubMetadata",
		},
		{
			name:               "DotnetDepsMetadata",
			metadata:           pkg.DotnetDepsMetadata{},
			expectedJSONName:   "dotnet-deps",
			expectedLegacyName: "DotnetDepsMetadata",
		},
		{
			name:               "DotnetPortableExecutableMetadata",
			metadata:           pkg.DotnetPortableExecutableMetadata{},
			expectedJSONName:   "dotnet-portable-executable",
			expectedLegacyName: "dotnet-portable-executable", // note: the legacy name should never be blank if it didn't exist pre v11.x
		},
		{
			name:               "DpkgMetadata",
			metadata:           pkg.DpkgMetadata{},
			expectedJSONName:   "debian-dpkg-db-record",
			expectedLegacyName: "DpkgMetadata",
		},
		{
			name:               "GemMetadata",
			metadata:           pkg.GemMetadata{},
			expectedJSONName:   "ruby-gemspec",
			expectedLegacyName: "GemMetadata",
		},
		{
			name:               "GolangBinMetadata",
			metadata:           pkg.GolangBinMetadata{},
			expectedJSONName:   "go-module-binary-buildinfo",
			expectedLegacyName: "GolangBinMetadata",
		},
		{
			name:               "GolangModMetadata",
			metadata:           pkg.GolangModMetadata{},
			expectedJSONName:   "go-module",
			expectedLegacyName: "GolangModMetadata",
		},
		{
			name:               "HackageStackYamlLockMetadata",
			metadata:           pkg.HackageStackYamlLockMetadata{},
			expectedJSONName:   "haskell-hackage-stack-lock",
			expectedLegacyName: "HackageMetadataType", // this is closest to the original data shape in <=v11.x schema
		},
		{
			name:               "HackageStackYamlMetadata",
			metadata:           pkg.HackageStackYamlMetadata{},
			expectedJSONName:   "haskell-hackage-stack",
			expectedLegacyName: "HackageMetadataType", // note: this conflicts with <=v11.x schema for "haskell-hackage-stack-lock" metadata type
		},
		{
			name:               "JavaMetadata",
			metadata:           pkg.JavaMetadata{},
			expectedJSONName:   "java-archive",
			expectedLegacyName: "JavaMetadata",
		},
		{
			name:               "KbPatchMetadata",
			metadata:           pkg.KbPatchMetadata{},
			expectedJSONName:   "microsoft-kb-patch",
			expectedLegacyName: "KbPatchMetadata",
		},
		{
			name:               "LinuxKernelMetadata",
			metadata:           pkg.LinuxKernelMetadata{},
			expectedJSONName:   "linux-kernel-archive",
			expectedLegacyName: "LinuxKernelMetadata",
		},
		{
			name:               "LinuxKernelModuleMetadata",
			metadata:           pkg.LinuxKernelModuleMetadata{},
			expectedJSONName:   "linux-kernel-module",
			expectedLegacyName: "LinuxKernelModuleMetadata",
		},
		{
			name:               "MixLockMetadata",
			metadata:           pkg.MixLockMetadata{},
			expectedJSONName:   "elixir-mix-lock",
			expectedLegacyName: "MixLockMetadataType",
		},
		{
			name:               "NixStoreMetadata",
			metadata:           pkg.NixStoreMetadata{},
			expectedJSONName:   "nix-store",
			expectedLegacyName: "NixStoreMetadata",
		},
		{
			name:               "NpmPackageJSONMetadata",
			metadata:           pkg.NpmPackageJSONMetadata{},
			expectedJSONName:   "javascript-npm-package",
			expectedLegacyName: "NpmPackageJsonMetadata",
		},
		{
			name:               "NpmPackageLockJSONMetadata",
			metadata:           pkg.NpmPackageLockJSONMetadata{},
			expectedJSONName:   "javascript-npm-package-lock",
			expectedLegacyName: "NpmPackageLockJsonMetadata",
		},
		{
			name:               "PhpComposerLockMetadata",
			metadata:           pkg.PhpComposerLockMetadata{},
			expectedJSONName:   "php-composer-lock",
			expectedLegacyName: "PhpComposerJsonMetadata",
		},
		{
			name:               "PhpComposerInstalledMetadata",
			metadata:           pkg.PhpComposerInstalledMetadata{},
			expectedJSONName:   "php-composer-installed",
			expectedLegacyName: "PhpComposerJsonMetadata",
		},
		{
			name:               "PortageMetadata",
			metadata:           pkg.PortageMetadata{},
			expectedJSONName:   "gentoo-portage-db-record",
			expectedLegacyName: "PortageMetadata",
		},
		{
			name:               "PythonPackageMetadata",
			metadata:           pkg.PythonPackageMetadata{},
			expectedJSONName:   "python-package",
			expectedLegacyName: "PythonPackageMetadata",
		},
		{
			name:               "PythonPipfileLockMetadata",
			metadata:           pkg.PythonPipfileLockMetadata{},
			expectedJSONName:   "python-pipfile-lock",
			expectedLegacyName: "PythonPipfileLockMetadata",
		},
		{
			name:               "PythonRequirementsMetadata",
			metadata:           pkg.PythonRequirementsMetadata{},
			expectedJSONName:   "python-pip-requirements",
			expectedLegacyName: "PythonRequirementsMetadata",
		},
		{
			name:               "RebarLockMetadata",
			metadata:           pkg.RebarLockMetadata{},
			expectedJSONName:   "erlang-rebar-lock",
			expectedLegacyName: "RebarLockMetadataType",
		},
		{
			name:               "RDescriptionFileMetadata",
			metadata:           pkg.RDescriptionFileMetadata{},
			expectedJSONName:   "r-description",
			expectedLegacyName: "RDescriptionFileMetadataType",
		},
		{
			name:               "RpmDBMetadata",
			metadata:           pkg.RpmDBMetadata{},
			expectedJSONName:   "redhat-rpm-db-record",
			expectedLegacyName: "RpmMetadata", // not accurate, but how it was pre v12 of the schema
		},
		{
			name:               "RpmArchiveMetadata",
			metadata:           pkg.RpmArchiveMetadata{},
			expectedJSONName:   "redhat-rpm-archive",
			expectedLegacyName: "RpmMetadata", // note: conflicts with <=v11.x schema for "redhat-rpm-db-record" metadata type
		},
		{
			name:               "SwiftPackageManagerMetadata",
			metadata:           pkg.SwiftPackageManagerMetadata{},
			expectedJSONName:   "swift-package-manager-lock",
			expectedLegacyName: "SwiftPackageManagerMetadata",
		},
		{
			name:               "CargoPackageMetadata",
			metadata:           pkg.CargoPackageMetadata{},
			expectedJSONName:   "rust-cargo-lock",
			expectedLegacyName: "RustCargoPackageMetadata",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actualJSONName := JSONName(test.metadata)
			actualLegacyName := JSONLegacyName(test.metadata)
			assert.Equal(t, test.expectedJSONName, actualJSONName, "unexpected name")
			assert.Equal(t, test.expectedLegacyName, actualLegacyName, "unexpected legacy name")
		})
	}
}
