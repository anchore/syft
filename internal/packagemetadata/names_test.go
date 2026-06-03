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
		assert.NotEmpty(t, JSONName(ty), "metadata type %q does not have a JSON name", reflect.TypeOf(ty).Name())
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
			lookup:     "rust-cargo-lock-entry",
			wantRecord: reflect.TypeFor[pkg.RustCargoLockEntry](),
		},
		{
			name:       "exact match on former name",
			lookup:     "RustCargoPackageMetadata",
			wantRecord: reflect.TypeFor[pkg.RustCargoLockEntry](),
		},
		{
			name:       "case insensitive on ID",
			lookup:     "RUST-CARGO-lock-entrY",
			wantRecord: reflect.TypeFor[pkg.RustCargoLockEntry](),
		},
		{
			name:       "case insensitive on alias",
			lookup:     "rusTcArgopacKagEmEtadATa",
			wantRecord: reflect.TypeFor[pkg.RustCargoLockEntry](),
		},
		{
			name: "consistent override",
			// there are two correct answers for this -- we should always get the same answer.
			lookup:     "HackageMetadataType",
			wantRecord: reflect.TypeFor[pkg.HackageStackYamlLockEntry](),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReflectTypeFromJSONName(tt.lookup)
			require.NotNil(t, got)
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
			name:     "map pkg.AlpmDBEntry struct type",
			input:    "AlpmMetadata",
			expected: reflect.TypeFor[pkg.AlpmDBEntry](),
		},
		{
			name:     "map pkg.ApkDBEntry struct type",
			input:    "ApkMetadata",
			expected: reflect.TypeFor[pkg.ApkDBEntry](),
		},
		{
			name:     "map pkg.BinarySignature struct type",
			input:    "BinaryMetadata",
			expected: reflect.TypeFor[pkg.BinarySignature](),
		},
		{
			name:     "map pkg.CocoaPodfileLockEntry struct type",
			input:    "CocoapodsMetadataType",
			expected: reflect.TypeFor[pkg.CocoaPodfileLockEntry](),
		},
		{
			name:     "map pkg.ConanLockEntry struct type",
			input:    "ConanLockMetadataType",
			expected: reflect.TypeFor[pkg.ConanV1LockEntry](),
		},
		{
			name:     "map pkg.ConanfileEntry struct type",
			input:    "ConanMetadataType",
			expected: reflect.TypeFor[pkg.ConanfileEntry](),
		},
		{
			name:     "map pkg.DartPubspecLockEntry struct type",
			input:    "DartPubMetadata",
			expected: reflect.TypeFor[pkg.DartPubspecLockEntry](),
		},
		{
			name:     "map pkg.DotnetDepsEntry struct type",
			input:    "DotnetDepsMetadata",
			expected: reflect.TypeFor[pkg.DotnetDepsEntry](),
		},
		{
			name:     "map pkg.DpkgDBEntry struct type",
			input:    "DpkgMetadata",
			expected: reflect.TypeFor[pkg.DpkgDBEntry](),
		},
		{
			name:     "map pkg.RubyGemspec struct type",
			input:    "GemMetadata",
			expected: reflect.TypeFor[pkg.RubyGemspec](),
		},
		{
			name:     "map pkg.GolangBinaryBuildinfoEntry struct type",
			input:    "GolangBinMetadata",
			expected: reflect.TypeFor[pkg.GolangBinaryBuildinfoEntry](),
		},
		{
			name:     "map pkg.GolangModuleEntry struct type",
			input:    "GolangModMetadata",
			expected: reflect.TypeFor[pkg.GolangModuleEntry](),
		},
		{
			name:     "map pkg.JavaArchive struct type",
			input:    "JavaMetadata",
			expected: reflect.TypeFor[pkg.JavaArchive](),
		},
		{
			name:     "map pkg.MicrosoftKbPatch struct type",
			input:    "KbPatchMetadata",
			expected: reflect.TypeFor[pkg.MicrosoftKbPatch](),
		},
		{
			name:     "map pkg.LinuxKernel struct type",
			input:    "LinuxKernel",
			expected: reflect.TypeFor[pkg.LinuxKernel](),
		},
		{
			name:     "map pkg.LinuxKernelModule struct type",
			input:    "LinuxKernelModule",
			expected: reflect.TypeFor[pkg.LinuxKernelModule](),
		},
		{
			name:     "map pkg.ElixirMixLockEntry struct type",
			input:    "MixLockMetadataType",
			expected: reflect.TypeFor[pkg.ElixirMixLockEntry](),
		},
		{
			name:     "map pkg.NixStoreEntry struct type",
			input:    "NixStoreMetadata",
			expected: reflect.TypeFor[pkg.NixStoreEntry](),
		},
		{
			name:     "map pkg.NpmPackage struct type",
			input:    "NpmPackageJsonMetadata",
			expected: reflect.TypeFor[pkg.NpmPackage](),
		},
		{
			name:     "map pkg.NpmPackageLockEntry struct type",
			input:    "NpmPackageLockJsonMetadata",
			expected: reflect.TypeFor[pkg.NpmPackageLockEntry](),
		},
		{
			name:     "map pkg.PortageEntry struct type",
			input:    "PortageMetadata",
			expected: reflect.TypeFor[pkg.PortageEntry](),
		},
		{
			name:     "map pkg.PythonPackage struct type",
			input:    "PythonPackageMetadata",
			expected: reflect.TypeFor[pkg.PythonPackage](),
		},
		{
			name:     "map pkg.PythonPipfileLockEntry struct type",
			input:    "PythonPipfileLockMetadata",
			expected: reflect.TypeFor[pkg.PythonPipfileLockEntry](),
		},
		{
			name:     "map pkg.PythonRequirementsEntry struct type",
			input:    "PythonRequirementsMetadata",
			expected: reflect.TypeFor[pkg.PythonRequirementsEntry](),
		},
		{
			name:     "map pkg.PhpPeclEntry struct type",
			input:    "PhpPeclMetadata",
			expected: reflect.TypeFor[pkg.PhpPeclEntry](),
		},
		{
			name:     "map pkg.ErlangRebarLockEntry struct type",
			input:    "RebarLockMetadataType",
			expected: reflect.TypeFor[pkg.ErlangRebarLockEntry](),
		},
		{
			name:     "map pkg.RDescription struct type",
			input:    "RDescriptionFileMetadataType",
			expected: reflect.TypeFor[pkg.RDescription](),
		},
		{
			name:     "map pkg.RpmDBEntry struct type",
			input:    "RpmdbMetadata",
			expected: reflect.TypeFor[pkg.RpmDBEntry](),
		},
		// these cases are 1:many
		{
			name:  "map pkg.RpmDBEntry struct type - overlap with RpmArchiveMetadata",
			input: "RpmMetadata",
			// this used to be shared as a use case for both RpmArchive and RpmDBEntry
			// from a data-shape perspective either would be equally correct
			// however, the RPMDBMetadata has been around longer and may have been more widely used
			// so we'll map to that type for backwards compatibility.
			expected: reflect.TypeFor[pkg.RpmDBEntry](),
		},
		{
			name:  "map pkg.HackageStackYamlLockEntry struct type - overlap with HackageStack*Metadata",
			input: "HackageMetadataType",
			// this used to be shared as a use case for both HackageStackYamlLockEntry and HackageStackYamlEntry
			// but the HackageStackYamlLockEntry maps most closely to the original data shape.
			expected: reflect.TypeFor[pkg.HackageStackYamlLockEntry](),
		},
		{
			name:  "map pkg.PhpComposerLockEntry struct type",
			input: "PhpComposerJsonMetadata",
			// this used to be shared as a use case for both PhpComposerLockEntry and PhpComposerInstalledEntry
			// neither of these is more correct over the other. These parsers were also introduced at the same time.
			expected: reflect.TypeFor[pkg.PhpComposerLockEntry](),
		},
		{
			name:  "map pkg.RustCargoLockEntry struct type",
			input: "RustCargoPackageMetadata",
			// this used to be shared as a use case for both RustCargoLockEntry and RustBinaryAuditEntry
			// neither of these is more correct over the other.
			expected: reflect.TypeFor[pkg.RustCargoLockEntry](),
		},
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
			metadata:           pkg.AlpmDBEntry{},
			expectedJSONName:   "alpm-db-entry",
			expectedLegacyName: "AlpmMetadata",
		},
		{
			name:               "ApkMetadata",
			metadata:           pkg.ApkDBEntry{},
			expectedJSONName:   "apk-db-entry",
			expectedLegacyName: "ApkMetadata",
		},
		{
			name:               "BinaryMetadata",
			metadata:           pkg.BinarySignature{},
			expectedJSONName:   "binary-signature",
			expectedLegacyName: "BinaryMetadata",
		},
		{
			name:               "CocoapodsMetadata",
			metadata:           pkg.CocoaPodfileLockEntry{},
			expectedJSONName:   "cocoa-podfile-lock-entry",
			expectedLegacyName: "CocoapodsMetadataType",
		},
		{
			name:               "ConanLockMetadata",
			metadata:           pkg.ConanV1LockEntry{},
			expectedJSONName:   "c-conan-lock-entry",
			expectedLegacyName: "ConanLockMetadataType",
		},
		{
			name:               "ConanMetadata",
			metadata:           pkg.ConanfileEntry{},
			expectedJSONName:   "c-conan-file-entry",
			expectedLegacyName: "ConanMetadataType",
		},
		{
			name:               "DartPubMetadata",
			metadata:           pkg.DartPubspecLockEntry{},
			expectedJSONName:   "dart-pubspec-lock-entry",
			expectedLegacyName: "DartPubMetadata",
		},
		{
			name:               "DotnetDepsMetadata",
			metadata:           pkg.DotnetDepsEntry{},
			expectedJSONName:   "dotnet-deps-entry",
			expectedLegacyName: "DotnetDepsMetadata",
		},
		{
			name:               "DotnetPortableExecutableMetadata",
			metadata:           pkg.DotnetPortableExecutableEntry{},
			expectedJSONName:   "dotnet-portable-executable-entry",
			expectedLegacyName: "dotnet-portable-executable-entry", // note: the legacy name should never be blank if it didn't exist pre v11.x
		},
		{
			name:               "DpkgMetadata",
			metadata:           pkg.DpkgDBEntry{},
			expectedJSONName:   "dpkg-db-entry",
			expectedLegacyName: "DpkgMetadata",
		},
		{
			name:               "GemMetadata",
			metadata:           pkg.RubyGemspec{},
			expectedJSONName:   "ruby-gemspec",
			expectedLegacyName: "GemMetadata",
		},
		{
			name:               "GolangBinMetadata",
			metadata:           pkg.GolangBinaryBuildinfoEntry{},
			expectedJSONName:   "go-module-buildinfo-entry",
			expectedLegacyName: "GolangBinMetadata",
		},
		{
			name:               "GolangModMetadata",
			metadata:           pkg.GolangModuleEntry{},
			expectedJSONName:   "go-module-entry",
			expectedLegacyName: "GolangModMetadata",
		},
		{
			name:               "GolangSourceMetadata",
			metadata:           pkg.GolangSourceEntry{},
			expectedJSONName:   "go-source-entry",
			expectedLegacyName: "go-source-entry",
		},
		{
			name:               "HackageStackYamlLockMetadata",
			metadata:           pkg.HackageStackYamlLockEntry{},
			expectedJSONName:   "haskell-hackage-stack-lock-entry",
			expectedLegacyName: "HackageMetadataType", // this is closest to the original data shape in <=v11.x schema
		},
		{
			name:               "HackageStackYamlMetadata",
			metadata:           pkg.HackageStackYamlEntry{},
			expectedJSONName:   "haskell-hackage-stack-entry",
			expectedLegacyName: "HackageMetadataType", // note: this conflicts with <=v11.x schema for "haskell-hackage-stack-lock" metadata type
		},
		{
			name:               "JavaMetadata",
			metadata:           pkg.JavaArchive{},
			expectedJSONName:   "java-archive",
			expectedLegacyName: "JavaMetadata",
		},
		{
			name:               "KbPatchMetadata",
			metadata:           pkg.MicrosoftKbPatch{},
			expectedJSONName:   "microsoft-kb-patch",
			expectedLegacyName: "KbPatchMetadata",
		},
		{
			name:               "LinuxKernel",
			metadata:           pkg.LinuxKernel{},
			expectedJSONName:   "linux-kernel-archive",
			expectedLegacyName: "LinuxKernel",
		},
		{
			name:               "LinuxKernelModule",
			metadata:           pkg.LinuxKernelModule{},
			expectedJSONName:   "linux-kernel-module",
			expectedLegacyName: "LinuxKernelModule",
		},
		{
			name:               "MixLockMetadata",
			metadata:           pkg.ElixirMixLockEntry{},
			expectedJSONName:   "elixir-mix-lock-entry",
			expectedLegacyName: "MixLockMetadataType",
		},
		{
			name:               "NixStoreMetadata",
			metadata:           pkg.NixStoreEntry{},
			expectedJSONName:   "nix-store-entry",
			expectedLegacyName: "NixStoreMetadata",
		},
		{
			name:               "NpmPackageJSONMetadata",
			metadata:           pkg.NpmPackage{},
			expectedJSONName:   "javascript-npm-package",
			expectedLegacyName: "NpmPackageJsonMetadata",
		},
		{
			name:               "NpmPackageLockJSONMetadata",
			metadata:           pkg.NpmPackageLockEntry{},
			expectedJSONName:   "javascript-npm-package-lock-entry",
			expectedLegacyName: "NpmPackageLockJsonMetadata",
		},
		{
			name:               "PhpComposerLockMetadata",
			metadata:           pkg.PhpComposerLockEntry{},
			expectedJSONName:   "php-composer-lock-entry",
			expectedLegacyName: "PhpComposerJsonMetadata", // note: maps to multiple entries (v11-12 breaking change)
		},
		{
			name:               "PhpComposerInstalledMetadata",
			metadata:           pkg.PhpComposerInstalledEntry{},
			expectedJSONName:   "php-composer-installed-entry",
			expectedLegacyName: "PhpComposerJsonMetadata", // note: maps to multiple entries (v11-12 breaking change)
		},
		{
			name:               "PhpPeclMetadata",
			metadata:           pkg.PhpPeclEntry{},
			expectedJSONName:   "php-pecl-entry",
			expectedLegacyName: "PhpPeclMetadata",
		},
		{
			name:               "PortageMetadata",
			metadata:           pkg.PortageEntry{},
			expectedJSONName:   "portage-db-entry",
			expectedLegacyName: "PortageMetadata",
		},
		{
			name:               "PythonPackageMetadata",
			metadata:           pkg.PythonPackage{},
			expectedJSONName:   "python-package",
			expectedLegacyName: "PythonPackageMetadata",
		},
		{
			name:               "PythonPipfileLockMetadata",
			metadata:           pkg.PythonPipfileLockEntry{},
			expectedJSONName:   "python-pipfile-lock-entry",
			expectedLegacyName: "PythonPipfileLockMetadata",
		},
		{
			name:               "PythonRequirementsMetadata",
			metadata:           pkg.PythonRequirementsEntry{},
			expectedJSONName:   "python-pip-requirements-entry",
			expectedLegacyName: "PythonRequirementsMetadata",
		},
		{
			name:               "RebarLockMetadata",
			metadata:           pkg.ErlangRebarLockEntry{},
			expectedJSONName:   "erlang-rebar-lock-entry",
			expectedLegacyName: "RebarLockMetadataType",
		},
		{
			name:               "RDescriptionFileMetadata",
			metadata:           pkg.RDescription{},
			expectedJSONName:   "r-description",
			expectedLegacyName: "RDescriptionFileMetadataType",
		},
		{
			name:               "RpmDBMetadata",
			metadata:           pkg.RpmDBEntry{},
			expectedJSONName:   "rpm-db-entry",
			expectedLegacyName: "RpmMetadata", // not accurate, but how it was pre v12 of the schema
		},
		{
			name:               "RpmArchiveMetadata",
			metadata:           pkg.RpmArchive{},
			expectedJSONName:   "rpm-archive",
			expectedLegacyName: "RpmMetadata", // note: conflicts with <=v11.x schema for "rpm-db-entry" metadata type
		},
		{
			name:               "CargoPackageMetadata",
			metadata:           pkg.RustCargoLockEntry{},
			expectedJSONName:   "rust-cargo-lock-entry",
			expectedLegacyName: "RustCargoPackageMetadata", // note: maps to multiple entries (v11-12 breaking change)
		},
		{
			name:               "CargoPackageMetadata (audit binary)",
			metadata:           pkg.RustBinaryAuditEntry{},
			expectedJSONName:   "rust-cargo-audit-entry",
			expectedLegacyName: "RustCargoPackageMetadata", // note: maps to multiple entries (v11-12 breaking change)
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
