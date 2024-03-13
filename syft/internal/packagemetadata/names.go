package packagemetadata

import (
	"reflect"
	"strings"

	"github.com/anchore/syft/syft/pkg"
)

type jsonType struct {
	ty                 any
	name               string
	legacyNames        []string
	noLookupLegacyName string // legacy name that conflict with other types, thus should not affect the lookup
}

func jsonNames(ty any, name string, legacyNames ...string) jsonType {
	return jsonType{
		ty:          ty,
		name:        name,
		legacyNames: expandLegacyNameVariants(legacyNames...),
	}
}

func jsonNamesWithoutLookup(ty any, name string, noLookupLegacyName string) jsonType {
	return jsonType{
		ty:                 ty,
		name:               name,
		noLookupLegacyName: noLookupLegacyName,
	}
}

type jsonTypeMapping struct {
	typeToName       map[reflect.Type]string
	typeToLegacyName map[reflect.Type]string
	nameToType       map[string]reflect.Type
}

func makeJSONTypes(types ...jsonType) jsonTypeMapping {
	out := jsonTypeMapping{
		typeToName:       make(map[reflect.Type]string),
		typeToLegacyName: make(map[reflect.Type]string),
		nameToType:       make(map[string]reflect.Type),
	}
	for _, t := range types {
		typ := reflect.TypeOf(t.ty)
		out.typeToName[typ] = t.name
		if len(t.noLookupLegacyName) > 0 {
			out.typeToLegacyName[typ] = t.noLookupLegacyName
		} else if len(t.legacyNames) > 0 {
			out.typeToLegacyName[typ] = t.legacyNames[0]
		}
		out.nameToType[strings.ToLower(t.name)] = typ
		for _, name := range t.legacyNames {
			out.nameToType[strings.ToLower(name)] = typ
		}
	}
	return out
}

// jsonNameFromType is lookup of all known package metadata types to their current JSON name and all previously known aliases.
// It is important that if a name needs to change that the old name is kept in this map (as an alias) for backwards
// compatibility to support decoding older JSON documents.
var jsonTypes = makeJSONTypes(
	jsonNames(pkg.AlpmDBEntry{}, "alpm-db-entry", "AlpmMetadata"),
	jsonNames(pkg.ApkDBEntry{}, "apk-db-entry", "ApkMetadata"),
	jsonNames(pkg.BinarySignature{}, "binary-signature", "BinaryMetadata"),
	jsonNames(pkg.CocoaPodfileLockEntry{}, "cocoa-podfile-lock-entry", "CocoapodsMetadataType"),
	jsonNames(pkg.ConanV1LockEntry{}, "c-conan-lock-entry", "ConanLockMetadataType"),
	jsonNames(pkg.ConanV2LockEntry{}, "c-conan-lock-v2-entry"),
	jsonNames(pkg.ConanfileEntry{}, "c-conan-file-entry", "ConanMetadataType"),
	jsonNames(pkg.ConaninfoEntry{}, "c-conan-info-entry"),
	jsonNames(pkg.DartPubspecLockEntry{}, "dart-pubspec-lock-entry", "DartPubMetadata"),
	jsonNames(pkg.DotnetDepsEntry{}, "dotnet-deps-entry", "DotnetDepsMetadata"),
	jsonNames(pkg.DotnetPortableExecutableEntry{}, "dotnet-portable-executable-entry"),
	jsonNames(pkg.DpkgDBEntry{}, "dpkg-db-entry", "DpkgMetadata"),
	jsonNames(pkg.ELFBinaryPackageNoteJSONPayload{}, "elf-binary-package-note-json-payload"),
	jsonNames(pkg.RubyGemspec{}, "ruby-gemspec", "GemMetadata"),
	jsonNames(pkg.GolangBinaryBuildinfoEntry{}, "go-module-buildinfo-entry", "GolangBinMetadata", "GolangMetadata"),
	jsonNames(pkg.GolangModuleEntry{}, "go-module-entry", "GolangModMetadata"),
	jsonNames(pkg.HackageStackYamlLockEntry{}, "haskell-hackage-stack-lock-entry", "HackageMetadataType"),
	jsonNamesWithoutLookup(pkg.HackageStackYamlEntry{}, "haskell-hackage-stack-entry", "HackageMetadataType"), // the legacy value is split into two types, where the other is preferred
	jsonNames(pkg.JavaArchive{}, "java-archive", "JavaMetadata"),
	jsonNames(pkg.MicrosoftKbPatch{}, "microsoft-kb-patch", "KbPatchMetadata"),
	jsonNames(pkg.LinuxKernel{}, "linux-kernel-archive", "LinuxKernel"),
	jsonNames(pkg.LinuxKernelModule{}, "linux-kernel-module", "LinuxKernelModule"),
	jsonNames(pkg.ElixirMixLockEntry{}, "elixir-mix-lock-entry", "MixLockMetadataType"),
	jsonNames(pkg.NixStoreEntry{}, "nix-store-entry", "NixStoreMetadata"),
	jsonNames(pkg.NpmPackage{}, "javascript-npm-package", "NpmPackageJsonMetadata"),
	jsonNames(pkg.NpmPackageLockEntry{}, "javascript-npm-package-lock-entry", "NpmPackageLockJsonMetadata"),
	jsonNames(pkg.YarnLockEntry{}, "javascript-yarn-lock-entry", "YarnLockJsonMetadata"),
	jsonNames(pkg.PhpComposerLockEntry{}, "php-composer-lock-entry", "PhpComposerJsonMetadata"),
	jsonNamesWithoutLookup(pkg.PhpComposerInstalledEntry{}, "php-composer-installed-entry", "PhpComposerJsonMetadata"), // the legacy value is split into two types, where the other is preferred
	jsonNames(pkg.PortageEntry{}, "portage-db-entry", "PortageMetadata"),
	jsonNames(pkg.PythonPackage{}, "python-package", "PythonPackageMetadata"),
	jsonNames(pkg.PythonPipfileLockEntry{}, "python-pipfile-lock-entry", "PythonPipfileLockMetadata"),
	jsonNames(pkg.PythonPoetryLockEntry{}, "python-poetry-lock-entry", "PythonPoetryLockMetadata"),
	jsonNames(pkg.PythonRequirementsEntry{}, "python-pip-requirements-entry", "PythonRequirementsMetadata"),
	jsonNames(pkg.ErlangRebarLockEntry{}, "erlang-rebar-lock-entry", "RebarLockMetadataType"),
	jsonNames(pkg.RDescription{}, "r-description", "RDescriptionFileMetadataType"),
	jsonNames(pkg.RpmDBEntry{}, "rpm-db-entry", "RpmMetadata", "RpmdbMetadata"),
	jsonNamesWithoutLookup(pkg.RpmArchive{}, "rpm-archive", "RpmMetadata"), // the legacy value is split into two types, where the other is preferred
	jsonNames(pkg.SwiftPackageManagerResolvedEntry{}, "swift-package-manager-lock-entry", "SwiftPackageManagerMetadata"),
	jsonNames(pkg.RustCargoLockEntry{}, "rust-cargo-lock-entry", "RustCargoPackageMetadata"),
	jsonNamesWithoutLookup(pkg.RustBinaryAuditEntry{}, "rust-cargo-audit-entry", "RustCargoPackageMetadata"), // the legacy value is split into two types, where the other is preferred
	jsonNames(pkg.WordpressPluginEntry{}, "wordpress-plugin-entry", "WordpressMetadata"),
)

func expandLegacyNameVariants(names ...string) []string {
	var candidates []string
	for _, name := range names {
		candidates = append(candidates, name)
		if strings.HasSuffix(name, "MetadataType") {
			candidates = append(candidates, strings.TrimSuffix(name, "Type"))
		} else if strings.HasSuffix(name, "Metadata") {
			candidates = append(candidates, name+"Type")
		}
	}
	return candidates
}

func AllTypeNames() []string {
	names := make([]string, 0)
	for _, t := range AllTypes() {
		names = append(names, reflect.TypeOf(t).Name())
	}
	return names
}

func JSONName(metadata any) string {
	if name, exists := jsonTypes.typeToName[reflect.TypeOf(metadata)]; exists {
		return name
	}
	return ""
}

func JSONLegacyName(metadata any) string {
	if name, exists := jsonTypes.typeToLegacyName[reflect.TypeOf(metadata)]; exists {
		return name
	}
	return JSONName(metadata)
}

func ReflectTypeFromJSONName(name string) reflect.Type {
	name = strings.ToLower(name)
	return jsonTypes.nameToType[name]
}
