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
	jsonNames(pkg.AlpmMetadata{}, "arch-alpm-db-record", "AlpmMetadata"),
	jsonNames(pkg.ApkMetadata{}, "alpine-apk-db-record", "ApkMetadata"),
	jsonNames(pkg.BinaryMetadata{}, "binary-signature", "BinaryMetadata"),
	jsonNames(pkg.CocoapodsMetadata{}, "cocoa-podfile-lock", "CocoapodsMetadataType"),
	jsonNames(pkg.ConanLockMetadata{}, "c-conan-lock", "ConanLockMetadataType"),
	jsonNames(pkg.ConanMetadata{}, "c-conan", "ConanMetadataType"),
	jsonNames(pkg.DartPubMetadata{}, "dart-pubspec-lock", "DartPubMetadata"),
	jsonNames(pkg.DotnetDepsMetadata{}, "dotnet-deps", "DotnetDepsMetadata"),
	jsonNames(pkg.DotnetPortableExecutableMetadata{}, "dotnet-portable-executable"),
	jsonNames(pkg.DpkgMetadata{}, "debian-dpkg-db-record", "DpkgMetadata"),
	jsonNames(pkg.GemMetadata{}, "ruby-gemspec", "GemMetadata"),
	jsonNames(pkg.GolangBinMetadata{}, "go-module-binary-buildinfo", "GolangBinMetadata", "GolangMetadata"),
	jsonNames(pkg.GolangModMetadata{}, "go-module", "GolangModMetadata"),
	jsonNames(pkg.HackageStackYamlLockMetadata{}, "haskell-hackage-stack-lock", "HackageMetadataType"),
	jsonNamesWithoutLookup(pkg.HackageStackYamlMetadata{}, "haskell-hackage-stack", "HackageMetadataType"), // the legacy value is split into two types, where the other is preferred
	jsonNames(pkg.JavaMetadata{}, "java-archive", "JavaMetadata"),
	jsonNames(pkg.KbPatchMetadata{}, "microsoft-kb-patch", "KbPatchMetadata"),
	jsonNames(pkg.LinuxKernelMetadata{}, "linux-kernel-archive", "LinuxKernelMetadata"),
	jsonNames(pkg.LinuxKernelModuleMetadata{}, "linux-kernel-module", "LinuxKernelModuleMetadata"),
	jsonNames(pkg.MixLockMetadata{}, "elixir-mix-lock", "MixLockMetadataType"),
	jsonNames(pkg.NixStoreMetadata{}, "nix-store", "NixStoreMetadata"),
	jsonNames(pkg.NpmPackageJSONMetadata{}, "javascript-npm-package", "NpmPackageJsonMetadata"),
	jsonNames(pkg.NpmPackageLockJSONMetadata{}, "javascript-npm-package-lock", "NpmPackageLockJsonMetadata"),
	jsonNames(pkg.PhpComposerLockMetadata{}, "php-composer-lock", "PhpComposerJsonMetadata"),
	jsonNames(pkg.PhpComposerInstalledMetadata{}, "php-composer-installed", "PhpComposerJsonMetadata"),
	jsonNames(pkg.PortageMetadata{}, "gentoo-portage-db-record", "PortageMetadata"),
	jsonNames(pkg.PythonPackageMetadata{}, "python-package", "PythonPackageMetadata"),
	jsonNames(pkg.PythonPipfileLockMetadata{}, "python-pipfile-lock", "PythonPipfileLockMetadata"),
	jsonNames(pkg.PythonRequirementsMetadata{}, "python-pip-requirements", "PythonRequirementsMetadata"),
	jsonNames(pkg.RebarLockMetadata{}, "erlang-rebar-lock", "RebarLockMetadataType"),
	jsonNames(pkg.RDescriptionFileMetadata{}, "r-description", "RDescriptionFileMetadataType"),
	jsonNames(pkg.RpmDBMetadata{}, "redhat-rpm-db-record", "RpmMetadata", "RpmdbMetadata"),
	jsonNamesWithoutLookup(pkg.RpmArchiveMetadata{}, "redhat-rpm-archive", "RpmMetadata"), // the legacy value is split into two types, where the other is preferred
	jsonNames(pkg.SwiftPackageManagerMetadata{}, "swift-package-manager-lock", "SwiftPackageManagerMetadata"),
	jsonNames(pkg.CargoPackageMetadata{}, "rust-cargo-lock", "RustCargoPackageMetadata"),
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
