package packagemetadata

import (
	"github.com/anchore/syft/syft/pkg"
	"reflect"
	"strings"
)

var jsonNameFromType = map[reflect.Type][]string{
	reflect.TypeOf(pkg.AlpmMetadata{}):               nameList("arch-alpm-db-record", "AlpmMetadata"),
	reflect.TypeOf(pkg.ApkMetadata{}):                nameList("alpine-apk-db-record", "ApkMetadata"),
	reflect.TypeOf(pkg.BinaryMetadata{}):             nameList("binary-signature", "BinaryMetadata"),
	reflect.TypeOf(pkg.CocoapodsMetadata{}):          nameList("cocoa-podfile-lock", "CocoapodsMetadataType"),
	reflect.TypeOf(pkg.ConanLockMetadata{}):          nameList("c-conan-lock", "ConanLockMetadataType"),
	reflect.TypeOf(pkg.ConanMetadata{}):              nameList("c-conan", "ConanMetadataType"),
	reflect.TypeOf(pkg.DartPubMetadata{}):            nameList("dart-pubspec-lock", "DartPubMetadata"),
	reflect.TypeOf(pkg.DotnetDepsMetadata{}):         nameList("dotnet-deps", "DotnetDepsMetadata"),
	reflect.TypeOf(pkg.DpkgMetadata{}):               nameList("debian-dpkg-db-record", "DpkgMetadata"),
	reflect.TypeOf(pkg.GemMetadata{}):                nameList("ruby-gemspec", "GemMetadata"),
	reflect.TypeOf(pkg.GolangBinMetadata{}):          nameList("go-module-binary-buildinfo", "GolangBinMetadata", "GolangMetadata"),
	reflect.TypeOf(pkg.GolangModMetadata{}):          nameList("go-module", "GolangModMetadata"),
	reflect.TypeOf(pkg.HackageMetadata{}):            {"HackageMetadataType"}, // TODO: it seems that the stack.yaml/stack.lock/cabal.project.freeze have different purposes and could have different installation intentions    // TODO: !!!!!!!!!!!!!  this should be split based on the cabal and stack files
	reflect.TypeOf(pkg.JavaMetadata{}):               nameList("java-archive", "JavaMetadata"),
	reflect.TypeOf(pkg.KbPatchMetadata{}):            nameList("microsoft-kb-patch", "KbPatchMetadata"),
	reflect.TypeOf(pkg.LinuxKernelMetadata{}):        nameList("linux-kernel-archive", "LinuxKernelMetadata"),
	reflect.TypeOf(pkg.LinuxKernelModuleMetadata{}):  nameList("linux-kernel-module", "LinuxKernelModuleMetadata"),
	reflect.TypeOf(pkg.MixLockMetadata{}):            nameList("elixir-mix-lock", "MixLockMetadataType"),
	reflect.TypeOf(pkg.NixStoreMetadata{}):           nameList("nix-store", "NixStoreMetadata"),
	reflect.TypeOf(pkg.NpmPackageJSONMetadata{}):     nameList("javascript-npm-package", "NpmPackageJsonMetadata"),
	reflect.TypeOf(pkg.NpmPackageLockJSONMetadata{}): nameList("javascript-npm-package-lock", "NpmPackageLockJsonMetadata"), // TODO: !!!!!!!!!!!!!  should there be versions for these?
	reflect.TypeOf(pkg.PhpComposerJSONMetadata{}):    nameList("php-composer-lock", "PhpComposerJsonMetadata"),              // TODO: note composer json vs lock! // TODO: !!!!!!!!!!!!! also note that I think the installed.json and composer.lock are using the same metadata struct... which is probably wrong
	reflect.TypeOf(pkg.PortageMetadata{}):            nameList("gentoo-portage-db-record", "PortageMetadata"),
	reflect.TypeOf(pkg.PythonPackageMetadata{}):      nameList("python-package", "PythonPackageMetadata"),
	reflect.TypeOf(pkg.PythonPipfileLockMetadata{}):  nameList("python-pipfile-lock", "PythonPipfileLockMetadata"),
	reflect.TypeOf(pkg.PythonRequirementsMetadata{}): nameList("python-pip-requirements", "PythonRequirementsMetadata"),
	reflect.TypeOf(pkg.RebarLockMetadata{}):          nameList("erlang-rebar-lock", "RebarLockMetadataType"),
	reflect.TypeOf(pkg.RDescriptionFileMetadata{}):   nameList("r-description", "RDescriptionFileMetadataType"),
	reflect.TypeOf(pkg.RpmDBMetadata{}):              nameList("redhat-rpm-db-record", "RpmdbMetadata"),
	reflect.TypeOf(pkg.RpmArchiveMetadata{}):         nameList("redhat-rpm-archive", "RpmMetadata"),
	reflect.TypeOf(pkg.CargoPackageMetadata{}):       nameList("rust-cargo-lock", "RustCargoPackageMetadata"),
}

func nameList(id string, others ...string) []string {
	names := []string{id}
	for _, o := range others {
		names = append(names, expandLegacyNameVariants(o)...)
	}
	return names
}

func expandLegacyNameVariants(name string) []string {
	candidates := []string{name}
	if strings.HasSuffix(name, "MetadataType") {
		candidates = append(candidates, strings.TrimSuffix(name, "Type"))
	} else if strings.HasSuffix(name, "Metadata") {
		candidates = append(candidates, name+"Type")
	}
	return candidates
}

func AllNames() []string {
	names := make([]string, 0)
	for _, t := range AllTypes() {
		names = append(names, reflect.TypeOf(t).Name())
	}
	return names
}

func JSONName(metadata any) string {
	if vs, exists := jsonNameFromType[reflect.TypeOf(metadata)]; exists {
		return vs[0]
	}
	return ""
}

func ReflectTypeFromJSONName(name string) reflect.Type {
	name = strings.ToLower(name)
	for t, vs := range jsonNameFromType {
		for _, v := range vs {
			if v == name {
				return t
			}
		}
	}
	return nil
}
