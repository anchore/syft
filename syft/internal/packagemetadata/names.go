package packagemetadata

import (
	"github.com/anchore/syft/syft/pkg"
	"reflect"
	"strings"
)

var jsonNameFromType = map[reflect.Type][]string{
	reflect.TypeOf(pkg.AlpmMetadata{}):               nameList("arch-alpm-catalog-entry", "AlpmMetadata"),
	reflect.TypeOf(pkg.ApkMetadata{}):                nameList("alpine-apk-catalog-entry", "ApkMetadata"),
	reflect.TypeOf(pkg.BinaryMetadata{}):             nameList("binary-signature", "BinaryMetadata"),
	reflect.TypeOf(pkg.CocoapodsMetadata{}):          nameList("cocoapod-lockfile", "CocoapodsMetadataType"),
	reflect.TypeOf(pkg.ConanLockMetadata{}):          nameList("c-conan-lockfile", "ConanLockMetadataType"),
	reflect.TypeOf(pkg.ConanMetadata{}):              nameList("c-conan-guidefile", "ConanMetadataType"),
	reflect.TypeOf(pkg.DartPubMetadata{}):            nameList("dart-pubspec-lockfile", "DartPubMetadata"),
	reflect.TypeOf(pkg.DotnetDepsMetadata{}):         nameList("dotnet-deps-guidefile", "DotnetDepsMetadata"),
	reflect.TypeOf(pkg.DpkgMetadata{}):               nameList("debian-dpkg-catalog-entry", "DpkgMetadata"),
	reflect.TypeOf(pkg.GemMetadata{}):                nameList("ruby-gemspec-guide", "GemMetadata"),                          // TODO: !!!!!!!!!!!!!  note, there is no gemfile metadata!
	reflect.TypeOf(pkg.GolangBinMetadata{}):          nameList("go-binary-buildinfo", "GolangBinMetadata", "GolangMetadata"), // TODO: !!!!!!!!!!!!!  think on this...
	reflect.TypeOf(pkg.GolangModMetadata{}):          nameList("go-module-(guidefile?)", "GolangModMetadata"),                // TODO: !!!!!!!!!!!!!  this isn't saying go.mod... as this could include go.sum info too someday??
	reflect.TypeOf(pkg.HackageMetadata{}):            {"HackageMetadataType"},                                                // TODO: it seems that the stack.yaml/stack.lock/cabal.project.freeze have different purposes and could have different installation intentions    // TODO: !!!!!!!!!!!!!  this should be split based on the cabal and stack files
	reflect.TypeOf(pkg.JavaMetadata{}):               nameList("java-archive", "JavaMetadata"),
	reflect.TypeOf(pkg.KbPackageMetadata{}):          nameList("microsoft-kb-package", "KbPackageMetadata"), // TODO: !!!!!!!!!!!!! not referenced in syft anywhere, but needed for enterprise
	reflect.TypeOf(pkg.LinuxKernelMetadata{}):        nameList("linux-kernel-archive", "LinuxKernelMetadata"),
	reflect.TypeOf(pkg.LinuxKernelModuleMetadata{}):  nameList("linux-kernel-module", "LinuxKernelModuleMetadata"),
	reflect.TypeOf(pkg.MixLockMetadata{}):            nameList("elixir-mix-lockfile", "MixLockMetadataType"),
	reflect.TypeOf(pkg.NixStoreMetadata{}):           nameList("nix-store", "NixStoreMetadata"),
	reflect.TypeOf(pkg.NpmPackageJSONMetadata{}):     nameList("javascript-npm-guidefile", "NpmPackageJsonMetadata"),
	reflect.TypeOf(pkg.NpmPackageLockJSONMetadata{}): nameList("javascript-npm-lockfile", "NpmPackageLockJsonMetadata"), // TODO: !!!!!!!!!!!!!  should there be versions for these?
	reflect.TypeOf(pkg.PhpComposerJSONMetadata{}):    nameList("php-composer-lockfile", "PhpComposerJsonMetadata"),      // TODO: note composer json vs lock! // TODO: !!!!!!!!!!!!! also note that I think the installed.json and composer.lock are using the same metadata struct... which is probably wrong
	reflect.TypeOf(pkg.PortageMetadata{}):            nameList("gentoo-portage-catalog-entry", "PortageMetadata"),
	reflect.TypeOf(pkg.PythonPackageMetadata{}):      nameList("python-egg-or-wheel-...", "PythonPackageMetadata"), // TODO: TODO: !!!!!!!!!!!!! this should be split based on the egg and wheel files (I think)
	reflect.TypeOf(pkg.PythonPipfileLockMetadata{}):  nameList("python-pipfile-lockfile", "PythonPipfileLockMetadata"),
	reflect.TypeOf(pkg.PythonRequirementsMetadata{}): nameList("python-requirements-guidefile", "PythonRequirementsMetadata"),
	reflect.TypeOf(pkg.RebarLockMetadata{}):          nameList("erlang-rebar-lockfile", "RebarLockMetadataType"),
	reflect.TypeOf(pkg.RDescriptionFileMetadata{}):   nameList("r-description-guidefile", "RDescriptionFileMetadataType"),
	reflect.TypeOf(pkg.RpmMetadata{}):                nameList("rpm-db-entry", "RpmdbMetadata"), // TODO: !!!!!!!!!!! this should get split into DB and file metadata types
	//reflect.TypeOf(pkg.RpmMetadata{}):                nameList("rpm-manifest", "RpmMetadata"),   // TODO: !!!!!!!!!!! this should get split into DB and file metadata types
	reflect.TypeOf(pkg.CargoPackageMetadata{}): nameList("rust-cargo-lockfile", "RustCargoPackageMetadata"),
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
