/*
Package cataloger provides the ability to process files from a container image or file system and discover packages
(gems, wheels, jars, rpms, debs, etc). Specifically, this package contains both a catalog function to utilize all
catalogers defined in child packages as well as the interface definition to implement a cataloger.
*/
package cataloger

import (
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/alpm"
	"github.com/anchore/syft/syft/pkg/cataloger/apkdb"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
	"github.com/anchore/syft/syft/pkg/cataloger/dart"
	"github.com/anchore/syft/syft/pkg/cataloger/deb"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
	"github.com/anchore/syft/syft/pkg/cataloger/elixir"
	"github.com/anchore/syft/syft/pkg/cataloger/erlang"
	"github.com/anchore/syft/syft/pkg/cataloger/githubactions"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/haskell"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/nix"
	"github.com/anchore/syft/syft/pkg/cataloger/php"
	"github.com/anchore/syft/syft/pkg/cataloger/portage"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/r"
	"github.com/anchore/syft/syft/pkg/cataloger/rpm"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	"github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/pkg/cataloger/swift"
)

const AllCatalogersPattern = "all"

// ImageCatalogers returns a slice of locally implemented catalogers that are fit for detecting installations of packages.
func ImageCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		alpm.NewAlpmdbCataloger(),
		apkdb.NewApkdbCataloger(),
		binary.NewCataloger(),
		deb.NewDpkgdbCataloger(),
		dotnet.NewDotnetPortableExecutableCataloger(),
		golang.NewGoModuleBinaryCataloger(cfg.Golang),
		java.NewJavaCataloger(cfg.Java()),
		java.NewNativeImageCataloger(),
		javascript.NewPackageCataloger(),
		nix.NewStoreCataloger(),
		php.NewComposerInstalledCataloger(),
		portage.NewPortageCataloger(),
		python.NewPythonPackageCataloger(),
		r.NewPackageCataloger(),
		rpm.NewRpmDBCataloger(),
		ruby.NewGemSpecCataloger(),
		sbom.NewSBOMCataloger(),
	}, cfg.Catalogers)
}

// DirectoryCatalogers returns a slice of locally implemented catalogers that are fit for detecting packages from index files (and select installations)
func DirectoryCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		alpm.NewAlpmdbCataloger(),
		apkdb.NewApkdbCataloger(),
		binary.NewCataloger(),
		cpp.NewConanCataloger(),
		dart.NewPubspecLockCataloger(),
		deb.NewDpkgdbCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		dotnet.NewDotnetPortableExecutableCataloger(),
		elixir.NewMixLockCataloger(),
		erlang.NewRebarLockCataloger(),
		githubactions.NewActionUsageCataloger(),
		githubactions.NewWorkflowUsageCataloger(),
		golang.NewGoModFileCataloger(cfg.Golang),
		golang.NewGoModuleBinaryCataloger(cfg.Golang),
		haskell.NewHackageCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		java.NewJavaGradleLockfileCataloger(),
		java.NewJavaPomCataloger(),
		java.NewNativeImageCataloger(),
		javascript.NewLockCataloger(),
		nix.NewStoreCataloger(),
		php.NewComposerLockCataloger(),
		portage.NewPortageCataloger(),
		python.NewPythonIndexCataloger(cfg.Python),
		python.NewPythonPackageCataloger(),
		rpm.NewFileCataloger(),
		rpm.NewRpmDBCataloger(),
		ruby.NewGemFileLockCataloger(),
		rust.NewCargoLockCataloger(),
		sbom.NewSBOMCataloger(),
		swift.NewCocoapodsCataloger(),
		swift.NewSwiftPackageManagerCataloger(),
	}, cfg.Catalogers)
}

// AllCatalogers returns all implemented catalogers
func AllCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		alpm.NewAlpmdbCataloger(),
		apkdb.NewApkdbCataloger(),
		binary.NewCataloger(),
		cpp.NewConanCataloger(),
		dart.NewPubspecLockCataloger(),
		deb.NewDpkgdbCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		dotnet.NewDotnetPortableExecutableCataloger(),
		elixir.NewMixLockCataloger(),
		erlang.NewRebarLockCataloger(),
		githubactions.NewActionUsageCataloger(),
		githubactions.NewWorkflowUsageCataloger(),
		golang.NewGoModFileCataloger(cfg.Golang),
		golang.NewGoModuleBinaryCataloger(cfg.Golang),
		haskell.NewHackageCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		java.NewJavaGradleLockfileCataloger(),
		java.NewJavaPomCataloger(),
		java.NewNativeImageCataloger(),
		javascript.NewLockCataloger(),
		javascript.NewPackageCataloger(),
		kernel.NewLinuxKernelCataloger(cfg.LinuxKernel),
		nix.NewStoreCataloger(),
		php.NewComposerInstalledCataloger(),
		php.NewComposerLockCataloger(),
		portage.NewPortageCataloger(),
		python.NewPythonIndexCataloger(cfg.Python),
		python.NewPythonPackageCataloger(),
		r.NewPackageCataloger(),
		rpm.NewFileCataloger(),
		rpm.NewRpmDBCataloger(),
		ruby.NewGemFileLockCataloger(),
		ruby.NewGemSpecCataloger(),
		rust.NewAuditBinaryCataloger(),
		rust.NewCargoLockCataloger(),
		sbom.NewSBOMCataloger(),
		swift.NewCocoapodsCataloger(),
		swift.NewSwiftPackageManagerCataloger(),
	}, cfg.Catalogers)
}

func RequestedAllCatalogers(cfg Config) bool {
	for _, enableCatalogerPattern := range cfg.Catalogers {
		if enableCatalogerPattern == AllCatalogersPattern {
			return true
		}
	}
	return false
}

func filterCatalogers(catalogers []pkg.Cataloger, enabledCatalogerPatterns []string) []pkg.Cataloger {
	// if cataloger is not set, all applicable catalogers are enabled by default
	if len(enabledCatalogerPatterns) == 0 {
		return catalogers
	}
	for _, enableCatalogerPattern := range enabledCatalogerPatterns {
		if enableCatalogerPattern == AllCatalogersPattern {
			return catalogers
		}
	}
	var keepCatalogers []pkg.Cataloger
	for _, cataloger := range catalogers {
		if contains(enabledCatalogerPatterns, cataloger.Name()) {
			keepCatalogers = append(keepCatalogers, cataloger)
			continue
		}
		log.Infof("skipping cataloger %q", cataloger.Name())
	}
	return keepCatalogers
}

func contains(enabledPartial []string, catalogerName string) bool {
	catalogerName = strings.TrimSuffix(catalogerName, "-cataloger")
	for _, partial := range enabledPartial {
		partial = strings.TrimSuffix(partial, "-cataloger")
		if partial == "" {
			continue
		}
		if hasFullWord(partial, catalogerName) {
			return true
		}
	}
	return false
}

func hasFullWord(targetPhrase, candidate string) bool {
	if targetPhrase == "cataloger" || targetPhrase == "" {
		return false
	}
	start := strings.Index(candidate, targetPhrase)
	if start == -1 {
		return false
	}

	if start > 0 && candidate[start-1] != '-' {
		return false
	}

	end := start + len(targetPhrase)
	if end < len(candidate) && candidate[end] != '-' {
		return false
	}
	return true
}
