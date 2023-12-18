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
	"github.com/anchore/syft/syft/pkg/cataloger/alpine"
	"github.com/anchore/syft/syft/pkg/cataloger/arch"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
	"github.com/anchore/syft/syft/pkg/cataloger/dart"
	"github.com/anchore/syft/syft/pkg/cataloger/debian"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
	"github.com/anchore/syft/syft/pkg/cataloger/elixir"
	"github.com/anchore/syft/syft/pkg/cataloger/erlang"
	"github.com/anchore/syft/syft/pkg/cataloger/gentoo"
	"github.com/anchore/syft/syft/pkg/cataloger/githubactions"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/haskell"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/nix"
	"github.com/anchore/syft/syft/pkg/cataloger/php"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/r"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	"github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/pkg/cataloger/swift"
)

const AllCatalogersPattern = "all"

// ImageCatalogers returns a slice of locally implemented catalogers that are fit for detecting installations of packages.
func ImageCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		arch.NewDBCataloger(),
		alpine.NewDBCataloger(),
		binary.NewCataloger(),
		cpp.NewConanInfoCataloger(),
		debian.NewDBCataloger(),
		dotnet.NewDotnetPortableExecutableCataloger(),
		golang.NewGoModuleBinaryCataloger(cfg.Golang),
		java.NewArchiveCataloger(cfg.JavaConfig()),
		java.NewNativeImageCataloger(),
		javascript.NewPackageCataloger(),
		nix.NewStoreCataloger(),
		php.NewComposerInstalledCataloger(),
		gentoo.NewPortageCataloger(),
		python.NewInstalledPackageCataloger(),
		r.NewPackageCataloger(),
		redhat.NewDBCataloger(),
		ruby.NewInstalledGemSpecCataloger(),
		sbom.NewCataloger(),
	}, cfg.Catalogers)
}

// DirectoryCatalogers returns a slice of locally implemented catalogers that are fit for detecting packages from index files (and select installations)
func DirectoryCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		arch.NewDBCataloger(),
		alpine.NewDBCataloger(),
		binary.NewCataloger(),
		cpp.NewConanCataloger(),
		dart.NewPubspecLockCataloger(),
		debian.NewDBCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		dotnet.NewDotnetPortableExecutableCataloger(),
		elixir.NewMixLockCataloger(),
		erlang.NewRebarLockCataloger(),
		githubactions.NewActionUsageCataloger(),
		githubactions.NewWorkflowUsageCataloger(),
		golang.NewGoModuleFileCataloger(cfg.Golang),
		golang.NewGoModuleBinaryCataloger(cfg.Golang),
		haskell.NewHackageCataloger(),
		java.NewArchiveCataloger(cfg.JavaConfig()),
		java.NewGradleLockfileCataloger(),
		java.NewPomCataloger(cfg.JavaConfig()),
		java.NewNativeImageCataloger(),
		javascript.NewLockCataloger(cfg.Javascript),
		nix.NewStoreCataloger(),
		php.NewComposerLockCataloger(),
		gentoo.NewPortageCataloger(),
		python.NewPackageCataloger(cfg.Python),
		python.NewInstalledPackageCataloger(),
		redhat.NewArchiveCataloger(),
		redhat.NewDBCataloger(),
		ruby.NewGemFileLockCataloger(),
		ruby.NewGemSpecCataloger(),
		rust.NewCargoLockCataloger(),
		sbom.NewCataloger(),
		swift.NewCocoapodsCataloger(),
		swift.NewSwiftPackageManagerCataloger(),
	}, cfg.Catalogers)
}

// AllCatalogers returns all implemented catalogers
func AllCatalogers(cfg Config) []pkg.Cataloger {
	return filterCatalogers([]pkg.Cataloger{
		arch.NewDBCataloger(),
		alpine.NewDBCataloger(),
		binary.NewCataloger(),
		cpp.NewConanCataloger(),
		dart.NewPubspecLockCataloger(),
		debian.NewDBCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		dotnet.NewDotnetPortableExecutableCataloger(),
		elixir.NewMixLockCataloger(),
		erlang.NewRebarLockCataloger(),
		githubactions.NewActionUsageCataloger(),
		githubactions.NewWorkflowUsageCataloger(),
		golang.NewGoModuleFileCataloger(cfg.Golang),
		golang.NewGoModuleBinaryCataloger(cfg.Golang),
		haskell.NewHackageCataloger(),
		java.NewArchiveCataloger(cfg.JavaConfig()),
		java.NewGradleLockfileCataloger(),
		java.NewPomCataloger(cfg.JavaConfig()),
		java.NewNativeImageCataloger(),
		javascript.NewLockCataloger(cfg.Javascript),
		javascript.NewPackageCataloger(),
		kernel.NewLinuxKernelCataloger(cfg.LinuxKernel),
		nix.NewStoreCataloger(),
		php.NewComposerInstalledCataloger(),
		php.NewComposerLockCataloger(),
		gentoo.NewPortageCataloger(),
		python.NewPackageCataloger(cfg.Python),
		python.NewInstalledPackageCataloger(),
		r.NewPackageCataloger(),
		redhat.NewArchiveCataloger(),
		redhat.NewDBCataloger(),
		ruby.NewGemFileLockCataloger(),
		ruby.NewGemSpecCataloger(),
		ruby.NewInstalledGemSpecCataloger(),
		rust.NewAuditBinaryCataloger(),
		rust.NewCargoLockCataloger(),
		sbom.NewCataloger(),
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
