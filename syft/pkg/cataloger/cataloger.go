/*
Package cataloger provides the ability to process files from a container image or file system and discover packages
(gems, wheels, jars, rpms, debs, etc). Specifically, this package contains both a catalog function to utilize all
catalogers defined in child packages as well as the interface definition to implement a cataloger.
*/
package cataloger

import (
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/alpm"
	"github.com/anchore/syft/syft/pkg/cataloger/apkdb"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
	"github.com/anchore/syft/syft/pkg/cataloger/dart"
	"github.com/anchore/syft/syft/pkg/cataloger/deb"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/haskell"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/php"
	"github.com/anchore/syft/syft/pkg/cataloger/portage"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/rpm"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	"github.com/anchore/syft/syft/pkg/cataloger/swift"
	"github.com/anchore/syft/syft/source"
)

const AllCatalogersPattern = "all"

// Cataloger describes behavior for an object to participate in parsing container image or file system
// contents for the purpose of discovering Packages. Each concrete implementation should focus on discovering Packages
// for a specific Package Type or ecosystem.
type Cataloger interface {
	// Name returns a string that uniquely describes a cataloger
	Name() string
	// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
	Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error)
}

// ImageCatalogers returns a slice of locally implemented catalogers that are fit for detecting installations of packages.
func ImageCatalogers(cfg Config) []Cataloger {
	return filterCatalogers([]Cataloger{
		alpm.NewAlpmdbCataloger(),
		ruby.NewGemSpecCataloger(),
		python.NewPythonPackageCataloger(),
		php.NewPHPComposerInstalledCataloger(),
		javascript.NewJavascriptPackageCataloger(),
		deb.NewDpkgdbCataloger(),
		rpm.NewRpmdbCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModuleBinaryCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		portage.NewPortageCataloger(),
	}, cfg.Catalogers)
}

// DirectoryCatalogers returns a slice of locally implemented catalogers that are fit for detecting packages from index files (and select installations)
func DirectoryCatalogers(cfg Config) []Cataloger {
	return filterCatalogers([]Cataloger{
		alpm.NewAlpmdbCataloger(),
		ruby.NewGemFileLockCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(),
		php.NewPHPComposerLockCataloger(),
		javascript.NewJavascriptLockCataloger(),
		deb.NewDpkgdbCataloger(),
		rpm.NewRpmdbCataloger(),
		rpm.NewFileCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		java.NewJavaPomCataloger(),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModuleBinaryCataloger(),
		golang.NewGoModFileCataloger(),
		rust.NewCargoLockCataloger(),
		dart.NewPubspecLockCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		swift.NewCocoapodsCataloger(),
		cpp.NewConanfileCataloger(),
		portage.NewPortageCataloger(),
		haskell.NewHackageCataloger(),
	}, cfg.Catalogers)
}

// AllCatalogers returns all implemented catalogers
func AllCatalogers(cfg Config) []Cataloger {
	return filterCatalogers([]Cataloger{
		alpm.NewAlpmdbCataloger(),
		ruby.NewGemFileLockCataloger(),
		ruby.NewGemSpecCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(),
		javascript.NewJavascriptLockCataloger(),
		javascript.NewJavascriptPackageCataloger(),
		deb.NewDpkgdbCataloger(),
		rpm.NewRpmdbCataloger(),
		rpm.NewFileCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		java.NewJavaPomCataloger(),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModuleBinaryCataloger(),
		golang.NewGoModFileCataloger(),
		rust.NewCargoLockCataloger(),
		rust.NewRustAuditBinaryCataloger(),
		dart.NewPubspecLockCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		php.NewPHPComposerInstalledCataloger(),
		php.NewPHPComposerLockCataloger(),
		swift.NewCocoapodsCataloger(),
		cpp.NewConanfileCataloger(),
		portage.NewPortageCataloger(),
		haskell.NewHackageCataloger(),
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

func filterCatalogers(catalogers []Cataloger, enabledCatalogerPatterns []string) []Cataloger {
	// if cataloger is not set, all applicable catalogers are enabled by default
	if len(enabledCatalogerPatterns) == 0 {
		return catalogers
	}
	for _, enableCatalogerPattern := range enabledCatalogerPatterns {
		if enableCatalogerPattern == AllCatalogersPattern {
			return catalogers
		}
	}
	var keepCatalogers []Cataloger
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
		if strings.Contains(catalogerName, partial) {
			return true
		}
	}
	return false
}
