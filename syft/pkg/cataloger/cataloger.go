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
	// UsesExternalSources returns if the cataloger uses external sources, such as querying a database
	UsesExternalSources() bool
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
		rpm.NewFileCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModuleBinaryCataloger(),
		dotnet.NewDotnetDepsCataloger(),
		portage.NewPortageCataloger(),
	}, cfg)
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
	}, cfg)
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
	}, cfg)
}

// RequestedAllCatalogers returns true if all Catalogers have been requested. Takes into account cfg.ExternalSourcesEnabled
func RequestedAllCatalogers(cfg Config) bool {
	// if external sources are disabled, only return false if there actually are any catalogers that use external sources
	if !cfg.ExternalSourcesEnabled {
		for _, cat := range AllCatalogers(Config{Catalogers: []string{"all"}, ExternalSourcesEnabled: true}) {
			if cat.UsesExternalSources() {
				return false
			}
		}
	}

	for _, enableCatalogerPattern := range cfg.Catalogers {
		if enableCatalogerPattern == AllCatalogersPattern {
			return true
		}
	}
	return false
}

func filterForExternalSources(catalogers []Cataloger, cfg Config) []Cataloger {
	if cfg.ExternalSourcesEnabled {
		return catalogers
	}

	var enabledCatalogers []Cataloger
	for _, cataloger := range catalogers {
		if !cataloger.UsesExternalSources() {
			enabledCatalogers = append(enabledCatalogers, cataloger)
		} else {
			log.Infof("cataloger %v will not be used because external sources are disabled", cataloger.Name())
		}
	}

	return enabledCatalogers
}

func filterCatalogers(catalogers []Cataloger, cfg Config) []Cataloger {
	enabledCatalogerPatterns := cfg.Catalogers

	// if cataloger is not set, all applicable catalogers are enabled by default
	if len(enabledCatalogerPatterns) == 0 {
		return filterForExternalSources(catalogers, cfg)
	}
	for _, enableCatalogerPattern := range enabledCatalogerPatterns {
		if enableCatalogerPattern == AllCatalogersPattern {
			return filterForExternalSources(catalogers, cfg)
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
	return filterForExternalSources(keepCatalogers, cfg)
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
