package options

import (
	"fmt"
	"sort"
	"strings"

	"github.com/iancoleman/strcase"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/filecataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/file/cataloger/executable"
	"github.com/anchore/syft/syft/file/cataloger/filecontent"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
)

type Catalog struct {
	// high-level cataloger configuration
	Catalogers        []string            `yaml:"-" json:"catalogers" mapstructure:"catalogers"` // deprecated and not shown in yaml output
	DefaultCatalogers []string            `yaml:"default-catalogers" json:"default-catalogers" mapstructure:"default-catalogers"`
	SelectCatalogers  []string            `yaml:"select-catalogers" json:"select-catalogers" mapstructure:"select-catalogers"`
	Package           packageConfig       `yaml:"package" json:"package" mapstructure:"package"`
	File              fileConfig          `yaml:"file" json:"file" mapstructure:"file"`
	Scope             string              `yaml:"scope" json:"scope" mapstructure:"scope"`
	Parallelism       int                 `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"` // the number of catalog workers to run in parallel
	Relationships     relationshipsConfig `yaml:"relationships" json:"relationships" mapstructure:"relationships"`

	// ecosystem-specific cataloger configuration
	Golang      golangConfig      `yaml:"golang" json:"golang" mapstructure:"golang"`
	Java        javaConfig        `yaml:"java" json:"java" mapstructure:"java"`
	JavaScript  javaScriptConfig  `yaml:"javascript" json:"javascript" mapstructure:"javascript"`
	LinuxKernel linuxKernelConfig `yaml:"linux-kernel" json:"linux-kernel" mapstructure:"linux-kernel"`
	Python      pythonConfig      `yaml:"python" json:"python" mapstructure:"python"`

	// configuration for the source (the subject being analyzed)
	Registry   registryConfig `yaml:"registry" json:"registry" mapstructure:"registry"`
	From       []string       `yaml:"from" json:"from" mapstructure:"from"`
	Platform   string         `yaml:"platform" json:"platform" mapstructure:"platform"`
	Source     sourceConfig   `yaml:"source" json:"source" mapstructure:"source"`
	Exclusions []string       `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
	fangs.FieldDescriber
} = (*Catalog)(nil)

func DefaultCatalog() Catalog {
	return Catalog{
		Scope:         source.SquashedScope.String(),
		Package:       defaultPackageConfig(),
		LinuxKernel:   defaultLinuxKernelConfig(),
		Golang:        defaultGolangConfig(),
		File:          defaultFileConfig(),
		Relationships: defaultRelationshipsConfig(),
		Source:        defaultSourceConfig(),
		Parallelism:   1,
	}
}

func (cfg Catalog) ToSBOMConfig(id clio.Identification) *syft.CreateSBOMConfig {
	return syft.DefaultCreateSBOMConfig().
		WithTool(id.Name, id.Version).
		WithParallelism(cfg.Parallelism).
		WithRelationshipsConfig(cfg.ToRelationshipsConfig()).
		WithSearchConfig(cfg.ToSearchConfig()).
		WithPackagesConfig(cfg.ToPackagesConfig()).
		WithFilesConfig(cfg.ToFilesConfig()).
		WithCatalogerSelection(
			pkgcataloging.NewSelectionRequest().
				WithDefaults(cfg.DefaultCatalogers...).
				WithExpression(cfg.SelectCatalogers...),
		)
}

func (cfg Catalog) ToSearchConfig() cataloging.SearchConfig {
	return cataloging.SearchConfig{
		Scope: source.ParseScope(cfg.Scope),
	}
}

func (cfg Catalog) ToRelationshipsConfig() cataloging.RelationshipsConfig {
	return cataloging.RelationshipsConfig{
		PackageFileOwnership:        cfg.Relationships.PackageFileOwnership,
		PackageFileOwnershipOverlap: cfg.Relationships.PackageFileOwnershipOverlap,
		// note: this option was surfaced in the syft application configuration before this relationships section was added
		ExcludeBinaryPackagesWithFileOwnershipOverlap: cfg.Package.ExcludeBinaryOverlapByOwnership,
	}
}

func (cfg Catalog) ToFilesConfig() filecataloging.Config {
	hashers, err := intFile.Hashers(cfg.File.Metadata.Digests...)
	if err != nil {
		log.WithFields("error", err).Warn("unable to configure file hashers")
	}

	return filecataloging.Config{
		Selection: cfg.File.Metadata.Selection,
		Hashers:   hashers,
		Content: filecontent.Config{
			Globs:              cfg.File.Content.Globs,
			SkipFilesAboveSize: cfg.File.Content.SkipFilesAboveSize,
		},
		Executable: executable.Config{
			MIMETypes: executable.DefaultConfig().MIMETypes,
			Globs:     cfg.File.Executable.Globs,
		},
	}
}

func (cfg Catalog) ToPackagesConfig() pkgcataloging.Config {
	archiveSearch := cataloging.ArchiveSearchConfig{
		IncludeIndexedArchives:   cfg.Package.SearchIndexedArchives,
		IncludeUnindexedArchives: cfg.Package.SearchUnindexedArchives,
	}
	return pkgcataloging.Config{
		Binary: binary.DefaultClassifierCatalogerConfig(),
		Golang: golang.DefaultCatalogerConfig().
			WithSearchLocalModCacheLicenses(cfg.Golang.SearchLocalModCacheLicenses).
			WithLocalModCacheDir(cfg.Golang.LocalModCacheDir).
			WithSearchRemoteLicenses(cfg.Golang.SearchRemoteLicenses).
			WithProxy(cfg.Golang.Proxy).
			WithNoProxy(cfg.Golang.NoProxy).
			WithMainModuleVersion(
				golang.DefaultMainModuleVersionConfig().
					WithFromContents(cfg.Golang.MainModuleVersion.FromContents).
					WithFromBuildSettings(cfg.Golang.MainModuleVersion.FromBuildSettings).
					WithFromLDFlags(cfg.Golang.MainModuleVersion.FromLDFlags),
			),
		JavaScript: javascript.DefaultCatalogerConfig().
			WithSearchRemoteLicenses(cfg.JavaScript.SearchRemoteLicenses).
			WithNpmBaseURL(cfg.JavaScript.NpmBaseURL),
		LinuxKernel: kernel.LinuxKernelCatalogerConfig{
			CatalogModules: cfg.LinuxKernel.CatalogModules,
		},
		Python: python.CatalogerConfig{
			GuessUnpinnedRequirements: cfg.Python.GuessUnpinnedRequirements,
		},
		JavaArchive: java.DefaultArchiveCatalogerConfig().
			WithUseNetwork(cfg.Java.UseNetwork).
			WithMavenBaseURL(cfg.Java.MavenURL).
			WithArchiveTraversal(archiveSearch, cfg.Java.MaxParentRecursiveDepth),
	}
}

func (cfg *Catalog) AddFlags(flags clio.FlagSet) {
	var validScopeValues []string
	for _, scope := range source.AllScopes {
		validScopeValues = append(validScopeValues, strcase.ToDelimited(string(scope), '-'))
	}
	flags.StringVarP(&cfg.Scope, "scope", "s",
		fmt.Sprintf("selection of layers to catalog, options=%v", validScopeValues))

	flags.StringArrayVarP(&cfg.From, "from", "",
		"specify the source behavior to use (e.g. docker, registry, oci-dir, ...)")

	flags.StringVarP(&cfg.Platform, "platform", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')")

	flags.StringArrayVarP(&cfg.Exclusions, "exclude", "",
		"exclude paths from being scanned using a glob expression")

	flags.StringArrayVarP(&cfg.Catalogers, "catalogers", "",
		"enable one or more package catalogers")

	if pfp, ok := flags.(fangs.PFlagSetProvider); ok {
		if err := pfp.PFlagSet().MarkDeprecated("catalogers", "use: override-default-catalogers and select-catalogers"); err != nil {
			panic(err)
		}
	} else {
		panic("unable to mark flags as deprecated")
	}

	flags.StringArrayVarP(&cfg.DefaultCatalogers, "override-default-catalogers", "",
		"set the base set of catalogers to use (defaults to 'image' or 'directory' depending on the scan source)")

	flags.StringArrayVarP(&cfg.SelectCatalogers, "select-catalogers", "",
		"add, remove, and filter the catalogers to be used")

	flags.StringVarP(&cfg.Source.Name, "source-name", "",
		"set the name of the target being analyzed")

	flags.StringVarP(&cfg.Source.Version, "source-version", "",
		"set the version of the target being analyzed")

	flags.StringVarP(&cfg.Source.BasePath, "base-path", "",
		"base directory for scanning, no links will be followed above this directory, and all paths will be reported relative to this directory")
}

func (cfg *Catalog) DescribeFields(descriptions fangs.FieldDescriptionSet) {
	descriptions.Add(&cfg.Parallelism, "number of cataloger workers to run in parallel")
}

func (cfg *Catalog) PostLoad() error {
	usingLegacyCatalogers := len(cfg.Catalogers) > 0
	usingNewCatalogers := len(cfg.DefaultCatalogers) > 0 || len(cfg.SelectCatalogers) > 0

	if usingLegacyCatalogers && usingNewCatalogers {
		return fmt.Errorf("cannot use both 'catalogers' and 'select-catalogers'/'default-catalogers' flags")
	}

	flatten := func(l []string) []string {
		var out []string
		for _, v := range l {
			for _, s := range strings.Split(v, ",") {
				out = append(out, strings.TrimSpace(s))
			}
		}
		sort.Strings(out)

		return out
	}

	cfg.From = flatten(cfg.From)

	cfg.Catalogers = flatten(cfg.Catalogers)
	cfg.DefaultCatalogers = flatten(cfg.DefaultCatalogers)
	cfg.SelectCatalogers = flatten(cfg.SelectCatalogers)

	// for backwards compatibility
	cfg.DefaultCatalogers = append(cfg.DefaultCatalogers, cfg.Catalogers...)

	s := source.ParseScope(cfg.Scope)
	if s == source.UnknownScope {
		return fmt.Errorf("bad scope value %q", cfg.Scope)
	}

	return nil
}
