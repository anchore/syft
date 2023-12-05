package options

import (
	"fmt"
	"sort"
	"strings"

	"github.com/iancoleman/strcase"
	"github.com/mitchellh/go-homedir"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/pkg/cataloger"
	golangCataloger "github.com/anchore/syft/syft/pkg/cataloger/golang"
	javaCataloger "github.com/anchore/syft/syft/pkg/cataloger/java"
	javascriptCataloger "github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	pythonCataloger "github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
)

type Catalog struct {
	Catalogers                      []string     `yaml:"catalogers" json:"catalogers" mapstructure:"catalogers"`
	Package                         pkg          `yaml:"package" json:"package" mapstructure:"package"`
	Golang                          golang       `yaml:"golang" json:"golang" mapstructure:"golang"`
	Java                            java         `yaml:"java" json:"java" mapstructure:"java"`
	Javascript                      javascript   `yaml:"javascript" json:"javascript" mapstructure:"javascript"`
	LinuxKernel                     linuxKernel  `yaml:"linux-kernel" json:"linux-kernel" mapstructure:"linux-kernel"`
	Python                          python       `yaml:"python" json:"python" mapstructure:"python"`
	FileMetadata                    fileMetadata `yaml:"file-metadata" json:"file-metadata" mapstructure:"file-metadata"`
	FileContents                    fileContents `yaml:"file-contents" json:"file-contents" mapstructure:"file-contents"`
	Registry                        registry     `yaml:"registry" json:"registry" mapstructure:"registry"`
	Exclusions                      []string     `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	Platform                        string       `yaml:"platform" json:"platform" mapstructure:"platform"`
	Name                            string       `yaml:"name" json:"name" mapstructure:"name"`
	Source                          sourceCfg    `yaml:"source" json:"source" mapstructure:"source"`
	Parallelism                     int          `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`                                                                         // the number of catalog workers to run in parallel
	DefaultImagePullSource          string       `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"`                               // specify default image pull source
	BasePath                        string       `yaml:"base-path" json:"base-path" mapstructure:"base-path"`                                                                               // specify base path for all file paths
	ExcludeBinaryOverlapByOwnership bool         `yaml:"exclude-binary-overlap-by-ownership" json:"exclude-binary-overlap-by-ownership" mapstructure:"exclude-binary-overlap-by-ownership"` // exclude synthetic binary packages owned by os package files
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*Catalog)(nil)

func DefaultCatalog() Catalog {
	return Catalog{
		Package:                         defaultPkg(),
		LinuxKernel:                     defaultLinuxKernel(),
		FileMetadata:                    defaultFileMetadata(),
		FileContents:                    defaultFileContents(),
		Source:                          defaultSourceCfg(),
		Parallelism:                     1,
		ExcludeBinaryOverlapByOwnership: true,
	}
}

func (cfg *Catalog) AddFlags(flags clio.FlagSet) {
	var validScopeValues []string
	for _, scope := range source.AllScopes {
		validScopeValues = append(validScopeValues, strcase.ToDelimited(string(scope), '-'))
	}
	flags.StringVarP(&cfg.Package.Cataloger.Scope, "scope", "s",
		fmt.Sprintf("selection of layers to catalog, options=%v", validScopeValues))

	flags.StringVarP(&cfg.Platform, "platform", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')")

	flags.StringArrayVarP(&cfg.Exclusions, "exclude", "",
		"exclude paths from being scanned using a glob expression")

	flags.StringArrayVarP(&cfg.Catalogers, "catalogers", "",
		"enable one or more package catalogers")

	flags.StringVarP(&cfg.Source.Name, "name", "",
		"set the name of the target being analyzed")

	if pfp, ok := flags.(fangs.PFlagSetProvider); ok {
		flagSet := pfp.PFlagSet()
		flagSet.Lookup("name").Deprecated = "use: source-name"
	}

	flags.StringVarP(&cfg.Source.Name, "source-name", "",
		"set the name of the target being analyzed")

	flags.StringVarP(&cfg.Source.Version, "source-version", "",
		"set the version of the target being analyzed")

	flags.StringVarP(&cfg.BasePath, "base-path", "",
		"base directory for scanning, no links will be followed above this directory, and all paths will be reported relative to this directory")
}

func (cfg *Catalog) PostLoad() error {
	// parse options on this struct
	var catalogers []string
	for _, c := range cfg.Catalogers {
		for _, f := range strings.Split(c, ",") {
			catalogers = append(catalogers, strings.TrimSpace(f))
		}
	}
	sort.Strings(catalogers)
	cfg.Catalogers = catalogers

	if err := checkDefaultSourceValues(cfg.DefaultImagePullSource); err != nil {
		return err
	}

	if cfg.Name != "" {
		log.Warnf("name parameter is deprecated. please use: source-name. name will be removed in a future version")
		if cfg.Source.Name == "" {
			cfg.Source.Name = cfg.Name
		}
	}

	return nil
}

func (cfg Catalog) ToCatalogerConfig() cataloger.Config {
	return cataloger.Config{
		Search: cataloger.SearchConfig{
			IncludeIndexedArchives:   cfg.Package.SearchIndexedArchives,
			IncludeUnindexedArchives: cfg.Package.SearchUnindexedArchives,
			Scope:                    cfg.Package.Cataloger.GetScope(),
		},
		Catalogers:  cfg.Catalogers,
		Parallelism: cfg.Parallelism,
		Golang: golangCataloger.DefaultCatalogerConfig().
			WithSearchLocalModCacheLicenses(cfg.Golang.SearchLocalModCacheLicenses).
			WithLocalModCacheDir(cfg.Golang.LocalModCacheDir).
			WithSearchRemoteLicenses(cfg.Golang.SearchRemoteLicenses).
			WithProxy(cfg.Golang.Proxy).
			WithNoProxy(cfg.Golang.NoProxy),
		LinuxKernel: kernel.LinuxKernelCatalogerConfig{
			CatalogModules: cfg.LinuxKernel.CatalogModules,
		},
		Java: javaCataloger.DefaultArchiveCatalogerConfig().
			WithUseNetwork(cfg.Java.UseNetwork).
			WithMavenBaseURL(cfg.Java.MavenURL).
			WithArchiveTraversal(
				cataloging.ArchiveSearchConfig{
					IncludeIndexedArchives:   cfg.Package.SearchIndexedArchives,
					IncludeUnindexedArchives: cfg.Package.SearchUnindexedArchives,
				},
				cfg.Java.MaxParentRecursiveDepth),
		Javascript: javascriptCataloger.DefaultCatalogerConfig().
			WithSearchRemoteLicenses(cfg.Javascript.SearchRemoteLicenses).
			WithNpmBaseURL(cfg.Javascript.NpmBaseURL),
		Python: pythonCataloger.CatalogerConfig{
			GuessUnpinnedRequirements: cfg.Python.GuessUnpinnedRequirements,
		},
		ExcludeBinaryOverlapByOwnership: cfg.ExcludeBinaryOverlapByOwnership,
	}
}

var validDefaultSourceValues = []string{"registry", "docker", "podman", ""}

func checkDefaultSourceValues(source string) error {
	validValues := strset.New(validDefaultSourceValues...)
	if !validValues.Has(source) {
		validValuesString := strings.Join(validDefaultSourceValues, ", ")
		return fmt.Errorf("%s is not a valid default source; please use one of the following: %s''", source, validValuesString)
	}

	return nil
}

func expandFilePath(file string) (string, error) {
	if file != "" {
		expandedPath, err := homedir.Expand(file)
		if err != nil {
			return "", fmt.Errorf("unable to expand file path=%q: %w", file, err)
		}
		file = expandedPath
	}
	return file, nil
}
