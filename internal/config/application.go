package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"

	"github.com/anchore/fangs/config"
	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger"
	golangCataloger "github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
)

// Application is the main syft application configuration.
type Application struct {
	// the location where the application config was read from (either from -c or discovered while loading); default .syft.yaml
	ConfigPath string `yaml:"configPath,omitempty" json:"configPath" mapstructure:"config"`
	Verbosity  int    `yaml:"verbosity,omitempty" json:"verbosity" mapstructure:"verbosity"`
	// -q, indicates to not show any status output to stderr (ETUI or logging UI)
	Quiet                  bool         `yaml:"quiet" json:"quiet" mapstructure:"quiet"`
	Outputs                []string     `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the format to use for output
	OutputTemplatePath     string       `yaml:"output-template-path" json:"output-template-path" mapstructure:"output-template-path"` // -t template file to use for output
	File                   string       `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	CheckForAppUpdate      bool         `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Dev                    development  `yaml:"dev" json:"dev" mapstructure:"dev"`
	Log                    logging      `yaml:"log" json:"log" mapstructure:"log"` // all logging-related options
	Catalogers             []string     `yaml:"catalogers" json:"catalogers" mapstructure:"catalogers"`
	Package                pkgOptions   `yaml:"package" json:"package" mapstructure:"package"`
	Golang                 golang       `yaml:"golang" json:"golang" mapstructure:"golang"`
	LinuxKernel            linuxKernel  `yaml:"linux-kernel" json:"linux-kernel" mapstructure:"linux-kernel"`
	Attest                 attest       `yaml:"attest" json:"attest" mapstructure:"attest"`
	FileMetadata           FileMetadata `yaml:"file-metadata" json:"file-metadata" mapstructure:"file-metadata"`
	FileContents           fileContents `yaml:"file-contents" json:"file-contents" mapstructure:"file-contents"`
	Secrets                secrets      `yaml:"secrets" json:"secrets" mapstructure:"secrets"`
	Registry               registry     `yaml:"registry" json:"registry" mapstructure:"registry"`
	Exclusions             []string     `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	Platform               string       `yaml:"platform" json:"platform" mapstructure:"platform"`
	Name                   string       `yaml:"name" json:"name" mapstructure:"name"`
	Parallelism            int          `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"`                                           // the number of catalog workers to run in parallel
	DefaultImagePullSource string       `yaml:"default-image-pull-source" json:"default-image-pull-source" mapstructure:"default-image-pull-source"` // specify default image pull source
}

var _ config.PostLoad = (*Application)(nil)

func NewApplication() *Application {
	return &Application{
		CheckForAppUpdate: true,
		Outputs:           []string{"table"},
		Package:           newPkgOptions(true),
		Attest:            newAttest(),
		FileMetadata:      newFileMetadata(false),
		FileContents:      newFileContents(false),
		Secrets:           newSecrets(false),
		Golang:            newGolang(),
		LinuxKernel:       newLinuxKernel(),
		Log:               newLogging(),
		Registry:          newRegistry(),
		Parallelism:       1,
	}
}

func (cfg Application) ToCatalogerConfig() cataloger.Config {
	return cataloger.Config{
		Search: cataloger.SearchConfig{
			IncludeIndexedArchives:   cfg.Package.SearchIndexedArchives,
			IncludeUnindexedArchives: cfg.Package.SearchUnindexedArchives,
			Scope:                    cfg.Package.Cataloger.ScopeOpt,
		},
		Catalogers:  cfg.Catalogers,
		Parallelism: cfg.Parallelism,
		Golang: golangCataloger.NewGoCatalogerOpts().
			WithSearchLocalModCacheLicenses(cfg.Golang.SearchLocalModCacheLicenses).
			WithLocalModCacheDir(cfg.Golang.LocalModCacheDir).
			WithSearchRemoteLicenses(cfg.Golang.SearchRemoteLicenses).
			WithProxy(cfg.Golang.Proxy).
			WithNoProxy(cfg.Golang.NoProxy),
		LinuxKernel: kernel.LinuxCatalogerConfig{
			CatalogModules: cfg.LinuxKernel.CatalogModules,
		},
	}
}

func (cfg *Application) FangsConfig() config.Config {
	c := config.NewConfig(internal.ApplicationName)
	c.File = cfg.ConfigPath
	c.Logger = log.Log

	// DEPRECATED: this is emulating an undesirable bug and will be removed in 1.0
	// see: https://github.com/anchore/syft/issues/1634
	c.Finders = []config.Finder{
		// 1. look for a directly configured file
		config.FindDirect,
		// 2. look for ./.<appname>.<ext>
		config.FindInCwd,
		// 3. look for ./.<appname>/config.<ext>
		config.FindInAppNameSubdir,
		// FIXME: remove this FindConfigYamlInCwd entry (and the entire block customizing the Finders)
		config.FindConfigYamlInCwd,
		// 4. look for ~/.<appname>.<ext>
		config.FindInHomeDir,
		// 5. look for <appname>/config.<ext> in xdg locations
		config.FindInXDG,
	}

	return c
}

func (cfg *Application) LoadAllValues(cmd *cobra.Command) error {
	if err := checkDefaultSourceValues(cfg.DefaultImagePullSource); err != nil {
		return err
	}
	return config.Load(cfg.FangsConfig(), cmd, cfg)
}

func (cfg *Application) PostLoad() error {
	// parse options on this struct
	var catalogers []string
	for _, c := range cfg.Catalogers {
		for _, f := range strings.Split(c, ",") {
			catalogers = append(catalogers, strings.TrimSpace(f))
		}
	}
	sort.Strings(catalogers)
	cfg.Catalogers = catalogers

	// parse application config options
	for _, optionFn := range []func() error{
		cfg.parseLogLevelOption,
		cfg.parseFile,
	} {
		if err := optionFn(); err != nil {
			return err
		}
	}
	return nil
}

func (cfg *Application) parseLogLevelOption() error {
	switch {
	case cfg.Quiet:
		// TODO: this is bad: quiet option trumps all other logging options (such as to a file on disk)
		// we should be able to quiet the console logging and leave file logging alone...
		// ... this will be an enhancement for later
		cfg.Log.Level = logger.DisabledLevel

	case cfg.Verbosity > 0:
		cfg.Log.Level = logger.LevelFromVerbosity(cfg.Verbosity, logger.WarnLevel, logger.InfoLevel, logger.DebugLevel, logger.TraceLevel)

	case cfg.Log.Level != "":
		var err error
		cfg.Log.Level, err = logger.LevelFromString(string(cfg.Log.Level))
		if err != nil {
			return err
		}

		if logger.IsVerbose(cfg.Log.Level) {
			cfg.Verbosity = 1
		}
	default:
		cfg.Log.Level = logger.WarnLevel
	}

	return nil
}

func (cfg *Application) parseFile() error {
	if cfg.File != "" {
		expandedPath, err := homedir.Expand(cfg.File)
		if err != nil {
			return fmt.Errorf("unable to expand file path=%q: %w", cfg.File, err)
		}
		cfg.File = expandedPath
	}
	return nil
}

func (cfg Application) String() string {
	// yaml is pretty human friendly (at least when compared to json)
	appStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appStr)
}

var validDefaultSourceValues = []string{"registry", "docker", "podman", ""}

func checkDefaultSourceValues(source string) error {
	validValues := internal.NewStringSet(validDefaultSourceValues...)
	if !validValues.Contains(source) {
		validValuesString := strings.Join(validDefaultSourceValues, ", ")
		return fmt.Errorf("%s is not a valid default source; please use one of the following: %s''", source, validValuesString)
	}

	return nil
}

func (cfg *Application) IsVerbose() (result bool) {
	isPipedInput, err := internal.IsPipedInput()
	if err != nil {
		// since we can't tell if there was piped input we assume that there could be to disable the ETUI
		log.Warnf("unable to determine if there is piped input: %+v", err)
		return true
	}
	// verbosity should consider if there is piped input (in which case we should not show the ETUI)
	return cfg.Verbosity > 0 || isPipedInput
}
