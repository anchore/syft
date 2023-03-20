package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"reflect"
	"sort"
	"strings"

	"github.com/adrg/xdg"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"

	"github.com/anchore/go-logger"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg/cataloger"
)

var (
	ErrApplicationConfigNotFound = fmt.Errorf("application config not found")
	catalogerEnabledDefault      = false
)

type defaultValueLoader interface {
	loadDefaultValues(*viper.Viper)
}

type parser interface {
	parseConfigValues() error
}

// Application is the main syft application configuration.
type Application struct {
	// the location where the application config was read from (either from -c or discovered while loading); default .syft.yaml
	ConfigPath string `yaml:"configPath,omitempty" json:"configPath" mapstructure:"config"`
	Verbosity  uint   `yaml:"verbosity,omitempty" json:"verbosity" mapstructure:"verbosity"`
	// -q, indicates to not show any status output to stderr (ETUI or logging UI)
	Quiet              bool               `yaml:"quiet" json:"quiet" mapstructure:"quiet"`
	Outputs            []string           `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the format to use for output
	OutputTemplatePath string             `yaml:"output-template-path" json:"output-template-path" mapstructure:"output-template-path"` // -t template file to use for output
	File               string             `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	CheckForAppUpdate  bool               `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Dev                development        `yaml:"dev" json:"dev" mapstructure:"dev"`
	Log                logging            `yaml:"log" json:"log" mapstructure:"log"` // all logging-related options
	Catalogers         []string           `yaml:"catalogers" json:"catalogers" mapstructure:"catalogers"`
	Package            pkg                `yaml:"package" json:"package" mapstructure:"package"`
	Attest             attest             `yaml:"attest" json:"attest" mapstructure:"attest"`
	FileMetadata       FileMetadata       `yaml:"file-metadata" json:"file-metadata" mapstructure:"file-metadata"`
	FileClassification fileClassification `yaml:"file-classification" json:"file-classification" mapstructure:"file-classification"`
	FileContents       fileContents       `yaml:"file-contents" json:"file-contents" mapstructure:"file-contents"`
	Secrets            secrets            `yaml:"secrets" json:"secrets" mapstructure:"secrets"`
	Registry           registry           `yaml:"registry" json:"registry" mapstructure:"registry"`
	Exclusions         []string           `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	Platform           string             `yaml:"platform" json:"platform" mapstructure:"platform"`
	Name               string             `yaml:"name" json:"name" mapstructure:"name"`
	Parallelism        int                `yaml:"parallelism" json:"parallelism" mapstructure:"parallelism"` // the number of catalog workers to run in parallel
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
	}
}

func (cfg *Application) LoadAllValues(v *viper.Viper, configPath string) error {
	// priority order: viper.Set, flag, env, config, kv, defaults
	// flags have already been loaded into viper by command construction

	// check if user specified config; otherwise read all possible paths
	if err := loadConfig(v, configPath); err != nil {
		var notFound *viper.ConfigFileNotFoundError
		if errors.As(err, &notFound) {
			log.Debugf("no config file found, using defaults")
		} else {
			return fmt.Errorf("unable to load config: %w", err)
		}
	}

	// load default config values into viper
	loadDefaultValues(v)

	// load environment variables
	v.SetEnvPrefix(internal.ApplicationName)
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()

	// unmarshal fully populated viper object onto config
	err := v.Unmarshal(cfg)
	if err != nil {
		return err
	}

	// Convert all populated config options to their internal application values ex: scope string => scopeOpt source.Scope
	return cfg.parseConfigValues()
}

func (cfg *Application) parseConfigValues() error {
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
	// parse nested config options
	// for each field in the configuration struct, see if the field implements the parser interface
	// note: the app config is a pointer, so we need to grab the elements explicitly (to traverse the address)
	value := reflect.ValueOf(cfg).Elem()
	for i := 0; i < value.NumField(); i++ {
		// note: since the interface method of parser is a pointer receiver we need to get the value of the field as a pointer.
		if parsable, ok := value.Field(i).Addr().Interface().(parser); ok {
			// the field implements parser, call it
			if err := parsable.parseConfigValues(); err != nil {
				return err
			}
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
		cfg.Log.Level = logger.LevelFromVerbosity(int(cfg.Verbosity), logger.WarnLevel, logger.InfoLevel, logger.DebugLevel, logger.TraceLevel)

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

// init loads the default configuration values into the viper instance (before the config values are read and parsed).
func loadDefaultValues(v *viper.Viper) {
	// set the default values for primitive fields in this struct
	v.SetDefault("quiet", false)
	v.SetDefault("check-for-app-update", true)
	v.SetDefault("catalogers", nil)
	v.SetDefault("parallelism", 1)

	// for each field in the configuration struct, see if the field implements the defaultValueLoader interface and invoke it if it does
	value := reflect.ValueOf(Application{})
	for i := 0; i < value.NumField(); i++ {
		// note: the defaultValueLoader method receiver is NOT a pointer receiver.
		if loadable, ok := value.Field(i).Interface().(defaultValueLoader); ok {
			// the field implements defaultValueLoader, call it
			loadable.loadDefaultValues(v)
		}
	}
}

func (cfg Application) String() string {
	// yaml is pretty human friendly (at least when compared to json)
	appaStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appaStr)
}

// nolint:funlen
func loadConfig(v *viper.Viper, configPath string) error {
	var err error
	// use explicitly the given user config
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("unable to read application config=%q : %w", configPath, err)
		}
		v.Set("config", v.ConfigFileUsed())
		// don't fall through to other options if the config path was explicitly provided
		return nil
	}

	// start searching for valid configs in order...
	// 1. look for .<appname>.yaml (in the current directory)
	confFilePath := "." + internal.ApplicationName

	// TODO: Remove this before v1.0.0
	// See syft #1634
	v.AddConfigPath(".")
	v.SetConfigName(confFilePath)

	// check if config.yaml exists in the current directory
	// DEPRECATED: this will be removed in v1.0.0
	if _, err := os.Stat("config.yaml"); err == nil {
		log.Warn("DEPRECATED: ./config.yaml as a configuration file is deprecated and will be removed as an option in v1.0.0, please rename to .syft.yaml")
	}

	if _, err := os.Stat(confFilePath + ".yaml"); err == nil {
		if err = v.ReadInConfig(); err == nil {
			v.Set("config", v.ConfigFileUsed())
			return nil
		} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
		}
	}

	// 2. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + internal.ApplicationName)
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		v.Set("config", v.ConfigFileUsed())
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 3. look for ~/.<appname>.yaml
	home, err := homedir.Dir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName("." + internal.ApplicationName)
		if err = v.ReadInConfig(); err == nil {
			v.Set("config", v.ConfigFileUsed())
			return nil
		} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
		}
	}

	// 4. look for .<appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)

	v.SetConfigName("config")
	configPath = path.Join(xdg.ConfigHome, "."+internal.ApplicationName)
	v.AddConfigPath(configPath)
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, "."+internal.ApplicationName))
	}
	if err = v.ReadInConfig(); err == nil {
		v.Set("config", v.ConfigFileUsed())
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}
	return nil
}
