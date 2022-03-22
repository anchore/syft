package config

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/cataloger/fileclassifier"

	"github.com/adrg/xdg"
	"github.com/anchore/syft/internal"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var ErrApplicationConfigNotFound = fmt.Errorf("application config not found")

var catalogerEnabledDefault = false

type defaultValueLoader interface {
	loadDefaultValues(*viper.Viper)
}

type parser interface {
	parseConfigValues() error
}

// Application is the main syft application configuration.
type Application struct {
	ConfigPath         string             `yaml:",omitempty" json:"configPath"`                                                         // the location where the application config was read from (either from -c or discovered while loading)
	Outputs            []string           `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the format to use for output
	File               string             `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	Quiet              bool               `yaml:"quiet" json:"quiet" mapstructure:"quiet"`                                              // -q, indicates to not show any status output to stderr (ETUI or logging UI)
	CheckForAppUpdate  bool               `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Anchore            anchore            `yaml:"anchore" json:"anchore" mapstructure:"anchore"`                                        // options for interacting with Anchore Engine/Enterprise
	CliOptions         CliOnlyOptions     `yaml:"-" json:"-"`                                                                           // all options only available through the CLI (not via env vars or config)
	Dev                development        `yaml:"dev" json:"dev" mapstructure:"dev"`
	Log                logging            `yaml:"log" json:"log" mapstructure:"log"` // all logging-related options
	Package            pkg                `yaml:"package" json:"package" mapstructure:"package"`
	FileMetadata       FileMetadata       `yaml:"file-metadata" json:"file-metadata" mapstructure:"file-metadata"`
	FileClassification fileClassification `yaml:"file-classification" json:"file-classification" mapstructure:"file-classification"`
	FileContents       fileContents       `yaml:"file-contents" json:"file-contents" mapstructure:"file-contents"`
	Secrets            secretsCfg         `yaml:"secrets" json:"secrets" mapstructure:"secrets"`
	Registry           registry           `yaml:"registry" json:"registry" mapstructure:"registry"`
	Exclusions         []string           `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	Attest             attest             `yaml:"attest" json:"attest" mapstructure:"attest"`
	Platform           string             `yaml:"platform" json:"platform" mapstructure:"platform"`
}

func (cfg Application) ToCatalogingConfig() (*syft.CatalogingConfig, error) {
	digests, err := file.DigestHashesByName(cfg.FileMetadata.Digests...)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config item 'file-metadata.digests': %w", err)
	}

	secretsConfig, err := cfg.Secrets.ToConfig()
	if err != nil {
		return nil, err
	}

	return &syft.CatalogingConfig{
		// note: package catalogers cannot be determined until runtime
		ToolName:             internal.ApplicationName,
		ToolVersion:          version.FromBuild().Version,
		ToolConfiguration:    cfg,
		Scope:                cfg.Package.Cataloger.ScopeOpt,
		ProcessTasksInSerial: false,
		CaptureFileMetadata:  cfg.FileMetadata.Cataloger.Enabled,
		DigestHashes:         digests,
		CaptureSecrets:       cfg.Secrets.Cataloger.Enabled,
		SecretsConfig:        *secretsConfig,
		SecretsScope:         cfg.Secrets.Cataloger.ScopeOpt,
		ClassifyFiles:        cfg.FileClassification.Cataloger.Enabled,
		FileClassifiers:      fileclassifier.DefaultClassifiers(),
		ContentsConfig:       cfg.FileContents.ToConfig(),
	}, nil
}

// PowerUserCatalogerEnabledDefault switches all catalogers to be enabled when running power-user command
func PowerUserCatalogerEnabledDefault() {
	catalogerEnabledDefault = true
}

func newApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions) *Application {
	config := &Application{
		CliOptions: cliOpts,
	}
	config.loadDefaultValues(v)
	return config
}

// LoadApplicationConfig populates the given viper object with application configuration discovered on disk
func LoadApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions) (*Application, error) {
	// the user may not have a config, and this is OK, we can use the default config + default cobra cli values instead
	config := newApplicationConfig(v, cliOpts)

	if err := readConfig(v, cliOpts.ConfigPath); err != nil && !errors.Is(err, ErrApplicationConfigNotFound) {
		return nil, err
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	config.ConfigPath = v.ConfigFileUsed()

	if err := config.parseConfigValues(); err != nil {
		return nil, fmt.Errorf("invalid application config: %w", err)
	}

	return config, nil
}

// init loads the default configuration values into the viper instance (before the config values are read and parsed).
func (cfg Application) loadDefaultValues(v *viper.Viper) {
	// set the default values for primitive fields in this struct
	v.SetDefault("check-for-app-update", true)

	// for each field in the configuration struct, see if the field implements the defaultValueLoader interface and invoke it if it does
	value := reflect.ValueOf(cfg)
	for i := 0; i < value.NumField(); i++ {
		// note: the defaultValueLoader method receiver is NOT a pointer receiver.
		if loadable, ok := value.Field(i).Interface().(defaultValueLoader); ok {
			// the field implements defaultValueLoader, call it
			loadable.loadDefaultValues(v)
		}
	}
}

func (cfg *Application) parseConfigValues() error {
	// parse application config options
	for _, optionFn := range []func() error{
		cfg.parseUploadOptions,
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

func (cfg *Application) parseUploadOptions() error {
	if cfg.Anchore.Host == "" && cfg.Anchore.Dockerfile != "" {
		return fmt.Errorf("cannot provide dockerfile option without enabling upload")
	}
	return nil
}

func (cfg *Application) parseLogLevelOption() error {
	switch {
	case cfg.Quiet:
		// TODO: this is bad: quiet option trumps all other logging options (such as to a file on disk)
		// we should be able to quiet the console logging and leave file logging alone...
		// ... this will be an enhancement for later
		cfg.Log.LevelOpt = logrus.PanicLevel
	case cfg.Log.Level != "":
		if cfg.CliOptions.Verbosity > 0 {
			return fmt.Errorf("cannot explicitly set log level (cfg file or env var) and use -v flag together")
		}

		lvl, err := logrus.ParseLevel(strings.ToLower(cfg.Log.Level))
		if err != nil {
			return fmt.Errorf("bad log level configured (%q): %w", cfg.Log.Level, err)
		}

		cfg.Log.LevelOpt = lvl
		if cfg.Log.LevelOpt >= logrus.InfoLevel {
			cfg.CliOptions.Verbosity = 1
		}
	default:

		switch v := cfg.CliOptions.Verbosity; {
		case v == 1:
			cfg.Log.LevelOpt = logrus.InfoLevel
		case v >= 2:
			cfg.Log.LevelOpt = logrus.DebugLevel
		default:
			cfg.Log.LevelOpt = logrus.ErrorLevel
		}
	}

	if cfg.Log.Level == "" {
		cfg.Log.Level = cfg.Log.LevelOpt.String()
	}

	return nil
}

func (cfg Application) String() string {
	// yaml is pretty human friendly (at least when compared to json)
	appCfgStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}

// readConfig attempts to read the given config path from disk or discover an alternate store location
// nolint:funlen
func readConfig(v *viper.Viper, configPath string) error {
	var err error
	v.AutomaticEnv()
	v.SetEnvPrefix(internal.ApplicationName)
	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// use explicitly the given user config
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("unable to read application config=%q : %w", configPath, err)
		}
		// don't fall through to other options if the config path was explicitly provided
		return nil
	}

	// start searching for valid configs in order...

	// 1. look for .<appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName("." + internal.ApplicationName)
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	// 2. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + internal.ApplicationName)
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
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
			return nil
		} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
			return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
		}
	}

	// 4. look for <appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)
	v.AddConfigPath(path.Join(xdg.ConfigHome, internal.ApplicationName))
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, internal.ApplicationName))
	}
	v.SetConfigName("config")
	if err = v.ReadInConfig(); err == nil {
		return nil
	} else if !errors.As(err, &viper.ConfigFileNotFoundError{}) {
		return fmt.Errorf("unable to parse config=%q: %w", v.ConfigFileUsed(), err)
	}

	return ErrApplicationConfigNotFound
}
