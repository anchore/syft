package config

import (
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/anchore/syft/syft/source"

	"github.com/adrg/xdg"
	"github.com/anchore/syft/internal"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var ErrApplicationConfigNotFound = fmt.Errorf("application config not found")

// Application is the main syft application configuration.
type Application struct {
	ConfigPath        string         `yaml:",omitempty" json:"configPath"`               // the location where the application config was read from (either from -c or discovered while loading)
	Output            string         `yaml:"output" json:"output" mapstructure:"output"` // -o, the Presenter hint string to use for report formatting
	Quiet             bool           `yaml:"quiet" json:"quiet" mapstructure:"quiet"`    // -q, indicates to not show any status output to stderr (ETUI or logging UI)
	Log               logging        `yaml:"log" json:"log" mapstructure:"log"`          // all logging-related options
	CliOptions        CliOnlyOptions `yaml:"-" json:"-"`                                 // all options only available through the CLI (not via env vars or config)
	Dev               Development    `yaml:"dev" json:"dev" mapstructure:"dev"`
	CheckForAppUpdate bool           `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Anchore           anchore        `yaml:"anchore" json:"anchore" mapstructure:"anchore"`                                        // options for interacting with Anchore Engine/Enterprise
	Package           Packages       `yaml:"package" json:"package" mapstructure:"package"`
	FileMetadata      FileMetadata   `yaml:"file-metadata" json:"file-metadata" mapstructure:"file-metadata"`
}

// LoadApplicationConfig populates the given viper object with application configuration discovered on disk
func LoadApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions) (*Application, error) {
	// the user may not have a config, and this is OK, we can use the default config + default cobra cli values instead
	setNonCliDefaultAppConfigValues(v)
	if err := readConfig(v, cliOpts.ConfigPath); err != nil && !errors.Is(err, ErrApplicationConfigNotFound) {
		return nil, err
	}

	config := &Application{
		CliOptions: cliOpts,
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	config.ConfigPath = v.ConfigFileUsed()

	if err := config.build(); err != nil {
		return nil, fmt.Errorf("invalid application config: %w", err)
	}

	return config, nil
}

// build inflates simple config values into syft native objects (or other complex objects) after the config is fully read in.
func (cfg *Application) build() error {
	if cfg.Quiet {
		// TODO: this is bad: quiet option trumps all other logging options
		// we should be able to quiet the console logging and leave file logging alone...
		// ... this will be an enhancement for later
		cfg.Log.LevelOpt = logrus.PanicLevel
	} else {
		if cfg.Log.Level != "" {
			if cfg.CliOptions.Verbosity > 0 {
				return fmt.Errorf("cannot explicitly set log level (cfg file or env var) and use -v flag together")
			}

			lvl, err := logrus.ParseLevel(strings.ToLower(cfg.Log.Level))
			if err != nil {
				return fmt.Errorf("bad log level configured (%q): %w", cfg.Log.Level, err)
			}
			// set the log level explicitly
			cfg.Log.LevelOpt = lvl
		} else {
			// set the log level implicitly
			switch v := cfg.CliOptions.Verbosity; {
			case v == 1:
				cfg.Log.LevelOpt = logrus.InfoLevel
			case v >= 2:
				cfg.Log.LevelOpt = logrus.DebugLevel
			default:
				cfg.Log.LevelOpt = logrus.WarnLevel
			}
		}
	}

	if cfg.Anchore.Host == "" && cfg.Anchore.Dockerfile != "" {
		return fmt.Errorf("cannot provide dockerfile option without enabling upload")
	}

	for _, builder := range []func() error{
		cfg.Package.build,
		cfg.FileMetadata.build,
	} {
		if err := builder(); err != nil {
			return err
		}
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

// setNonCliDefaultAppConfigValues ensures that there are sane defaults for values that do not have CLI equivalent options (where there would already be a default value)
func setNonCliDefaultAppConfigValues(v *viper.Viper) {
	v.SetDefault("anchore.path", "")
	v.SetDefault("log.structured", false)
	v.SetDefault("check-for-app-update", true)
	v.SetDefault("dev.profile-cpu", false)
	v.SetDefault("dev.profile-mem", false)
	v.SetDefault("package.cataloger.enabled", true)
	v.SetDefault("file-metadata.cataloger.enabled", true)
	v.SetDefault("file-metadata.cataloger.scope", source.SquashedScope)
	v.SetDefault("file-metadata.digests", []string{"sha256"})
}
