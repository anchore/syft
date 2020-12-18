package config

import (
	"fmt"
	"path"
	"strings"

	"github.com/adrg/xdg"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/presenter"
	"github.com/anchore/syft/syft/source"
	"github.com/mitchellh/go-homedir"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// Application is the main syft application configuration.
type Application struct {
	ConfigPath        string           `yaml:",omitempty"`                   // the location where the application config was read from (either from -c or discovered while loading)
	PresenterOpt      presenter.Option `yaml:"-"`                            // -o, the native Presenter.Option to use for report formatting
	Output            string           `yaml:"output" mapstructure:"output"` // -o, the Presenter hint string to use for report formatting
	ScopeOpt          source.Scope     `yaml:"-"`                            // -s, the native source.Scope option to use for how to catalog the container image
	Scope             string           `yaml:"scope" mapstructure:"scope"`   // -s, the source.Scope string hint for how to catalog the container image
	Quiet             bool             `yaml:"quiet" mapstructure:"quiet"`   // -q, indicates to not show any status output to stderr (ETUI or logging UI)
	Log               logging          `yaml:"log"  mapstructure:"log"`      // all logging-related options
	CliOptions        CliOnlyOptions   `yaml:"-"`                            // all options only available through the CLI (not via env vars or config)
	Dev               Development      `mapstructure:"dev"`
	CheckForAppUpdate bool             `yaml:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Anchore           anchore          `yaml:"anchore" mapstructure:"anchore"`                           // options for interacting with Anchore Engine/Enterprise
}

// CliOnlyOptions are options that are in the application config in memory, but are only exposed via CLI switches (not from unmarshaling a config file)
type CliOnlyOptions struct {
	ConfigPath string // -c. where the read config is on disk
	Verbosity  int    // -v or -vv , controlling which UI (ETUI vs logging) and what the log level should be
}

// logging contains all logging-related configuration options available to the user via the application config.
type logging struct {
	Structured   bool         `yaml:"structured" mapstructure:"structured"` // show all log entries as JSON formatted strings
	LevelOpt     logrus.Level `yaml:"level"`                                // the native log level object used by the logger
	Level        string       `yaml:"-" mapstructure:"level"`               // the log level string hint
	FileLocation string       `yaml:"file" mapstructure:"file"`             // the file path to write logs to
}

type anchore struct {
	// upload options
	UploadEnabled          bool   `yaml:"upload-enabled"  mapstructure:"upload-enabled"`                    // whether to upload results to Anchore Engine/Enterprise (defaults to "false" unless there is the presence of -h CLI option)
	Host                   string `yaml:"host" mapstructure:"host"`                                         // -H , hostname of the engine/enterprise instance to upload to
	Path                   string `yaml:"path" mapstructure:"path"`                                         // override the engine/enterprise API upload path
	Username               string `yaml:"username" mapstructure:"username"`                                 // -u , username to authenticate upload
	Password               string `yaml:"password" mapstructure:"password"`                                 // -p , password to authenticate upload
	Dockerfile             string `yaml:"dockerfile" mapstructure:"dockerfile"`                             // -d , dockerfile to attach for upload
	OverwriteExistingImage bool   `yaml:"overwrite-existing-image" mapstructure:"overwrite-existing-image"` // --overwrite-existing-image , if any of the SBOM components have already been uploaded this flag will ensure they are overwritten with the current upload
}

type Development struct {
	ProfileCPU bool `mapstructure:"profile-cpu"`
	ProfileMem bool `mapstructure:"profile-mem"`
}

// LoadApplicationConfig populates the given viper object with application configuration discovered on disk
func LoadApplicationConfig(v *viper.Viper, cliOpts CliOnlyOptions, wasHostnameSet bool) (*Application, error) {
	// the user may not have a config, and this is OK, we can use the default config + default cobra cli values instead
	setNonCliDefaultValues(v)
	_ = readConfig(v, cliOpts.ConfigPath)

	config := &Application{
		CliOptions: cliOpts,
	}

	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("unable to parse config: %w", err)
	}
	config.ConfigPath = v.ConfigFileUsed()

	if err := config.build(v, wasHostnameSet); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return config, nil
}

// build inflates simple config values into syft native objects (or other complex objects) after the config is fully read in.
func (cfg *Application) build(v *viper.Viper, wasHostnameSet bool) error {
	// set the presenter
	presenterOption := presenter.ParseOption(cfg.Output)
	if presenterOption == presenter.UnknownPresenter {
		return fmt.Errorf("bad --output value '%s'", cfg.Output)
	}
	cfg.PresenterOpt = presenterOption

	// set the source
	scopeOption := source.ParseScope(cfg.Scope)
	if scopeOption == source.UnknownScope {
		return fmt.Errorf("bad --scope value '%s'", cfg.Scope)
	}
	cfg.ScopeOpt = scopeOption

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
	// check if upload should be done relative to the CLI and config behavior
	if !v.IsSet("anchore.upload-enabled") && wasHostnameSet {
		// we know the user didn't specify to upload in the config file and a --hostname option was provided (so set upload)
		cfg.Anchore.UploadEnabled = true
	}

	if !cfg.Anchore.UploadEnabled && cfg.Anchore.Dockerfile != "" {
		return fmt.Errorf("cannot provide dockerfile option without enabling upload")
	}

	return nil
}

func (cfg Application) String() string {
	// redact sensitive information
	if cfg.Anchore.Username != "" {
		cfg.Anchore.Username = "********"
	}

	if cfg.Anchore.Password != "" {
		cfg.Anchore.Password = "********"
	}

	// yaml is pretty human friendly (at least when compared to json)
	appCfgStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}

// readConfig attempts to read the given config path from disk or discover an alternate store location
func readConfig(v *viper.Viper, configPath string) error {
	v.AutomaticEnv()
	v.SetEnvPrefix(internal.ApplicationName)
	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// use explicitly the given user config
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err == nil {
			return nil
		}
		// don't fall through to other options if this fails
		return fmt.Errorf("unable to read config: %v", configPath)
	}

	// start searching for valid configs in order...

	// 1. look for .<appname>.yaml (in the current directory)
	v.AddConfigPath(".")
	v.SetConfigName(internal.ApplicationName)
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	// 2. look for .<appname>/config.yaml (in the current directory)
	v.AddConfigPath("." + internal.ApplicationName)
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	// 3. look for ~/.<appname>.yaml
	home, err := homedir.Dir()
	if err == nil {
		v.AddConfigPath(home)
		v.SetConfigName("." + internal.ApplicationName)
		if err := v.ReadInConfig(); err == nil {
			return nil
		}
	}

	// 4. look for <appname>/config.yaml in xdg locations (starting with xdg home config dir, then moving upwards)
	v.AddConfigPath(path.Join(xdg.ConfigHome, internal.ApplicationName))
	for _, dir := range xdg.ConfigDirs {
		v.AddConfigPath(path.Join(dir, internal.ApplicationName))
	}
	v.SetConfigName("config")
	if err := v.ReadInConfig(); err == nil {
		return nil
	}

	return fmt.Errorf("application config not found")
}

// setNonCliDefaultValues ensures that there are sane defaults for values that do not have CLI equivalent options (where there would already be a default value)
func setNonCliDefaultValues(v *viper.Viper) {
	v.SetDefault("log.level", "")
	v.SetDefault("log.file", "")
	v.SetDefault("log.structured", false)
	v.SetDefault("check-for-app-update", true)
	v.SetDefault("dev.profile-cpu", false)
	v.SetDefault("dev.profile-mem", false)
}
