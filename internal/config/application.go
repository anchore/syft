package config

import (
	"errors"
	"fmt"
	"path"
	"reflect"

	"github.com/adrg/xdg"
	"github.com/anchore/syft/internal"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

var (
	ErrApplicationConfigNotFound = fmt.Errorf("application config not found")
	catalogerEnabledDefault      = false
)

type defaultValueLoader interface {
	loadDefaultValues(*viper.Viper)
}

// Application is the main syft application configuration.
type Application struct {
	// the location where the application config was read from (either from -c or discovered while loading); default .syft.yaml
	Config    string `yaml:"config,omitempty" json:"config" mapstructure:"config"`
	Verbosity uint   `yaml:"verbosity,omitempty" json:"verbosity" mapstructure:"verbosity"`
	// -q, indicates to not show any status output to stderr (ETUI or logging UI)
	Quiet              bool               `yaml:"quiet" json:"quiet" mapstructure:"quiet"`
	Outputs            []string           `yaml:"output" json:"output" mapstructure:"output"`                                           // -o, the format to use for output
	File               string             `yaml:"file" json:"file" mapstructure:"file"`                                                 // --file, the file to write report output to
	CheckForAppUpdate  bool               `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
	Anchore            anchore            `yaml:"anchore" json:"anchore" mapstructure:"anchore"`                                        // options for interacting with Anchore Engine/Enterprise
	Dev                development        `yaml:"dev" json:"dev" mapstructure:"dev"`
	Log                logging            `yaml:"log" json:"log" mapstructure:"log"` // all logging-related options
	Package            pkg                `yaml:"package" json:"package" mapstructure:"package"`
	FileMetadata       FileMetadata       `yaml:"file-metadata" json:"file-metadata" mapstructure:"file-metadata"`
	FileClassification fileClassification `yaml:"file-classification" json:"file-classification" mapstructure:"file-classification"`
	FileContents       fileContents       `yaml:"file-contents" json:"file-contents" mapstructure:"file-contents"`
	Secrets            secrets            `yaml:"secrets" json:"secrets" mapstructure:"secrets"`
	Registry           registry           `yaml:"registry" json:"registry" mapstructure:"registry"`
	Exclusions         []string           `yaml:"exclude" json:"exclude" mapstructure:"exclude"`
	Attest             attest             `yaml:"attest" json:"attest" mapstructure:"attest"`
	Platform           string             `yaml:"platform" json:"platform" mapstructure:"platform"`
}

func (a *Application) LoadAllValues(v *viper.Viper, configPath string) error {
	// priority order: viper.Set, flag, env, config, kv, defaults
	// flags have already been loaded into viper by command construction

	// load environment variables
	v.SetEnvPrefix(internal.ApplicationName)
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()

	// check if user specified config; otherwise read all possible paths
	if err := loadConfig(v, configPath); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Not Found; ignore this error
		}
	}

	// load default config values into viper
	loadDefaultValues(v)

	// unmarshal fully populated viper object onto config
	err := v.Unmarshal(a)
	if err != nil {
		return err
	}
	return nil
}

// init loads the default configuration values into the viper instance (before the config values are read and parsed).
func loadDefaultValues(v *viper.Viper) {
	// set the default values for primitive fields in this struct
	v.SetDefault("quiet", false)
	v.SetDefault("check-for-app-update", true)

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
	appCfgStr, err := yaml.Marshal(&cfg)

	if err != nil {
		return err.Error()
	}

	return string(appCfgStr)
}

func loadConfig(v *viper.Viper, configPath string) error {
	var err error
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

	return nil
}
