package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/pflag"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/logger"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

var (
	appConfig         *config.Application
	eventBus          *partybus.Bus
	eventSubscription *partybus.Subscription
)

func init() {
	cobra.OnInitialize(
		initCmdAliasBindings,
		initAppConfig,
		initLogging,
		logAppConfig,
		checkForApplicationUpdate,
		logAppVersion,
		initEventBus,
	)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}

// we must setup the config-cli bindings first before the application configuration is parsed. However, this cannot
// be done without determining what the primary command that the config options should be bound to since there are
// shared concerns (the root-packages alias).
func initCmdAliasBindings() {
	activeCmd, _, err := rootCmd.Find(os.Args[1:])
	if err != nil {
		panic(err)
	}

	// enable all cataloger by default if power-user command is run
	if activeCmd == powerUserCmd {
		config.PowerUserCatalogerEnabledDefault()
	}

	// set bindings based on the packages alias
	switch activeCmd {
	case packagesCmd, rootCmd:
		// note: we need to lazily bind config options since they are shared between both the root command
		// and the packages command. Otherwise there will be global viper state that is in contention.
		// See for more details: https://github.com/spf13/viper/issues/233 . Additionally, the bindings must occur BEFORE
		// reading the application configuration, which implies that it must be an initializer (or rewrite the command
		// initialization structure against typical patterns used with cobra, which is somewhat extreme for a
		// temporary alias)
		if err = bindPackagesConfigOptions(activeCmd.Flags()); err != nil {
			panic(err)
		}
	case attestCmd:
		// the --output and --platform options are independently defined flags, but a shared config option
		if err = bindSharedConfigOption(attestCmd.Flags()); err != nil {
			panic(err)
		}
		// even though the root command or packages command is NOT being run, we still need default bindings
		// such that application config parsing passes.
		if err = bindExclusivePackagesConfigOptions(packagesCmd.Flags()); err != nil {
			panic(err)
		}
	default:
		// even though the root command or packages command is NOT being run, we still need default bindings
		// such that application config parsing passes.
		if err = bindPackagesConfigOptions(packagesCmd.Flags()); err != nil {
			panic(err)
		}
	}
}

func bindSharedConfigOption(flags *pflag.FlagSet) error {
	if err := viper.BindPFlag("output", flags.Lookup("output")); err != nil {
		return err
	}

	if err := viper.BindPFlag("platform", flags.Lookup("platform")); err != nil {
		return err
	}

	return nil
}

func initAppConfig() {
	cfg, err := config.LoadApplicationConfig(viper.GetViper(), persistentOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}

	appConfig = cfg
}

func initLogging() {
	cfg := logger.LogrusConfig{
		EnableConsole: (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet,
		EnableFile:    appConfig.Log.FileLocation != "",
		Level:         appConfig.Log.LevelOpt,
		Structured:    appConfig.Log.Structured,
		FileLocation:  appConfig.Log.FileLocation,
	}

	logWrapper := logger.NewLogrusLogger(cfg)
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(&logger.LogrusNestedLogger{
		Logger: logWrapper.Logger.WithField("from-lib", "stereoscope"),
	})
}

func logAppConfig() {
	log.Debugf("application config:\n%+v", color.Magenta.Sprint(appConfig.String()))
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
}

func logAppVersion() {
	versionInfo := version.FromBuild()
	log.Infof("syft version: %s", versionInfo.Version)

	var fields map[string]interface{}
	bytes, err := json.Marshal(versionInfo)
	if err != nil {
		return
	}
	err = json.Unmarshal(bytes, &fields)
	if err != nil {
		return
	}

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for idx, field := range keys {
		value := fields[field]
		branch := "├──"
		if idx == len(fields)-1 {
			branch = "└──"
		}
		log.Debugf("  %s %s: %s", branch, field, value)
	}
}
