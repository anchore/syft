package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/logger"
	"github.com/anchore/syft/syft"
	"github.com/gookit/color"
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
		initEventBus,
	)
}

// provided to disambiguate the root vs packages command, whichever is indicated by the cli args will be set here.
// TODO: when the root alias command is removed, this function (hack) can be removed
var activeCmd *cobra.Command

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}

func initCmdAliasBindings() {
	// TODO: when the root alias command is removed, this function (hack) can be removed

	activeCmd = rootCmd
	for i, a := range os.Args {
		if i == 0 {
			// don't consider the bin
			continue
		}
		if a == "packages" {
			// this is positively the first subcommand directive, and is "packages"
			activeCmd = packagesCmd
			break
		}
		if !strings.HasPrefix("-", a) {
			// this is the first non-switch provided and was not "packages"
			break
		}
	}

	if activeCmd == rootCmd {
		// note: cobra supports command deprecation, however the command name is empty and does not report to stderr
		fmt.Fprintln(os.Stderr, color.New(color.Bold, color.Red).Sprintf("The root command is deprecated, please use the 'packages' subcommand"))
	}

	// note: we need to lazily bind config options since they are shared between both the root command
	// and the packages command. Otherwise there will be global viper state that is in contention.
	// See for more details: https://github.com/spf13/viper/issues/233 . Additionally, the bindings must occur BEFORE
	// reading the application configuration, which implies that it must be an initializer (or rewrite the command
	// initialization structure against typical patterns used with cobra, which is somewhat extreme for a
	// temporary alias)
	if err := bindConfigOptions(activeCmd.Flags()); err != nil {
		panic(err)
	}
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
