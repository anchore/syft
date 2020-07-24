package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/anchore/syft/syft/presenter"
	"github.com/anchore/syft/syft/scope"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/format"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/logger"
	"github.com/anchore/syft/syft"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
	"gopkg.in/yaml.v2"
)

var appConfig *config.Application
var eventBus *partybus.Bus
var eventSubscription *partybus.Subscription
var cliOpts = config.CliOnlyOptions{}

func init() {
	setGlobalCliOptions()

	cobra.OnInitialize(
		initAppConfig,
		initLogging,
		logAppConfig,
		initEventBus,
	)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf(err.Error())
		os.Exit(1)
	}
}

func setGlobalCliOptions() {
	rootCmd.PersistentFlags().StringVarP(&cliOpts.ConfigPath, "config", "c", "", "application config file")

	// scan options
	flag := "scope"
	rootCmd.Flags().StringP(
		"scope", "s", scope.AllLayersScope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", scope.Options))
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	// output & formatting options
	flag = "output"
	rootCmd.Flags().StringP(
		flag, "o", presenter.TextPresenter.String(),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "quiet"
	rootCmd.Flags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.Flags().CountVarP(&cliOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}

func initAppConfig() {
	cfg, err := config.LoadConfigFromFile(viper.GetViper(), &cliOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}
	appConfig = cfg
}

func initLogging() {
	config := logger.LogConfig{
		EnableConsole: (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet,
		EnableFile:    appConfig.Log.FileLocation != "",
		Level:         appConfig.Log.LevelOpt,
		Structured:    appConfig.Log.Structured,
		FileLocation:  appConfig.Log.FileLocation,
	}

	logWrapper := logger.NewZapLogger(config)
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(logWrapper)
}

func logAppConfig() {
	appCfgStr, err := yaml.Marshal(&appConfig)

	if err != nil {
		log.Debugf("Could not display application config: %+v", err)
	} else {
		log.Debugf("Application config:\n%+v", format.Magenta.Format(string(appCfgStr)))
	}
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
}
