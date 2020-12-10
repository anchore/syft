package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/logger"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/presenter"
	"github.com/anchore/syft/syft/source"
	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
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
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func setGlobalCliOptions() {
	rootCmd.PersistentFlags().StringVarP(&cliOpts.ConfigPath, "config", "c", "", "application config file")

	// scan options
	flag := "scope"
	rootCmd.Flags().StringP(
		"scope", "s", source.SquashedScope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))
	if err := viper.BindPFlag(flag, rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	// output & formatting options
	flag = "output"
	rootCmd.Flags().StringP(
		flag, "o", string(presenter.TablePresenter),
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

	// upload options

	// since -h defaults to --help, we need to set a --help that does not have a shorthand
	rootCmd.Flags().Bool("help", false, "help for "+internal.ApplicationName)

	flag = "hostname"
	rootCmd.Flags().StringP(
		flag, "h", "",
		"the hostname of the Anchore Engine/Enterprise instance to upload to",
	)
	if err := viper.BindPFlag("anchore.hostname", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "username"
	rootCmd.Flags().StringP(
		flag, "u", "",
		"the username to authenticate against Anchore Engine/Enterprise",
	)
	if err := viper.BindPFlag("anchore.username", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "password"
	rootCmd.Flags().StringP(
		flag, "p", "",
		"the password to authenticate against Anchore Engine/Enterprise",
	)
	if err := viper.BindPFlag("anchore.password", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

}

func initAppConfig() {
	cfgVehicle := viper.GetViper()
	cfg, err := config.LoadApplicationConfig(cfgVehicle, cliOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}

	// check if upload should be done relative to the CLI and config behavior
	if !cfgVehicle.IsSet("anchore.upload-enabled") && rootCmd.Flags().Changed("hostname") {
		// we know the user didn't specify to upload in the config file and a --hostname option was provided (so set upload)
		cfg.Anchore.UploadEnabled = true
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
	log.Debugf("Application config:\n%+v", color.Magenta.Sprint(appConfig.String()))
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
}
