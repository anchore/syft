package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/stereoscope"
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

	setGlobalFormatOptions()
	setGlobalUploadOptions()
}

func setGlobalFormatOptions() {
	// output & formatting options
	flag := "output"
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
}

func setGlobalUploadOptions() {
	flag := "host"
	rootCmd.Flags().StringP(
		flag, "H", "",
		"the hostname or URL of the Anchore Enterprise instance to upload to",
	)
	if err := viper.BindPFlag("anchore.host", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "username"
	rootCmd.Flags().StringP(
		flag, "u", "",
		"the username to authenticate against Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.username", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "password"
	rootCmd.Flags().StringP(
		flag, "p", "",
		"the password to authenticate against Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.password", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "dockerfile"
	rootCmd.Flags().StringP(
		flag, "d", "",
		"include dockerfile for upload to Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.dockerfile", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '#{flag}': #{err}")
		os.Exit(1)
	}

	flag = "overwrite-existing-image"
	rootCmd.Flags().Bool(
		flag, false,
		"overwrite an existing image during the upload to Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.overwrite-existing-image", rootCmd.Flags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '#{flag}': #{err}")
		os.Exit(1)
	}
}

func initAppConfig() {
	cfgVehicle := viper.GetViper()
	wasHostnameSet := rootCmd.Flags().Changed("host")
	cfg, err := config.LoadApplicationConfig(cfgVehicle, cliOpts, wasHostnameSet)
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
	log.Debugf("Application config:\n%+v", color.Magenta.Sprint(appConfig.String()))
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
}
