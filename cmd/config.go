package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/internal/config"
	"github.com/anchore/imgbom/internal/logger"
	"github.com/spf13/viper"
)

var appConfig *config.Application

func loadAppConfig() {
	cfg, err := config.LoadConfigFromFile(viper.GetViper(), &cliOpts)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}
	appConfig = cfg
}

func setupLoggingFromAppConfig() {
	config := logger.LogConfig{
		EnableConsole: appConfig.Log.FileLocation == "" && !appConfig.Quiet,
		EnableFile:    appConfig.Log.FileLocation != "",
		Level:         appConfig.Log.LevelOpt,
		FormatAsJSON:  appConfig.Log.FormatAsJSON,
		FileLocation:  appConfig.Log.FileLocation,
	}

	imgbom.SetLogger(logger.NewZapLogger(config))
}
