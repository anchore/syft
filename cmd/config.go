package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/internal/config"
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
