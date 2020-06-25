package cmd

import (
	"os"

	"github.com/anchore/imgbom/internal/log"
)

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("could not start application: %w", err)
		os.Exit(1)
	}
}
