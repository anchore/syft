package cmd

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var (
	attestCmd = &cobra.Command{
		Use:   "attest [SOURCE]",
		Short: "Generate a package SBOM and attach it as an attestation to [SOURCE]",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container image and attach it as an attestation.",
		Example: internal.Tprintf(packagesExample, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "attest",
		}),
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
				return fmt.Errorf("cannot profile CPU and memory simultaneously")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return attestExec(cmd, args)
		},
	}
)

func attestExec(_ *cobra.Command, args []string) error {
	// could be an image or a directory, with or without a scheme
	userInput := args[0]

	src, cleanup, err := source.New(userInput, appConfig.Registry.ToOptions(), appConfig.Exclusions)
	if err != nil {
		return fmt.Errorf("failed to construct source from user input %q: %w", userInput, err)
	}


	return nil
}

func init() {
	setAttestFlags(attestCmd.Flags())
	rootCmd.AddCommand(attestCmd)
}

func setAttestFlags(flags *pflag.FlagSet) {
	// Key options
	flags.StringP(
		"key", "", "",
		"private key to use to sign attestation",
	)
}
