package cmd

import (
	"context"

	"github.com/pkg/profile"
	"github.com/spf13/cobra"
)

const (
	convertExample = `  {{.appName}} {{.command}} original.json --to [FORMAT]
`
)

var (
	convertCmd = &cobra.Command{
		Use:           "convert original.json --to [FORMAT]",
		Args:          validateInputArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if appConfig.Dev.ProfileCPU {
				defer profile.Start(profile.CPUProfile).Stop()
			} else if appConfig.Dev.ProfileMem {
				defer profile.Start(profile.MemProfile).Stop()
			}

			return convertExec(cmd.Context(), cmd, args)
		},
	}
)

func convertExec(ctx context.Context, _ *cobra.Command, args []string) error {

	return nil
}
