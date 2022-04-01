package options

import "github.com/spf13/cobra"

// RootOptions define flags and options for the root syft cli.
type RootOptions struct {
	ConfigPath string
	Quiet      bool
	Verbosity  int
}

func (o *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&o.ConfigPath, "config", "c", "",
		"application config file")

	cmd.PersistentFlags().BoolVarP(&o.Quiet, "quiet", "q", false,
		"suppress all logging output")

	cmd.PersistentFlags().CountVarP(&o.Verbosity, "verbose", "v",
		"increase verbosity (-v = info, -vv = debug)")
}
