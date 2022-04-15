package options

import "github.com/spf13/cobra"

type RootOptions struct {
	Config  string
	Quiet   bool
	Verbose int
}

var _ Interface = (*RootOptions)(nil)

func (o *RootOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(&o.Config, "config", "c", "", "application config file")
	cmd.PersistentFlags().BoolVarP(&o.Quiet, "quiet", "q", false, "suppress all logging output")
	cmd.PersistentFlags().CountVarP(&o.Verbose, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}
