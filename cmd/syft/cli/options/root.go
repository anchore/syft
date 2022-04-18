package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type RootOptions struct {
	Config  string
	Quiet   bool
	Verbose int
}

var _ Interface = (*RootOptions)(nil)

func (o *RootOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.PersistentFlags().StringVarP(&o.Config, "config", "c", "", "application config file")
	cmd.PersistentFlags().CountVarP(&o.Verbose, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
	cmd.PersistentFlags().BoolVarP(&o.Quiet, "quiet", "q", false, "suppress all logging output")

	return bindRootConfigOptions(cmd.PersistentFlags(), v)
}

func bindRootConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := v.BindPFlag("config", flags.Lookup("config")); err != nil {
		return err
	}
	if err := v.BindPFlag("verbosity", flags.Lookup("verbose")); err != nil {
		return err
	}
	if err := v.BindPFlag("quiet", flags.Lookup("quiet")); err != nil {
		return err
	}
	return nil
}
