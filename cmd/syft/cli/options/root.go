package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/anchore/syft/internal"
)

type RootOptions struct {
	Config  string
	Quiet   bool
	Verbose int
}

var _ Interface = (*RootOptions)(nil)

func (o *RootOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	// load environment variables
	v.SetEnvPrefix(internal.ApplicationName)
	v.AllowEmptyEnv(true)
	v.AutomaticEnv()

	cmd.PersistentFlags().StringVarP(&o.Config, "config", "c", "", "application config file")
	cmd.PersistentFlags().CountVarP(&o.Verbose, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
	cmd.PersistentFlags().BoolVarP(&o.Quiet, "quiet", "q", false, "suppress all logging output")

	// Set precedence order of flag -> env -> defaults
	o.Config = v.GetString("config")
	o.Quiet = v.GetBool("quiet")
	o.Verbose = v.GetInt("verbose")

	return nil
}
