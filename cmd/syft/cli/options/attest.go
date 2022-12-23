package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type AttestOptions struct{}

var _ Interface = (*AttestOptions)(nil)

func (o *AttestOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	return bindAttestationConfigOptions(cmd.Flags(), v)
}

func bindAttestationConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	return nil
}
