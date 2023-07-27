package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type AttestOptions struct {
	Key string
}

var _ Interface = (*AttestOptions)(nil)

func (o AttestOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.Flags().StringVarP(&o.Key, "key", "k", "", "the key to use for the attestation")
	return bindAttestConfigOptions(cmd.Flags(), v)
}

//nolint:revive
func bindAttestConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := v.BindPFlag("attest.key", flags.Lookup("key")); err != nil {
		return err
	}
	return nil
}
