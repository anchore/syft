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

func (o *AttestOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.PersistentFlags().StringVarP(&o.Key, "key", "", "cosign.key",
		"path to the private key file to use for attestation")

	return bindAttestationConfigOptions(cmd.PersistentFlags(), v)
}

func bindAttestationConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := v.BindPFlag("attest.key", flags.Lookup("key")); err != nil {
		return err
	}

	return nil
}
