package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const defaultFulcioURL = "https://fulcio.sigstore.dev"

// FulcioOptions is the wrapper for Fulcio related options.
type FulcioOptions struct {
	URL                      string
	IdentityToken            string
	InsecureSkipFulcioVerify bool
}

var _ Interface = (*FulcioOptions)(nil)

// AddFlags implements Interface
func (o *FulcioOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	// TODO: change this back to api.SigstorePublicServerURL after the v1 migration is complete.
	cmd.Flags().StringVar(&o.URL, "fulcio-url", defaultFulcioURL,
		"address of sigstore PKI server")

	cmd.Flags().StringVar(&o.IdentityToken, "identity-token", "",
		"identity token to use for certificate from fulcio")

	cmd.Flags().BoolVar(&o.InsecureSkipFulcioVerify, "insecure-skip-verify", false,
		"skip verifying fulcio certificat and the SCT (Signed Certificate Timestamp) (this should only be used for testing).")
	return bindFulcioConfigOptions(cmd.Flags(), v)
}

func bindFulcioConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := v.BindPFlag("attest.fulcio-url", flags.Lookup("fulcio-url")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.fulcio-identity-token", flags.Lookup("identity-token")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.insecure-skip-verify", flags.Lookup("insecure-skip-verify")); err != nil {
		return err
	}

	return nil
}
