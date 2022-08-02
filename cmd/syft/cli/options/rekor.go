package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const DefaultRekorURL = "https://rekor.sigstore.dev"

// RekorOptions is the wrapper for Rekor related options.
type RekorOptions struct {
	URL string
}

var _ Interface = (*RekorOptions)(nil)

// AddFlags implements Interface
func (o *RekorOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.Flags().StringVar(&o.URL, "rekor-url", DefaultRekorURL,
		"address of rekor STL server")
	return bindRekorConfigOptions(cmd.Flags(), v)
}

func bindRekorConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	// TODO: config re-design
	if err := v.BindPFlag("attest.rekor-url", flags.Lookup("rekor-url")); err != nil {
		return err
	}

	return nil
}
