package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const DefaultOIDCIssuerURL = "https://oauth2.sigstore.dev/auth"

// OIDCOptions is the wrapper for OIDC related options.
type OIDCOptions struct {
	Issuer      string
	ClientID    string
	RedirectURL string
}

var _ Interface = (*OIDCOptions)(nil)

// AddFlags implements Interface
func (o *OIDCOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.Flags().StringVar(&o.Issuer, "oidc-issuer", DefaultOIDCIssuerURL,
		"OIDC provider to be used to issue ID token")

	cmd.Flags().StringVar(&o.ClientID, "oidc-client-id", "sigstore",
		"OIDC client ID for application")

	cmd.Flags().StringVar(&o.RedirectURL, "oidc-redirect-url", "",
		"OIDC redirect URL (Optional). The default oidc-redirect-url is 'http://localhost:0/auth/callback'.")

	return bindOIDCConfigOptions(cmd.Flags(), v)
}

func bindOIDCConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := v.BindPFlag("attest.oidc_issuer", flags.Lookup("oidc-issuer")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.oidc_client_id", flags.Lookup("oidc-client-id")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.oidc_redirect_url", flags.Lookup("oidc-reirect-url")); err != nil {
		return err
	}

	return nil
}
