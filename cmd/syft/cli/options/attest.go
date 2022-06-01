package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const defaultKeyFileName = "cosign.key"

type AttestOptions struct {
	Key       string
	Cert      string
	CertChain string
	NoUpload  bool
	Force     bool
	Recursive bool

	Rekor  RekorOptions
	Fulcio FulcioOptions
	OIDC   OIDCOptions
}

var _ Interface = (*AttestOptions)(nil)

func (o *AttestOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	if err := o.Rekor.AddFlags(cmd, v); err != nil {
		return err
	}
	if err := o.Fulcio.AddFlags(cmd, v); err != nil {
		return err
	}
	if err := o.OIDC.AddFlags(cmd, v); err != nil {
		return err
	}

	cmd.Flags().StringVarP(&o.Key, "key", "", defaultKeyFileName,
		"path to the private key file to use for attestation")

	cmd.Flags().StringVarP(&o.Cert, "cert", "", "",
		"path to the x.509 certificate in PEM format to include in the OCI Signature")

	cmd.Flags().BoolVarP(&o.NoUpload, "no-upload", "", false,
		"do not upload the generated attestation")

	cmd.Flags().BoolVarP(&o.Force, "force", "", false,
		"skip warnings and confirmations")

	cmd.Flags().BoolVarP(&o.Recursive, "recursive", "", false,
		"if a multi-arch image is specified, additionally sign each discrete image")

	return bindAttestationConfigOptions(cmd.Flags(), v)
}

func bindAttestationConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	if err := v.BindPFlag("attest.key", flags.Lookup("key")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.cert", flags.Lookup("cert")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.no-upload", flags.Lookup("no-upload")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.force", flags.Lookup("force")); err != nil {
		return err
	}

	if err := v.BindPFlag("attest.recursive", flags.Lookup("recursive")); err != nil {
		return err
	}

	return nil
}
