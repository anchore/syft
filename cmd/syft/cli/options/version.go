package options

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type VersionOptions struct {
	Output string
}

var _ Interface = (*PackagesOptions)(nil)

func (o *VersionOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.Flags().StringVarP(&o.Output, "output", "o", "text", "format to show version information (available=[text, json])")
	return nil
}
