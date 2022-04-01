package options

import "github.com/spf13/cobra"

type VersionOptions struct {
	Output string
}

func (o *VersionOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Output, "output", "o", "text",
		"format to show version information (available=[text, json])")
}
