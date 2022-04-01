package options

import (
	"fmt"
	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/cobra"
)

// PackagesOptions define flags and options for the packages syft cli.
// See AddFlags function for usage of each value
// TODO: Are any of these flags shared with attest or poweruser?
// TODO: Bind to config via Viper
type PackagesOptions struct {
	// Formatting and Input options
	Scope    string
	Output   []string
	File     string
	Platform string
	Exclude  []string

	// Anchore Enterprise options
	Host                   string
	UserName               string
	Password               string
	Dockerfile             string
	OverWriteExistingImage bool
	ImportTimeOut          int
}

func (o *PackagesOptions) AddFlags(cmd *cobra.Command) {
	// Formatting and Input options ///////////////////////////////////////////////////////////
	defaultScope := cataloger.DefaultSearchConfig().Scope.String()
	cmd.Flags().StringVarP(&o.Scope, "scope", "s", defaultScope,
		fmt.Sprintf("select of layers to catalog, options=%v", source.AllScopes))

	defaultOutput := table.ID
	cmd.Flags().StringArrayVarP(&o.Output, "output", "o", formatSyftOutputs(defaultOutput),
		fmt.Sprintf("report output format, options=%v", formatSyftOutputs(syft.FormatIDs()...)))

	cmd.Flags().StringVarP(&o.File, "file", "", "",
		"file to write the default report output to (default is STDOUT)")

	cmd.Flags().StringVarP(&o.Platform, "platform", "", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')")

	cmd.Flags().StringArrayVarP(&o.Exclude, "exclude", "", nil,
		"exclude paths from being scanned using a glob expression")

	// Anchore Enterprise Options /////////////////////////////////////////////////////////////
	cmd.Flags().StringVarP(&o.Host, "host", "H", "",
		"the hostname or URL of the Anchore Enterprise instance to upload to")

	cmd.Flags().StringVarP(&o.UserName, "username", "u", "",
		"the username to authenticate against Anchore Enterprise")

	cmd.Flags().StringVarP(&o.Password, "password", "p", "",
		"the password to authenticate against Anchore Enterprise")

	cmd.Flags().StringVarP(&o.Dockerfile, "dockerfile", "d", "",
		"include dockerfile for upload to Anchore Enterprise")

	cmd.Flags().BoolVarP(&o.OverWriteExistingImage, "overwrite-existing-image", "", false,
		"overwrite an existing image during the upload to Anchore Enterprise")

	cmd.Flags().IntVarP(&o.ImportTimeOut, "import-timeout", "", 30,
		"set a timeout duration (in seconds) for the upload to Anchore Enterprise")
}
