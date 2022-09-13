package options

import (
	"fmt"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

type PackagesOptions struct {
	Scope                  string
	Output                 []string
	OutputTemplatePath     string
	File                   string
	Platform               string
	Host                   string
	Username               string
	Password               string
	Dockerfile             string
	Exclude                []string
	OverwriteExistingImage bool
	ImportTimeout          uint
	Catalogers             []string
}

var _ Interface = (*PackagesOptions)(nil)

func (o *PackagesOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.Flags().StringVarP(&o.Scope, "scope", "s", cataloger.DefaultSearchConfig().Scope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))

	cmd.Flags().StringArrayVarP(&o.Output, "output", "o", FormatAliases(table.ID),
		fmt.Sprintf("report output format, options=%v", FormatAliases(syft.FormatIDs()...)))

	cmd.Flags().StringVarP(&o.File, "file", "", "",
		"file to write the default report output to (default is STDOUT)")

	cmd.Flags().StringVarP(&o.OutputTemplatePath, "template", "t", "",
		"specify the path to a Go template file")

	cmd.Flags().StringVarP(&o.Platform, "platform", "", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')")

	cmd.Flags().StringVarP(&o.Host, "host", "H", "",
		"the hostname or URL of the Anchore Enterprise instance to upload to")

	cmd.Flags().StringVarP(&o.Username, "username", "u", "",
		"the username to authenticate against Anchore Enterprise")

	cmd.Flags().StringVarP(&o.Password, "password", "p", "",
		"the password to authenticate against Anchore Enterprise")

	cmd.Flags().StringVarP(&o.Dockerfile, "dockerfile", "d", "",
		"include dockerfile for upload to Anchore Enterprise")

	cmd.Flags().StringArrayVarP(&o.Exclude, "exclude", "", nil,
		"exclude paths from being scanned using a glob expression")

	cmd.Flags().StringArrayVarP(&o.Catalogers, "catalogers", "", nil,
		"enable one or more package catalogers")

	cmd.Flags().BoolVarP(&o.OverwriteExistingImage, "overwrite-existing-image", "", false,
		"overwrite an existing image during the upload to Anchore Enterprise")

	cmd.Flags().UintVarP(&o.ImportTimeout, "import-timeout", "", 30,
		"set a timeout duration (in seconds) for the upload to Anchore Enterprise")

	return bindPackageConfigOptions(cmd.Flags(), v)
}

func bindPackageConfigOptions(flags *pflag.FlagSet, v *viper.Viper) error {
	// Formatting & Input options //////////////////////////////////////////////

	if err := v.BindPFlag("package.cataloger.scope", flags.Lookup("scope")); err != nil {
		return err
	}

	if err := v.BindPFlag("file", flags.Lookup("file")); err != nil {
		return err
	}

	if err := v.BindPFlag("exclude", flags.Lookup("exclude")); err != nil {
		return err
	}

	if err := v.BindPFlag("catalogers", flags.Lookup("catalogers")); err != nil {
		return err
	}

	if err := v.BindPFlag("output", flags.Lookup("output")); err != nil {
		return err
	}

	if err := v.BindPFlag("output-template-path", flags.Lookup("template")); err != nil {
		return err
	}

	if err := v.BindPFlag("platform", flags.Lookup("platform")); err != nil {
		return err
	}

	// Upload options //////////////////////////////////////////////////////////

	if err := v.BindPFlag("anchore.host", flags.Lookup("host")); err != nil {
		return err
	}

	if err := v.BindPFlag("anchore.username", flags.Lookup("username")); err != nil {
		return err
	}

	if err := v.BindPFlag("anchore.password", flags.Lookup("password")); err != nil {
		return err
	}

	if err := v.BindPFlag("anchore.dockerfile", flags.Lookup("dockerfile")); err != nil {
		return err
	}

	if err := v.BindPFlag("anchore.overwrite-existing-image", flags.Lookup("overwrite-existing-image")); err != nil {
		return err
	}

	if err := v.BindPFlag("anchore.import-timeout", flags.Lookup("import-timeout")); err != nil {
		return err
	}

	return nil
}
