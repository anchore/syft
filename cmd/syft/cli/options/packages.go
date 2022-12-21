package options

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/source"
)

type PackagesOptions struct {
	Scope              string
	Output             []string
	OutputTemplatePath string
	File               string
	Platform           string
	Exclude            []string
	Catalogers         []string
	Name               string
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

	cmd.Flags().StringArrayVarP(&o.Exclude, "exclude", "", nil,
		"exclude paths from being scanned using a glob expression")

	cmd.Flags().StringArrayVarP(&o.Catalogers, "catalogers", "", nil,
		"enable one or more package catalogers")

	cmd.Flags().StringVarP(&o.Name, "name", "", "",
		"set the name of the target being analyzed")

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

	if err := v.BindPFlag("name", flags.Lookup("name")); err != nil {
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

	return nil
}
