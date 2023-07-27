package options

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/anchore/syft/syft/formats"
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
	SourceName         string
	SourceVersion      string
	BasePath           string
}

var _ Interface = (*PackagesOptions)(nil)

func (o *PackagesOptions) AddFlags(cmd *cobra.Command, v *viper.Viper) error {
	cmd.Flags().StringVarP(&o.Scope, "scope", "s", cataloger.DefaultSearchConfig().Scope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))

	cmd.Flags().StringArrayVarP(&o.Output, "output", "o", []string{string(table.ID)},
		fmt.Sprintf("report output format, options=%v", formats.AllIDs()))

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

	cmd.Flags().StringVarP(&o.SourceName, "name", "", "",
		"set the name of the target being analyzed")
	cmd.Flags().Lookup("name").Deprecated = "use: source-name"

	cmd.Flags().StringVarP(&o.SourceName, "source-name", "", "",
		"set the name of the target being analyzed")

	cmd.Flags().StringVarP(&o.SourceVersion, "source-version", "", "",
		"set the name of the target being analyzed")

	cmd.Flags().StringVarP(&o.BasePath, "base-path", "", "",
		"base directory for scanning, no links will be followed above this directory, and all paths will be reported relative to this directory")

	return bindPackageConfigOptions(cmd.Flags(), v)
}

//nolint:revive
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

	if err := v.BindPFlag("source.name", flags.Lookup("source-name")); err != nil {
		return err
	}

	if err := v.BindPFlag("source.version", flags.Lookup("source-version")); err != nil {
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

	if err := v.BindPFlag("base-path", flags.Lookup("base-path")); err != nil {
		return err
	}

	return nil
}
