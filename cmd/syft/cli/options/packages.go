package options

import (
	"flag"
	"fmt"

	"github.com/anchore/syft/internal/formats/table"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/pkg/cataloger"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type PackagesOptions struct {
	Scope                  string
	Output                 []string
	File                   string
	Platform               string
	Host                   string
	Username               string
	Password               string
	Dockerfile             string
	Exclude                []string
	OverwriteExistingImage bool
	ImportTimeout          uint
}

var _ Interface = (*PackagesOptions)(nil)

func (o *PackagesOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.Scope, "scope", "s", cataloger.DefaultSearchConfig().Scope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))

	cmd.Flags().StringArrayVarP(&o.Output, "output", "o", formatAliases(table.ID),
		fmt.Sprintf("report output format, options=%v", formatAliases(syft.FormatIDs()...)))

	cmd.Flags().StringVarP(&o.File, "file", "", "",
		"file to write the default report output to (default is STDOUT)")

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

	cmd.Flags().BoolVarP(&o.OverwriteExistingImage, "overwrite-existing-image", "", false,
		"overwrite an existing image during the upload to Anchore Enterprise")

	cmd.Flags().UintVarP(&o.ImportTimeout, "import-timeout", "", 30,
		"set a timeout duration (in seconds) for the upload to Anchore Enterprise")
}

func bindPackageConfigOptions(flags *flag.FlagSet) error {
	if err := viper.BindPFlag("package.cataloger.scope", flags.Lookup("scope")); err != nil {
		return err
	}

	return nil
}

func formatAliases(ids ...sbom.FormatID) (aliases []string) {
	for _, id := range ids {
		switch id {
		case syft.JSONFormatID:
			aliases = append(aliases, "syft-json")
		case syft.TextFormatID:
			aliases = append(aliases, "text")
		case syft.TableFormatID:
			aliases = append(aliases, "table")
		case syft.SPDXJSONFormatID:
			aliases = append(aliases, "spdx-json")
		case syft.SPDXTagValueFormatID:
			aliases = append(aliases, "spdx-tag-value")
		case syft.CycloneDxXMLFormatID:
			aliases = append(aliases, "cyclonedx-xml")
		case syft.CycloneDxJSONFormatID:
			aliases = append(aliases, "cyclonedx-json")
		case syft.GitHubID:
			aliases = append(aliases, "github", "github-json")
		default:
			aliases = append(aliases, string(id))
		}
	}
	return aliases
}
