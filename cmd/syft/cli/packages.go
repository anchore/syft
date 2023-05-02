package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/anchore/syft/cmd/syft/cli/packages"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/source"
)

const (
	packagesExample = `  {{.appName}} {{.command}} alpine:latest                                a summary of discovered packages
  {{.appName}} {{.command}} alpine:latest -o json                        show all possible cataloging details
  {{.appName}} {{.command}} alpine:latest -o cyclonedx                   show a CycloneDX formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o cyclonedx-json              show a CycloneDX JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx                        show a SPDX 2.3 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx@2.2                    show a SPDX 2.2 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json                   show a SPDX 2.3 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json@2.2               show a SPDX 2.2 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -vv                            show verbose debug information
  {{.appName}} {{.command}} alpine:latest -o template -t my_format.tmpl  show a SBOM formatted according to given template file

  Supports the following image sources:
    {{.appName}} {{.command}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} path/to/a/file/or/dir      a Docker tar, OCI tar, OCI directory, SIF container, or generic filesystem directory
`

	schemeHelpHeader = "You can also explicitly specify the scheme to use:"
	imageSchemeHelp  = `    {{.appName}} {{.command}} docker:yourrepo/yourimage:tag            explicitly use the Docker daemon
    {{.appName}} {{.command}} podman:yourrepo/yourimage:tag            explicitly use the Podman daemon
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag          pull image directly from a registry (no container runtime required)
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar     use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar        use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage                read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} {{.command}} singularity:path/to/yourimage.sif        read directly from a Singularity Image Format (SIF) container on disk
`
	nonImageSchemeHelp = `    {{.appName}} {{.command}} dir:path/to/yourproject                  read directly from a path on disk (any directory)
    {{.appName}} {{.command}} file:path/to/yourproject/file            read directly from a path on disk (any single file)
`
	packagesSchemeHelp = "\n" + indent + schemeHelpHeader + "\n" + imageSchemeHelp + nonImageSchemeHelp

	packagesHelp = packagesExample + packagesSchemeHelp
)

//nolint:dupl
func Packages(app *config.Application) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "packages [SOURCE]",
		Short: "Generate a package SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(packagesHelp, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "packages",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := app.LoadAllValues(cmd); err != nil {
				return fmt.Errorf("invalid application config: %w", err)
			}
			// configure logging for command
			newLogWrapper(app)
			logApplicationConfig(app)
			return validateArgs(cmd, args)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if app.CheckForAppUpdate {
				checkForApplicationUpdate()
			}
			return packages.Run(cmd.Context(), app, args)
		},
	}

	AddPackagesFlags(cmd.Flags(), app)

	return cmd
}

func AddPackagesFlags(flags *pflag.FlagSet, app *config.Application) {
	flags.StringVarP(&app.Package.Cataloger.Scope, "scope", "s", app.Package.Cataloger.Scope,
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))

	flags.StringArrayVarP(&app.Outputs, "output", "o", []string{string(table.ID)},
		fmt.Sprintf("report output format, options=%v", formats.AllIDs()))

	flags.StringVarP(&app.File, "file", "", "",
		"file to write the default report output to (default is STDOUT)")

	flags.StringVarP(&app.OutputTemplatePath, "template", "t", "",
		"specify the path to a Go template file")

	flags.StringVarP(&app.Platform, "platform", "", "",
		"an optional platform specifier for container image sources (e.g. 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux')")

	flags.StringArrayVarP(&app.Exclusions, "exclude", "", nil,
		"exclude paths from being scanned using a glob expression")

	flags.StringArrayVarP(&app.Catalogers, "catalogers", "", nil,
		"enable one or more package catalogers")

	flags.StringVarP(&app.Name, "name", "", "",
		"set the name of the target being analyzed")
}
