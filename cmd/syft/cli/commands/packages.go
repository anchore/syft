package commands

import (
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
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

type packagesOptions struct {
	options.Output      `yaml:",inline" mapstructure:",squash"`
	options.UpdateCheck `yaml:",inline" mapstructure:",squash"`
	options.Packages    `yaml:",inline" mapstructure:",squash"`
}

func packagesOptionsDefault() *packagesOptions {
	return &packagesOptions{
		Output:      options.OutputDefault(),
		UpdateCheck: options.UpdateCheckDefault(),
		Packages:    options.PackagesDefault(),
	}
}

//nolint:dupl
func Packages(app clio.Application) *cobra.Command {
	opts := packagesOptionsDefault()

	return app.SetupCommand(&cobra.Command{
		Use:   "packages [SOURCE]",
		Short: "Generate a package SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(packagesHelp, map[string]interface{}{
			"appName": app.ID().Name,
			"command": "packages",
		}),
		Args: func(cmd *cobra.Command, args []string) error {
			if err := cobra.ExactArgs(1)(cmd, args); err != nil {
				return err
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.CheckForAppUpdate {
				checkForApplicationUpdate(app)
			}
			return runPackages(app, opts, args[0])
		},
	}, opts)
}
