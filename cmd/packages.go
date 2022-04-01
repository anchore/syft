package cmd

import (
	"fmt"
	"github.com/anchore/syft/cmd/options"
	"github.com/anchore/syft/internal"
	"github.com/spf13/cobra"
)

const (
	packagesExample = `  {{.appName}} {{.command}} alpine:latest                    a summary of discovered packages
  {{.appName}} {{.command}} alpine:latest -o json            show all possible cataloging details
  {{.appName}} {{.command}} alpine:latest -o cyclonedx       show a CycloneDX formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o cyclonedx-json  show a CycloneDX JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx            show a SPDX 2.2 Tag-Value formatted SBOM
  {{.appName}} {{.command}} alpine:latest -o spdx-json       show a SPDX 2.2 JSON formatted SBOM
  {{.appName}} {{.command}} alpine:latest -vv                show verbose debug information
  Supports the following image sources:
    {{.appName}} {{.command}} yourrepo/yourimage:tag     defaults to using images from a Docker daemon. If Docker is not present, the image is pulled directly from the registry.
    {{.appName}} {{.command}} path/to/a/file/or/dir      a Docker tar, OCI tar, OCI directory, or generic filesystem directory
`

	schemeHelpHeader = "You can also explicitly specify the scheme to use:"
	imageSchemeHelp  = `    {{.appName}} {{.command}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} {{.command}} podman:yourrepo/yourimage:tag        	 explicitly use the Podman daemon
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
`
	nonImageSchemeHelp = `    {{.appName}} {{.command}} dir:path/to/yourproject                read directly from a path on disk (any directory)
    {{.appName}} {{.command}} file:path/to/yourproject/file          read directly from a path on disk (any single file)
`
	packagesSchemeHelp = "\n" + options.Indent + schemeHelpHeader + "\n" + imageSchemeHelp + nonImageSchemeHelp

	packagesHelp = packagesExample + packagesSchemeHelp
)

func Packages() *cobra.Command {
	o := &options.PackagesOptions{}

	cmd := &cobra.Command{
		Use:   "packages [SOURCE]",
		Short: "Generate a package SBOM",
		Long:  "Generate a packaged-based Software Bill Of Materials (SBOM) from container images and filesystems",
		Example: internal.Tprintf(packagesHelp, map[string]interface{}{
			"appName": internal.ApplicationName,
			"command": "packages",
		}),
		Args:          validateInputArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, args []string) (err error) {
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	o.AddFlags(cmd)
	return cmd
}

func validateInputArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		// in the case that no arguments are given we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}
