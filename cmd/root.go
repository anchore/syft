package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var persistentOpts = config.CliOnlyOptions{}

// rootCmd is currently an alias for the packages command
var rootCmd = &cobra.Command{
	Short:             packagesCmd.Short,
	Long:              packagesCmd.Long,
	Args:              packagesCmd.Args,
	Example:           packagesCmd.Example,
	SilenceUsage:      true,
	SilenceErrors:     true,
	PreRunE:           packagesCmd.PreRunE,
	RunE:              packagesCmd.RunE,
	ValidArgsFunction: packagesCmd.ValidArgsFunction,
	Version:           version.FromBuild().Version,
}

const schemeHelp = `You can also explicitly specify the scheme to use:
    {{.appName}} {{.command}} docker:yourrepo/yourimage:tag          explicitly use the Docker daemon
    {{.appName}} {{.command}} docker-archive:path/to/yourimage.tar   use a tarball from disk for archives created from "docker save"
    {{.appName}} {{.command}} oci-archive:path/to/yourimage.tar      use a tarball from disk for OCI archives (from Skopeo or otherwise)
    {{.appName}} {{.command}} oci-dir:path/to/yourimage              read directly from a path on disk for OCI layout directories (from Skopeo or otherwise)
    {{.appName}} {{.command}} dir:path/to/yourproject                read directly from a path on disk (any directory)
    {{.appName}} {{.command}} file:path/to/yourproject/file          read directly from a path on disk (any single file)
    {{.appName}} {{.command}} registry:yourrepo/yourimage:tag        pull image directly from a registry (no container runtime required)
`

func init() {
	// set universal flags
	rootCmd.PersistentFlags().StringVarP(&persistentOpts.ConfigPath, "config", "c", "", "application config file")
	// setting the version template to just print out the string since we already have a templatized version string
	rootCmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", internal.ApplicationName))
	flag := "quiet"
	rootCmd.PersistentFlags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)

	if err := viper.BindPFlag(flag, rootCmd.PersistentFlags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().CountVarP(&persistentOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")

	// set common options that are not universal (package subcommand-alias specific)
	setPackageFlags(rootCmd.Flags())
}
