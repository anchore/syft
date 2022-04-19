package cli

import (
	"fmt"
	golog "log"
	"strings"

	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/event"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

const indent = "  "

// New constructs the `syft packages` command and aliases the root command.
func New() *cobra.Command {
	ro := &options.RootOptions{}
	po := &options.PackagesOptions{}
	app := &config.Application{}

	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v := viper.NewWithOptions(viper.EnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_")))

	// since root is aliased as packages we need to construct this command first
	packagesCmd := Packages(v, app, ro, po)

	// rootCmd is currently an alias for the packages command
	cmd := &cobra.Command{
		Short:         packagesCmd.Short,
		Long:          packagesCmd.Long,
		Args:          packagesCmd.Args,
		Example:       packagesCmd.Example,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          packagesCmd.RunE,
		Version:       version.FromBuild().Version,
	}
	cmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", internal.ApplicationName))
	err := ro.AddFlags(cmd, v)
	if err != nil {
		golog.Fatal(err)
	}

	// add package flags to rootCmd because of alias
	err = po.AddFlags(cmd, v)
	if err != nil {
		golog.Fatal(err)
	}

	// Add sub-commands.
	cmd.AddCommand(packagesCmd)
	cmd.AddCommand(Version(v, app))

	return cmd
}

func helpArgs(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		// in the case that no arguments are given we want to show the help text and return with a non-0 return code.
		if err := cmd.Help(); err != nil {
			return fmt.Errorf("unable to display help: %w", err)
		}
		return fmt.Errorf("an image/directory argument is required")
	}

	return cobra.MaximumNArgs(1)(cmd, args)
}

func checkForApplicationUpdate() {
	log.Debugf("checking if new vesion of %s is available", internal.ApplicationName)
	isAvailable, newVersion, err := version.IsUpdateAvailable()
	if err != nil {
		// this should never stop the application
		log.Errorf(err.Error())
	}
	if isAvailable {
		log.Infof("new version of %s is available: %s (current version is %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)

		bus.Publish(partybus.Event{
			Type:  event.AppUpdateAvailable,
			Value: newVersion,
		})
	} else {
		log.Debugf("no new %s update available", internal.ApplicationName)
	}
}
