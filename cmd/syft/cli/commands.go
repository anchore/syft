package cli

import (
	"fmt"
	"strings"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal/logger"
	"github.com/anchore/syft/syft"

	"github.com/anchore/syft/cmd/syft/cli/options"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/event"
	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

const indent = "  "

// New constructs the `syft packages` command, aliases the root command to `syft packages`,
// and constructs the `syft power-user` and `syft attest` commands. It is also responsible for
// organizing flag usage and injecting the application config for each command.
// Because of how the `cobra` library behaves, the application's configuration is initialized
// at this level. Values from the config should only be used after `app.LoadAllValues` has been called.
// Cobra does not have knowledge of the user provided flags until the `RunE` block of each command.
// `RunE` is the earliest that the complete application configuration can be loaded.
func New() (*cobra.Command, error) {
	app := &config.Application{}

	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v := viper.NewWithOptions(viper.EnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_")))

	// since root is aliased as the packages cmd we need to construct this command first
	// we also need the command to have information about the `root` options because of this alias
	ro := &options.RootOptions{}
	po := &options.PackagesOptions{}
	packagesCmd := Packages(v, app, ro, po)

	// root options are also passed to the attestCmd so that a user provided config location can be discovered
	attestCmd := Attest(v, app, ro)
	poweruserCmd := PowerUser(v, app, ro)
	convertCmd := Convert(v, app, ro)

	// rootCmd is currently an alias for the packages command
	rootCmd := &cobra.Command{
		Short:         packagesCmd.Short,
		Long:          packagesCmd.Long,
		Args:          packagesCmd.Args,
		Example:       packagesCmd.Example,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          packagesCmd.RunE,
		Version:       version.FromBuild().Version,
	}
	rootCmd.SetVersionTemplate(fmt.Sprintf("%s {{.Version}}\n", internal.ApplicationName))

	// start adding flags to all the commands
	err := ro.AddFlags(rootCmd, v)
	if err != nil {
		return nil, err
	}
	// package flags need to be decorated onto the rootCmd so that rootCmd can function as a packages alias
	err = po.AddFlags(rootCmd, v)
	if err != nil {
		return nil, err
	}
	// attest also uses flags from the packagesCmd since it generates an sbom
	err = po.AddFlags(attestCmd, v)
	if err != nil {
		return nil, err
	}
	// poweruser also uses the packagesCmd flags since it is a specialized version of the command
	err = po.AddFlags(poweruserCmd, v)
	if err != nil {
		return nil, err
	}

	// Add sub-commands.
	rootCmd.AddCommand(packagesCmd)
	rootCmd.AddCommand(attestCmd)
	rootCmd.AddCommand(poweruserCmd)
	rootCmd.AddCommand(Completion())
	rootCmd.AddCommand(Version(v, app))
	rootCmd.AddCommand(convertCmd)

	return rootCmd, err
}

func validateArgs(cmd *cobra.Command, args []string) error {
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

func logApplicationConfig(app *config.Application) {
	versionInfo := version.FromBuild()
	log.Infof("syft version: %+v", versionInfo.Version)
	log.Debugf("application config:\n%+v", color.Magenta.Sprint(app.String()))
}

func newLogWrapper(app *config.Application) {
	cfg := logger.LogrusConfig{
		EnableConsole: (app.Log.FileLocation == "" || app.Verbosity > 0) && !app.Quiet,
		EnableFile:    app.Log.FileLocation != "",
		Level:         app.Log.LevelOpt,
		Structured:    app.Log.Structured,
		FileLocation:  app.Log.FileLocation,
	}

	logWrapper := logger.NewLogrusLogger(cfg)
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(&logger.LogrusNestedLogger{
		Logger: logWrapper.Logger.WithField("from-lib", "stereoscope"),
	})
}
