package cli

import (
	"fmt"

	cranecmd "github.com/google/go-containerregistry/cmd/crane/cmd"
	"github.com/gookit/color"
	logrusUpstream "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/go-logger/adapter/logrus"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/event"
)

const indent = "  "

// New constructs the `syft packages` command, aliases the root command to `syft packages`,
// and constructs the `syft power-user` command. It is also responsible for
// organizing flag usage and injecting the application config for each command.
// It also constructs the syft attest command and the syft version command.

// Because of how the `cobra` library behaves, the application's configuration is initialized
// at this level. Values from the config should only be used after `app.LoadAllValues` has been called.
// Cobra does not have knowledge of the user provided flags until the `RunE` block of each command.
// `RunE` is the earliest that the complete application configuration can be loaded.
func New() *cobra.Command {
	app := config.NewApplication()

	// since root is aliased as the packages cmd we need to construct this command first
	packagesCmd := Packages(app)

	// rootCmd is currently an alias for the packages command
	rootCmd := &cobra.Command{
		Use:           fmt.Sprintf("%s [SOURCE]", internal.ApplicationName),
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

	// add flags common for all commands
	AddRootFlags(rootCmd.PersistentFlags(), app)

	// package flags need to be decorated onto the rootCmd so that rootCmd can function as a packages alias
	AddPackagesFlags(rootCmd.Flags(), app)

	// commands to add to root
	cmds := []*cobra.Command{
		packagesCmd,
		PowerUser(app),
		Convert(app),
		Attest(app),
		Version(app),
		cranecmd.NewCmdAuthLogin("syft"), // syft login uses the same command as crane
	}

	// Add sub-commands.
	rootCmd.AddCommand(cmds...)

	return rootCmd
}

func AddRootFlags(flags *pflag.FlagSet, app *config.Application) {
	flags.StringVarP(&app.ConfigPath, "config", "c", app.ConfigPath, "application config file")
	flags.CountVarP(&app.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
	flags.BoolVarP(&app.Quiet, "quiet", "q", app.Quiet, "suppress all logging output")
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
	log.Debugf("checking if a new version of %s is available", internal.ApplicationName)
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
	log.Infof("%s version: %+v", internal.ApplicationName, versionInfo.Version)
	log.Debugf("application config:\n%+v", color.Magenta.Sprint(app.String()))
}

func newLogWrapper(app *config.Application) {
	cfg := logrus.Config{
		EnableConsole: (app.Log.FileLocation == "" || app.Verbosity > 0) && !app.Quiet,
		FileLocation:  app.Log.FileLocation,
		Level:         app.Log.Level,
	}

	if app.Log.Structured {
		cfg.Formatter = &logrusUpstream.JSONFormatter{
			TimestampFormat:   "2006-01-02 15:04:05",
			DisableTimestamp:  false,
			DisableHTMLEscape: false,
			PrettyPrint:       false,
		}
	}

	logWrapper, err := logrus.New(cfg)
	if err != nil {
		// this is kinda circular, but we can't return an error... ¯\_(ツ)_/¯
		// I'm going to leave this here in case we one day have a different default logger other than the "discard" logger
		log.Error("unable to initialize logger: %+v", err)
		return
	}
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(logWrapper.Nested("from-lib", "stereoscope"))
}
