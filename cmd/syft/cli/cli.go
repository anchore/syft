package cli

import (
	"os"

	cranecmd "github.com/google/go-containerregistry/cmd/crane/cmd"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/cmd/syft/cli/commands"
	handler "github.com/anchore/syft/cmd/syft/cli/ui"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/redact"
)

// Application constructs the `syft packages` command, aliases the root command to `syft packages`,
// and constructs the `syft power-user` command. It is also responsible for
// organizing flag usage and injecting the application config for each command.
// It also constructs the syft attest command and the syft version command.
// `RunE` is the earliest that the complete application configuration can be loaded.
func Application(id clio.Identification) clio.Application {
	app, _ := create(id)
	return app
}

// Command returns the root command for the syft CLI application. This is useful for embedding the entire syft CLI
// into an existing application.
func Command(id clio.Identification) *cobra.Command {
	_, cmd := create(id)
	return cmd
}

func create(id clio.Identification) (clio.Application, *cobra.Command) {
	clioCfg := clio.NewSetupConfig(id).
		WithGlobalConfigFlag().   // add persistent -c <path> for reading an application config from
		WithGlobalLoggingFlags(). // add persistent -v and -q flags tied to the logging config
		WithConfigInRootHelp().   // --help on the root command renders the full application config in the help text
		WithUIConstructor(
			// select a UI based on the logging configuration and state of stdin (if stdin is a tty)
			func(cfg clio.Config) ([]clio.UI, error) {
				noUI := ui.None(cfg.Log.Quiet)
				if !cfg.Log.AllowUI(os.Stdin) || cfg.Log.Quiet {
					return []clio.UI{noUI}, nil
				}

				return []clio.UI{
					ui.New(cfg.Log.Quiet,
						handler.New(handler.DefaultHandlerConfig()),
					),
					noUI,
				}, nil
			},
		).
		WithInitializers(
			func(state *clio.State) error {
				// clio is setting up and providing the bus, redact store, and logger to the application. Once loaded,
				// we can hoist them into the internal packages for global use.
				stereoscope.SetBus(state.Bus)
				bus.Set(state.Bus)

				redact.Set(state.RedactStore)

				log.Set(state.Logger)
				stereoscope.SetLogger(state.Logger)

				return nil
			},
		).
		WithPostRuns(func(state *clio.State, err error) {
			stereoscope.Cleanup()
		})

	app := clio.New(*clioCfg)

	// since root is aliased as the packages cmd we need to construct this command first
	// we also need the command to have information about the `root` options because of this alias
	packagesCmd := commands.Packages(app)

	// rootCmd is currently an alias for the packages command
	rootCmd := commands.Root(app, packagesCmd)

	// add sub-commands
	rootCmd.AddCommand(
		packagesCmd,
		commands.PowerUser(app),
		commands.Attest(app),
		commands.Convert(app),
		clio.VersionCommand(id),
		cranecmd.NewCmdAuthLogin(id.Name), // syft login uses the same command as crane
	)

	return app, rootCmd
}
