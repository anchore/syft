package cli

import (
	"io"
	"os"

	cranecmd "github.com/google/go-containerregistry/cmd/crane/cmd"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/internal"
	"github.com/anchore/syft/cmd/syft/internal/commands"
)

// Application constructs the `syft packages` command and aliases the root command to `syft packages`.
// It is also responsible for organizing flag usage and injecting the application config for each command.
// It also constructs the syft attest command and the syft version command.
// `RunE` is the earliest that the complete application configuration can be loaded.
func Application(id clio.Identification) clio.Application {
	app, _ := create(id, os.Stdout)
	return app
}

// Command returns the root command for the syft CLI application. This is useful for embedding the entire syft CLI
// into an existing application.
func Command(id clio.Identification) *cobra.Command {
	_, cmd := create(id, os.Stdout)
	return cmd
}

func create(id clio.Identification, out io.Writer) (clio.Application, *cobra.Command) {
	clioCfg := internal.AppClioSetupConfig(id, out)

	app := clio.New(*clioCfg)

	// since root is aliased as the packages cmd we need to construct this command first
	// we also need the command to have information about the `root` options because of this alias
	scanCmd := commands.Scan(app)

	// root is currently an alias for the scan command
	rootCmd := commands.Root(app, scanCmd)

	// add sub-commands
	rootCmd.AddCommand(
		scanCmd,
		commands.Packages(app, scanCmd), // this is currently an alias for the scan command
		commands.Cataloger(app),
		commands.Attest(app),
		commands.Convert(app),
		clio.VersionCommand(id),
		clio.ConfigCommand(app, nil),
		cranecmd.NewCmdAuthLogin(id.Name), // syft login uses the same command as crane
	)

	// note: we would direct cobra to use our writer explicitly with rootCmd.SetOut(out) , however this causes
	// deprecation warnings to be shown to stdout via the writer instead of stderr. This is unfortunate since this
	// does not appear to be the correct behavior on cobra's part https://github.com/spf13/cobra/issues/1708 .
	// In the future this functionality should be restored.

	return app, rootCmd
}
