package internal

import (
	"io"
	"os"

	"github.com/anchore/clio"
	"github.com/anchore/go-logger"
	gologgerredact "github.com/anchore/go-logger/adapter/redact"
	"github.com/anchore/stereoscope"
	handlers "github.com/anchore/syft/cmd/syft/cli/ui"
	"github.com/anchore/syft/cmd/syft/internal/ui"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/redact"
)

func AppClioSetupConfig(id clio.Identification, out io.Writer) *clio.SetupConfig {
	clioCfg := clio.NewSetupConfig(id).
		WithGlobalConfigFlag().   // add persistent -c <path> for reading an application config from
		WithGlobalLoggingFlags(). // add persistent -v and -q flags tied to the logging config
		WithConfigInRootHelp().   // --help on the root command renders the full application config in the help text
		WithLoggerConstructor(
			func(cfg clio.Config, store gologgerredact.Store) (logger.Logger, error) {
				if !cfg.Log.AllowUI(os.Stdin) && !cfg.Log.Quiet {
					// this is a special case where the user has not explicitly disabled the UI, but the UI is not allowed
					// due to the lack of a tty. In this case, we should default to info level.
					cfg.Log.Level = logger.InfoLevel
					cfg.Log.Verbosity = 1
				}
				return clio.DefaultLogger(cfg, store)
			},
		).
		WithUIConstructor(
			// select a UI based on the logging configuration and state of stdin (if stdin is a tty)
			func(cfg clio.Config) ([]clio.UI, error) {
				noUI := ui.None(out, cfg.Log.Quiet)
				if !cfg.Log.AllowUI(os.Stdin) || cfg.Log.Quiet {
					return []clio.UI{noUI}, nil
				}

				return []clio.UI{
					ui.New(out, cfg.Log.Quiet,
						handlers.New(handlers.DefaultHandlerConfig()),
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
	return clioCfg
}
