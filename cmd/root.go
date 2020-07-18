package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/event"
	"github.com/anchore/imgbom/imgbom/presenter"
	"github.com/anchore/imgbom/internal"
	"github.com/anchore/imgbom/internal/bus"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/imgbom/internal/ui"
	"github.com/anchore/imgbom/internal/version"
	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
)

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [SOURCE]", internal.ApplicationName),
	Short: "A tool that generates a Software Build Of Materials (SBOM)",
	Long: internal.Tprintf(`\
Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag             defaults to using images from a docker daemon
    {{.appName}} docker://yourrepo/yourimage:tag    explicitly use the docker daemon
    {{.appName}} tar://path/to/yourimage.tar        use a tarball from disk
    {{.appName}} dir://path/to/yourproject          read directly from a path in disk
`, map[string]interface{}{
		"appName": internal.ApplicationName,
	}),
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := doRunCmd(cmd, args)
		if err != nil {
			log.Errorf(err.Error())
			os.Exit(1)
		}
	},
}

func startWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		if appConfig.CheckForAppUpdate {
			isAvailable, newVersion, err := version.IsUpdateAvailable()
			if err != nil {
				log.Errorf(err.Error())
			}
			if isAvailable {
				log.Infof("New version of %s is available: %s", internal.ApplicationName, newVersion)

				bus.Publish(partybus.Event{
					Type:  event.AppUpdateAvailable,
					Value: newVersion,
				})
			}
		}

		catalog, scope, _, err := imgbom.Catalog(userInput, appConfig.ScopeOpt)
		if err != nil {
			errs <- fmt.Errorf("failed to catalog input: %+v", err)
			return
		}

		bus.Publish(partybus.Event{
			Type:  event.CatalogerFinished,
			Value: presenter.GetPresenter(appConfig.PresenterOpt, *scope, catalog),
		})
	}()
	return errs
}

func doRunCmd(_ *cobra.Command, args []string) error {
	userInput := args[0]
	errs := startWorker(userInput)
	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	return ux(errs, eventSubscription)
}
