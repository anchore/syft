package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/event"
	"github.com/anchore/imgbom/imgbom/presenter"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal"
	"github.com/anchore/imgbom/internal/bus"
	"github.com/anchore/imgbom/internal/log"
	"github.com/anchore/imgbom/internal/ui"
	"github.com/anchore/stereoscope"
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
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		os.Exit(doRunCmd(cmd, args))
	},
}

func init() {
	setCliOptions()

	cobra.OnInitialize(
		initAppConfig,
		initLogging,
		logAppConfig,
		initEventBus,
	)
}

func startWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)
		protocol := imgbom.NewProtocol(userInput)
		log.Debugf("protocol: %+v", protocol)

		var s scope.Scope
		var err error

		switch protocol.Type {
		case imgbom.DirProtocol:
			// populate the scope object for dir
			s, err = imgbom.GetScopeFromDir(protocol.Value, appConfig.ScopeOpt)
			if err != nil {
				errs <- fmt.Errorf("could not populate scope from path (%s): %w", protocol.Value, err)
			}

		default:
			log.Infof("Fetching image '%s'", userInput)
			img, err := stereoscope.GetImage(userInput)

			if err != nil || img == nil {
				errs <- fmt.Errorf("could not fetch image '%s': %w", userInput, err)

				// TODO: this needs to be handled better
				bus.Publish(partybus.Event{
					Type:  event.CatalogerFinished,
					Value: nil,
				})
				return
			}
			defer stereoscope.Cleanup()

			// populate the scope object for image
			s, err = imgbom.GetScopeFromImage(img, appConfig.ScopeOpt)
			if err != nil {
				errs <- fmt.Errorf("could not populate scope with image: %w", err)
			}
		}

		log.Info("Identifying Distro")
		distro := imgbom.IdentifyDistro(s)
		if distro == nil {
			log.Errorf("error identifying distro")
		} else {
			log.Infof("  Distro: %s", distro)
		}

		bus.Publish(partybus.Event{
			Type:  event.CatalogerFinished,
			Value: presenter.GetPresenter(appConfig.PresenterOpt, s),
		})
	}()
	return errs
}

func doRunCmd(_ *cobra.Command, args []string) int {
	errs := startWorker(args[0])

	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)

	return ux(errs, eventSubscription)
}
