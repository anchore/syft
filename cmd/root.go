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
	"github.com/anchore/stereoscope"
	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"
)

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [IMAGE]", internal.ApplicationName),
	Short: "A container image BOM tool", // TODO: add copy
	Long: internal.Tprintf(`\
Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag             defaults to using images from a docker daemon
    {{.appName}} docker://yourrepo/yourimage:tag    explicitly use the docker daemon
    {{.appName}} tar://path/to/yourimage.tar        use a tarball from disk
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

func startWorker(userImage string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		log.Infof("Fetching image '%s'", userImage)
		img, err := stereoscope.GetImage(userImage)
		if err != nil {
			errs <- fmt.Errorf("could not fetch image '%s': %w", userImage, err)
			return
		}
		defer stereoscope.Cleanup()

		log.Info("Identifying Distro")
		distro := imgbom.IdentifyDistro(img)
		if distro == nil {
			log.Errorf("error identifying distro")
		} else {
			log.Infof("  Distro: %s", distro)
		}

		log.Info("Cataloging image")
		catalog, err := imgbom.CatalogImage(img, appConfig.ScopeOpt)
		if err != nil {
			errs <- fmt.Errorf("could not catalog image: %w", err)
		}

		log.Info("Complete!")
		bus.Publish(partybus.Event{
			Type:  event.CatalogerFinished,
			Value: presenter.GetPresenter(appConfig.PresenterOpt, img, catalog),
		})
	}()
	return errs
}

func doRunCmd(_ *cobra.Command, args []string) int {
	errs := startWorker(args[0])

	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)

	return ux(errs, eventSubscription)
}
