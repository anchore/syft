package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/presenter"
	"github.com/anchore/imgbom/internal"
	"github.com/anchore/stereoscope"
	"github.com/spf13/cobra"
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
	Run:  runCmdWrapper,
}

func init() {
	setCliOptions()

	cobra.OnInitialize(initAppConfig)
	cobra.OnInitialize(initLogging)
	cobra.OnInitialize(logAppConfig)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("could not start application: %w", err)
		os.Exit(1)
	}
}

func runCmdWrapper(cmd *cobra.Command, args []string) {
	os.Exit(doRunCmd(cmd, args))
}

func doRunCmd(_ *cobra.Command, args []string) int {
	userImageStr := args[0]
	log.Infof("Fetching image '%s'", userImageStr)
	img, err := stereoscope.GetImage(userImageStr)
	if err != nil {
		log.Errorf("could not fetch image '%s': %w", userImageStr, err)
		return 1
	}
	defer stereoscope.Cleanup()

	log.Info("Identifying Distro")
	distro, err := imgbom.IdentifyDistro(img)
	if err != nil {
		log.Errorf("error identifying Distro: %w", err)
	} else {
		log.Info("  Distro: %s", distro)
	}

	log.Info("Cataloging image")
	catalog, err := imgbom.CatalogImage(img, appConfig.ScopeOpt)
	if err != nil {
		log.Errorf("could not catalog image: %w", err)
		return 1
	}

	log.Info("Complete!")
	err = presenter.GetPresenter(appConfig.PresenterOpt).Present(os.Stdout, img, catalog)
	if err != nil {
		log.Errorf("could not format catalog results: %w", err)
		return 1
	}

	return 0
}
