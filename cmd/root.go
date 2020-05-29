package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/pkg"
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

func doRunCmd(cmd *cobra.Command, args []string) int {
	userImageStr := args[0]
	log.Infof("Fetching image '%s'", userImageStr)
	img, err := stereoscope.GetImage(userImageStr)
	if err != nil {
		log.Errorf("could not fetch image '%s': %w", userImageStr, err)
		return 1
	}
	defer stereoscope.Cleanup()

	log.Info("Cataloging image")
	catalog, err := imgbom.CatalogImage(img, appConfig.ScopeOpt)
	if err != nil {
		log.Errorf("could not catalog image: %w", err)
		return 1
	}

	log.Info("Complete!")
	// err = presenter.GetPresenter(appConfig.PresenterOpt).Present(os.Stdout, img, catalog)
	// if err != nil {
	// 	log.Errorf("could not format catalog results: %w", err)
	// 	return 1
	// }
	result := catalog.SearchName("libselinux")
	fmt.Println(result)
	if result != nil {
		for _, hit := range result.Hits {
			pkgId, err := strconv.Atoi(hit.ID)
			if err != nil {
				// TODO: just no...
				panic(err)
			}
			fmt.Println(pkgId, catalog.Package(pkg.ID(pkgId)), hit.Score)
		}
	}
	fmt.Println("------------------------------------------")

	result = catalog.SearchMetadata("libselinux")
	fmt.Println(result)
	if result != nil {
		for _, hit := range result.Hits {
			pkgId, err := strconv.Atoi(hit.ID)
			if err != nil {
				// TODO: just no...
				panic(err)
			}
			fmt.Println(pkgId, catalog.Package(pkg.ID(pkgId)), hit.Score)
		}
	}
	return 0
}
