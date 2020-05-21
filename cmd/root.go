package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/imgbom/imgbom"
	"github.com/anchore/imgbom/imgbom/presenter"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal"
	"github.com/anchore/stereoscope"
	"github.com/spf13/cobra"
)

const ApplicationName = "imgbom"

var rootOptions struct {
	cfgFile string
	scope   string
	output  string
}

var rootCmd = &cobra.Command{
	Use:   fmt.Sprintf("%s [IMAGE]", ApplicationName),
	Short: "A container image BOM tool", // TODO: add copy
	Long: internal.Tprintf(`\
Supports the following image sources:
    {{.appName}} yourrepo/yourimage:tag             defaults to using images from a docker daemon
    {{.appName}} docker://yourrepo/yourimage:tag    explicitly use the docker daemon
    {{.appName}} tar://path/to/yourimage.tar        use a tarball from disk
`, map[string]interface{}{
		"appName": ApplicationName,
	}),
	Args: cobra.MaximumNArgs(1),
	Run:  doRunCmd,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(loadApplicationConfig)
	// TODO: add config support
	//rootCmd.PersistentFlags().StringVarP(&rootOptions.cfgFile, "config", "c", "", "config file")

	// scan options
	rootCmd.Flags().StringVarP(&rootOptions.scope, "scope", "s", scope.AllLayersScope.String(),
		fmt.Sprintf("selection of layers to analyze, options=%v", scope.Options))

	// output & formatting options
	rootCmd.Flags().StringVarP(&rootOptions.output, "output", "o", presenter.JSONOption.String(),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options))
}

func loadApplicationConfig() {
	// TODO: add config support
}

func doRunCmd(cmd *cobra.Command, args []string) {
	var pres = presenter.GetPresenter(rootOptions.output)
	if pres == nil {
		// TODO: replace with log and exit
		panic("could not determine presenter")
	}

	scopeOption := scope.ParseOption(rootOptions.scope)
	if scopeOption == scope.UnknownScope {
		// TODO: replace with log and exit
		panic(scopeOption)
	}

	img, err := stereoscope.GetImage(args[0])
	if err != nil {
		// TODO: replace with log and exit
		panic(err)
	}
	defer stereoscope.Cleanup()

	catalog, err := imgbom.CatalogImage(img, scopeOption)
	if err != nil {
		// TODO: replace with log and exit
		panic(err)
	}

	err = pres.Present(os.Stdout, img, catalog)
	if err != nil {
		// TODO: replace with log and exit
		panic(err)
	}
}
