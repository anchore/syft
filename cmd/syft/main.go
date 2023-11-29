package main

import (
	"os"

	_ "modernc.org/sqlite"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli"
	"github.com/anchore/syft/cmd/syft/internal"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
)

// applicationName is the non-capitalized name of the application (do not change this)
const applicationName = "syft"

// all variables here are provided as build-time arguments, with clear default values
var (
	version        = internal.NotProvided
	buildDate      = internal.NotProvided
	gitCommit      = internal.NotProvided
	gitDescription = internal.NotProvided
)

func main() {
	app := cli.Application(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	out := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	app.Run()

	dotnet.AllResourcesCSV(out)
}
