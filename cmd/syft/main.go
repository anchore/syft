package main

import (
	_ "modernc.org/sqlite"

	"github.com/anchore/clio"
	"github.com/anchore/syft/cmd/syft/cli"
)

const valueNotProvided = "[not provided]"

// all variables here are provided as build-time arguments, with clear default values
var version = valueNotProvided
var buildDate = valueNotProvided
var gitCommit = valueNotProvided
var gitDescription = valueNotProvided

// applicationName is the non-capitalized name of the application (do not change this)
const applicationName = "syft"

func main() {
	app := cli.New(
		clio.Identification{
			Name:           applicationName,
			Version:        version,
			BuildDate:      buildDate,
			GitCommit:      gitCommit,
			GitDescription: gitDescription,
		},
	)

	app.Run()
}
