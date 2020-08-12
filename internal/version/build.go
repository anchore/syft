package version

import (
	"fmt"
	"runtime"
)

const valueNotProvided = "[not provided]"

// all variables here are provided as build-time arguments, with clear default values
var version = valueNotProvided
var gitCommit = valueNotProvided
var gitTreeState = valueNotProvided
var buildDate = valueNotProvided
var platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

// Version defines the application version details (generally from build information)
type Version struct {
	Version      string // application semantic version
	GitCommit    string // git SHA at build-time
	GitTreeState string // indication of git tree (either "clean" or "dirty") at build-time
	BuildDate    string // date of the build
	GoVersion    string // go runtime version at build-time
	Compiler     string // compiler used at build-time
	Platform     string // GOOS and GOARCH at build-time
}

// FromBuild provides all version details
func FromBuild() Version {
	return Version{
		Version:      version,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     platform,
	}
}
