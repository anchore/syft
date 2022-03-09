/*
Package version contains all build time metadata (version, build time, git commit, etc).
*/
package version

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/anchore/syft/internal"
)

const valueNotProvided = "[not provided]"

// all variables here are provided as build-time arguments, with clear default values
var version = valueNotProvided
var gitCommit = valueNotProvided
var gitDescription = valueNotProvided
var buildDate = valueNotProvided
var platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

// Version defines the application version details (generally from build information)
type Version struct {
	Version           string `json:"version"`           // application semantic version
	JSONSchemaVersion string `json:"jsonSchemaVersion"` // application semantic JSON schema version
	GitCommit         string `json:"gitCommit"`         // git SHA at build-time
	GitDescription    string `json:"gitDescription"`    // output of 'git describe --dirty --always --tags'
	BuildDate         string `json:"buildDate"`         // date of the build
	GoVersion         string `json:"goVersion"`         // go runtime version at build-time
	Compiler          string `json:"compiler"`          // compiler used at build-time
	Platform          string `json:"platform"`          // GOOS and GOARCH at build-time
}

func (v Version) IsProductionBuild() bool {
	if strings.Contains(v.Version, "SNAPSHOT") || strings.Contains(v.Version, valueNotProvided) {
		return false
	}
	return true
}

// FromBuild provides all version details
func FromBuild() Version {
	return Version{
		Version:           version,
		JSONSchemaVersion: internal.JSONSchemaVersion,
		GitCommit:         gitCommit,
		GitDescription:    gitDescription,
		BuildDate:         buildDate,
		GoVersion:         runtime.Version(),
		Compiler:          runtime.Compiler,
		Platform:          platform,
	}
}
