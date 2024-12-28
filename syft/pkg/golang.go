package pkg

import (
	"golang.org/x/tools/go/packages"
	"time"
)

// GolangBinaryBuildinfoEntry represents all captured data for a Golang binary
type GolangBinaryBuildinfoEntry struct {
	BuildSettings     KeyValues `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string    `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string    `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string    `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	MainModule        string    `json:"mainModule,omitempty" cyclonedx:"mainModule"`
	GoCryptoSettings  []string  `json:"goCryptoSettings,omitempty" cyclonedx:"goCryptoSettings"`
	GoExperiments     []string  `json:"goExperiments,omitempty" cyclonedx:"goExperiments"`
}

// GolangModuleEntry represents all captured data for a Golang source scan with go.mod/go.sum
type GolangModuleEntry struct {
	H1Digest string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
}

// GolangModuleEntryMetadata represetns all captured data from the golang.org/x/tools/go/packages package
// when scanning a golang source directory for direct and indirect dependencies
type GolangModuleEntryMetadata struct {
	Path      string           // module path
	Version   string           // module version
	Replace   *packages.Module // replaced by this module
	Time      *time.Time       // time version was created
	Main      bool             // is this the main module?
	Indirect  bool             // is this module only an indirect dependency of main module?
	Dir       string           // directory holding files for this module, if any
	GoMod     string           // path to go.mod file used when loading this module, if any
	GoVersion string           // go version used in module
}
