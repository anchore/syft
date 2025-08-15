package pkg

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

// GolangSourceEntry represents all captured data for a Golang package found through source analysis
type GolangSourceEntry struct {
	H1Digest   string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	GOROOT     string `json:"goroot,omitempty" cyclonedx:"goroot"`
	GOPATH     string `json:"gopath,omitempty" cyclonedx:"gopath"`
	GOOS       string `json:"goos,omitempty" cyclonedx:"goos"`
	GOARCH     string `json:"goarch,omitempty" cyclonedx:"goarch"`
	Compiler   string `json:"compiler,omitempty" cyclonedx:"compiler"`
	BuildTags  string `json:"buildTags,omitempty" cyclonedx:"buildTags"`
	CgoEnabled bool   `json:"cgoEnabled" cyclonedx:"cgoEnabled"`
}
