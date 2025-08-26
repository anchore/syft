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
	H1Digest        string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	OperatingSystem string `json:"os,omitempty" cyclonedx:"os"`
	Architecture    string `json:"architecture,omitempty" cyclonedx:"architecture"`
	BuildTags       string `json:"buildTags,omitempty" cyclonedx:"buildTags"`
	CgoEnabled      bool   `json:"cgoEnabled" cyclonedx:"cgoEnabled"`
}
