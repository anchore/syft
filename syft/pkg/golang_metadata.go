package pkg

// GolangBinMetadata represents all captured data for a Golang binary
type GolangBinMetadata struct {
	BuildSettings     map[string]string `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string            `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string            `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string            `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	MainModule        string            `json:"mainModule,omitempty" cyclonedx:"mainModule"`
	GoCryptoSettings  []string          `json:"goCryptoSettings,omitempty" cyclonedx:"goCryptoSettings"`
}

// GolangModMetadata represents all captured data for a Golang source scan with go.mod/go.sum
type GolangModMetadata struct {
	H1Digest string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
}
