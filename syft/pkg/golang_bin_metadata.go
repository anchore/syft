package pkg

// GolangBinMetadata represents all captured data for a Golang Binary
type GolangBinMetadata struct {
	BuildSettings     map[string]string `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string            `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string            `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string            `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
}
