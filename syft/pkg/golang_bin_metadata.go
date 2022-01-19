package pkg

// GolangBinMetadata represents all captured data for a Golang Binary
type GolangBinMetadata struct {
	GoCompiledVersion string `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string `json:"h1Digest" cyclonedx:"h1Digest"`
}
