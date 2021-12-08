package pkg

// GolangBinMetadata represents all captured data for a Golang Binary
type GolangBinMetadata struct {
	GoCompiledVersion string `json:"goCompiledVersion"`
	Architecture      string `json:"architecture"`
	H1Digest          string `json:"h1Digest"`
}
