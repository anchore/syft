package pkg

// GolangMetadata represents all captured data for a Golang Binary
type GolangMetadata struct {
	BuildSettings     map[string]string `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`
	GoCompiledVersion string            `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`
	Architecture      string            `json:"architecture" cyclonedx:"architecture"`
	H1Digest          string            `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
	MainModule        string            `json:"mainModule,omitempty" cyclonedx:"mainModule"`
}
