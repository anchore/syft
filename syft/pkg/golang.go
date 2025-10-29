package pkg

// GolangBinaryBuildinfoEntry represents all captured data for a Golang binary
type GolangBinaryBuildinfoEntry struct {
	// BuildSettings contains the Go build settings and flags used to compile the binary (e.g., GOARCH, GOOS, CGO_ENABLED).
	BuildSettings KeyValues `json:"goBuildSettings,omitempty" cyclonedx:"goBuildSettings"`

	// GoCompiledVersion is the version of Go used to compile the binary.
	GoCompiledVersion string `json:"goCompiledVersion" cyclonedx:"goCompiledVersion"`

	// Architecture is the target CPU architecture for the binary (extracted from GOARCH build setting).
	Architecture string `json:"architecture" cyclonedx:"architecture"`

	// H1Digest is the Go module hash in h1: format for the main module from go.sum.
	H1Digest string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`

	// MainModule is the main module path for the binary (e.g., "github.com/anchore/syft").
	MainModule string `json:"mainModule,omitempty" cyclonedx:"mainModule"`

	// GoCryptoSettings contains FIPS and cryptographic configuration settings if present.
	GoCryptoSettings []string `json:"goCryptoSettings,omitempty" cyclonedx:"goCryptoSettings"`

	// GoExperiments lists experimental Go features enabled during compilation (e.g., "arenas", "cgocheck2").
	GoExperiments []string `json:"goExperiments,omitempty" cyclonedx:"goExperiments"`
}

// GolangModuleEntry represents all captured data for a Golang source scan with go.mod/go.sum
type GolangModuleEntry struct {
	// H1Digest is the Go module hash in h1: format from go.sum for verifying module contents.
	H1Digest string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`
}

// GolangSourceEntry represents all captured data for a Golang package found through source analysis
type GolangSourceEntry struct {
	// H1Digest is the Go module hash in h1: format from go.sum for verifying module contents.
	H1Digest string `json:"h1Digest,omitempty" cyclonedx:"h1Digest"`

	// OperatingSystem is the target OS for build constraints (e.g., "linux", "darwin", "windows").
	OperatingSystem string `json:"os,omitempty" cyclonedx:"os"`

	// Architecture is the target CPU architecture for build constraints (e.g., "amd64", "arm64").
	Architecture string `json:"architecture,omitempty" cyclonedx:"architecture"`

	// BuildTags are the build tags used to conditionally compile code (e.g., "integration,debug").
	BuildTags string `json:"buildTags,omitempty" cyclonedx:"buildTags"`

	// CgoEnabled indicates whether CGO was enabled for this package.
	CgoEnabled bool `json:"cgoEnabled" cyclonedx:"cgoEnabled"`
}
