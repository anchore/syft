// this file provides a single source of truth for all capability file paths used in generation and testing.
package internal

import "path/filepath"

// path constants - single source of truth for all capability file locations
const (
	// CatalogerDirRel is the cataloger directory relative to repo root
	CatalogerDirRel = "syft/pkg/cataloger"

	// InternalCapabilitiesDirRel is internal capabilities dir relative to repo root
	InternalCapabilitiesDirRel = "internal/capabilities"

	// CapabilitiesFilename is the capabilities file name within each ecosystem dir
	CapabilitiesFilename = "capabilities.yaml"

	// AppconfigFilename is the application config filename
	AppconfigFilename = "appconfig.yaml"
)

// CatalogerDir returns absolute path to cataloger directory
func CatalogerDir(repoRoot string) string {
	return filepath.Join(repoRoot, CatalogerDirRel)
}

// CapabilitiesDir returns absolute path to internal capabilities
func CapabilitiesDir(repoRoot string) string {
	return filepath.Join(repoRoot, InternalCapabilitiesDirRel)
}

// EcosystemCapabilitiesPath returns path to an ecosystem's capabilities.yaml
func EcosystemCapabilitiesPath(catalogerDir, ecosystem string) string {
	return filepath.Join(catalogerDir, ecosystem, CapabilitiesFilename)
}

// AppconfigPath returns path to appconfig.yaml (in internal/capabilities)
func AppconfigPath(repoRoot string) string {
	return filepath.Join(CapabilitiesDir(repoRoot), AppconfigFilename)
}
