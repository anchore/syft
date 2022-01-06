package sbom

import "io"

// Writer an interface to write SBOMs
type Writer interface {
	// Write writes the provided SBOM
	Write(SBOM) error

	// Closer a resource cleanup hook which will be called after SBOM
	// is written or if an error occurs before Write is called
	io.Closer
}
