package sbom

// Writer an interface to write SBOMs to a destination
type Writer interface {
	Write(SBOM) error
}
