/*
Package ai provides concrete Cataloger implementations for AI artifacts and machine learning models,
including support for GGUF (GPT-Generated Unified Format) model files.
*/
package ai

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	catalogerName      = "gguf-cataloger"
	ggufLayerMediaType = "application/vnd.docker.ai*"
)

// NewGGUFCataloger returns a new cataloger instance for GGUF model files.
// It supports both traditional file-based discovery and OCI layer-aware discovery
// when the source for the SBOM is the oci model source
func NewGGUFCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseGGUFModel, "**/*.gguf").
		WithParserByMediaType(parseGGUFModel, ggufLayerMediaType).
		WithProcessors(ggufMergeProcessor)
}
