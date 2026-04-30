/*
Package ai provides concrete Cataloger implementations for AI artifacts and machine learning models,
including support for GGUF (GPT-Generated Unified Format) and SafeTensors model files.
*/
package ai

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const (
	catalogerName             = "gguf-cataloger"
	ggufLayerMediaType        = "application/vnd.docker.ai*"
	safeTensorsCatalogerName  = "safetensors-cataloger"
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

// NewSafeTensorsCataloger returns a cataloger for SafeTensors model files,
// covering three discovery paths:
//   - **/*.safetensors files (single-file models; header-only parse)
//   - **/model.safetensors.index.json files (sharded models)
//   - application/vnd.docker.ai.model.config.v0.1+json OCI layers (Docker Model
//     Runner artifacts whose config advertises format=="safetensors")
func NewSafeTensorsCataloger() pkg.Cataloger {
	return generic.NewCataloger(safeTensorsCatalogerName).
		WithParserByGlobs(parseSafeTensorsFile, "**/*.safetensors").
		WithParserByGlobs(parseSafeTensorsIndex, "**/*.safetensors.index.json").
		WithParserByMediaType(parseSafeTensorsOCIConfig, dockerAIModelConfigMediaType).
		WithProcessors(safeTensorsMergeProcessor)
}
