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
	catalogerName            = "gguf-cataloger"
	ggufLayerMediaType       = "application/vnd.docker.ai*"
	safeTensorsCatalogerName = "safetensors-cataloger"
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
//   - **/*.safetensors files (single-file models and individual shards;
//     header-only parse)
//   - application/vnd.docker.ai.model.config.v0.1+json / v0.2+json OCI layers
//     (Docker Model Runner artifacts whose config advertises format=="safetensors")
//   - application/vnd.docker.ai.safetensors OCI layers (per-shard JSON headers,
//     fetched as a prefix by the OCI model source; emitted as nameless
//     packages and merged into the config-derived package as Parts)
//
// model.safetensors.index.json files are intentionally not parsed today: the
// index describes how tensors map to shards but contributes no metadata the
// cataloger can't derive from the shard headers themselves. If a model is
// distributed as just an index.json with no accompanying shard files, the
// cataloger emits nothing for that directory.
func NewSafeTensorsCataloger() pkg.Cataloger {
	return generic.NewCataloger(safeTensorsCatalogerName).
		WithParserByGlobs(parseSafeTensorsFile, "**/*.safetensors").
		WithParserByMediaType(parseSafeTensorsOCIConfig, dockerAIModelConfigMediaTypes...).
		WithParserByMediaType(parseSafeTensorsOCILayer, dockerAISafeTensorsMediaType).
		WithResolvingProcessors(safeTensorsMergeProcessor)
}
