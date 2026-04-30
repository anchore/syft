package pkg

// SafeTensorsMetadata represents metadata extracted from a SafeTensors model.
// SafeTensors is a simple, safe serialization format for storing tensors, used
// as the default weight format for Hugging Face transformer models. Syft may
// populate this struct from three sources:
//   - a single .safetensors file (header-only parse)
//   - a sharded model described by model.safetensors.index.json
//   - a Docker AI OCI model artifact config blob (vnd.docker.ai.model.config.v0.1+json)
//
// The Model Name, License, and Version fields have all been lifted up to be on
// the syft Package.
type SafeTensorsMetadata struct {
	// Format is the source format label (always "safetensors" for this metadata type).
	// Present because the Docker AI model config blob carries an explicit format field
	// that can also be "gguf", and recording it here makes the origin explicit.
	Format string `json:"format,omitempty" cyclonedx:"format"`

	// Architecture is the model architecture (e.g., "LlamaForCausalLM",
	// "Qwen3MoeForConditionalGeneration"), sourced from the Hugging Face config.json
	// "architectures" array.
	Architecture string `json:"architecture,omitempty" cyclonedx:"architecture"`

	// Quantization describes tensor precision (e.g., "BF16", "F16", "F32", "INT8").
	Quantization string `json:"quantization,omitempty" cyclonedx:"quantization"`

	// Parameters is the parameter count as reported by upstream. Stored as a string
	// because Docker AI and Hugging Face labels use notation like "2.68B" or "35B-A3B".
	Parameters string `json:"parameters,omitempty" cyclonedx:"parameters"`

	// TensorCount is the number of tensor entries in the file header.
	TensorCount uint64 `json:"tensorCount,omitempty" cyclonedx:"tensorCount"`

	// TotalSize is the total byte size of tensor data across all shards when known
	// (from the Docker AI model config "size" field or the sharded index "total_size").
	TotalSize string `json:"totalSize,omitempty" cyclonedx:"totalSize"`

	// TorchDtype is the Hugging Face torch_dtype (e.g., "bfloat16", "float16").
	TorchDtype string `json:"torchDtype,omitempty" cyclonedx:"torchDtype"`

	// TransformersVersion is the transformers library version recorded in config.json.
	TransformersVersion string `json:"transformersVersion,omitempty" cyclonedx:"transformersVersion"`

	// ShardCount is the number of .safetensors shards for a sharded model (1 for a
	// single-file model).
	ShardCount int `json:"shardCount,omitempty" cyclonedx:"shardCount"`

	// UserMetadata is the optional "__metadata__" map from a .safetensors file header
	// (string-to-string key/values set by the producer).
	UserMetadata map[string]string `json:"userMetadata,omitempty" cyclonedx:"userMetadata"`

	// MetadataHash is an xxhash of the normalized header metadata, providing a stable
	// identifier for identical model content across repositories or filenames.
	MetadataHash string `json:"metadataHash,omitempty" cyclonedx:"metadataHash"`

	// Parts contains metadata from additional SafeTensors shards or OCI layers that
	// were merged into this package during post-processing.
	Parts []SafeTensorsMetadata `json:"parts,omitempty" cyclonedx:"parts"`
}
