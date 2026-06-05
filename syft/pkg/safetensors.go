package pkg

// SafeTensorsModelInfo holds the model details extracted from SafeTensors content.
// SafeTensors is a simple, safe serialization format for storing tensors, used
// as the default weight format for Hugging Face transformer models.
// Model name, license, and version live on the syft Package
type SafeTensorsModelInfo struct {
	// Format is the source format label (always "safetensors" for this metadata type).
	// Present because the Docker AI model config blob carries an explicit format field
	Format string `json:"format,omitempty" cyclonedx:"format"`

	// Architecture is the model architecture (e.g., "LlamaForCausalLM",
	// "Qwen3MoeForConditionalGeneration"). It is not present in the SafeTensors
	// header itself; it is enriched from the companion config.json
	// "architectures" array when one is found alongside the model.
	Architecture string `json:"architecture,omitempty" cyclonedx:"architecture"`

	// Quantization describes tensor precision (e.g., "BF16", "F16", "F32", "INT8").
	Quantization string `json:"quantization,omitempty" cyclonedx:"quantization"`

	// Parameters is the parameter count as reported by upstream. Stored as a string
	// because Docker AI and Hugging Face labels use notation like "2.68B" or "35B-A3B".
	Parameters string `json:"parameters,omitempty" cyclonedx:"parameters"`

	// TensorCount is the number of tensor entries in the file header.
	TensorCount uint64 `json:"tensorCount,omitempty" cyclonedx:"tensorCount"`

	// TotalSize is the total byte size of tensor data across all shards when known
	// (from the Docker AI model config "size" field).
	TotalSize string `json:"totalSize,omitempty" cyclonedx:"totalSize"`

	// ShardCount is the number of .safetensors shards for a sharded model (1 for a
	// single-file model).
	ShardCount int `json:"shardCount,omitempty" cyclonedx:"shardCount"`

	// UserMetadata is the optional "__metadata__" map from a .safetensors file header
	// (string-to-string key/values set by the producer).
	UserMetadata KeyValues `json:"userMetadata,omitempty" cyclonedx:"userMetadata"`

	// MetadataHash is an xxhash over the on-disk SafeTensors header (sorted tensor
	// entries + __metadata__). It is derived ONLY from the safetensors file bytes.
	MetadataHash string `json:"metadataHash,omitempty" cyclonedx:"metadataHash"`

	// Parts contains metadata from additional SafeTensors shards or OCI layers that
	// were merged into this package during post-processing.
	Parts []SafeTensorsModelInfo `json:"parts,omitempty" cyclonedx:"parts"`
}
