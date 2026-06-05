package pkg

// SafeTensorsModelInfo holds the model details extracted from SafeTensors content.
// SafeTensors is a simple, safe serialization format for storing tensors, used
// as the default weight format for Hugging Face transformer models. Syft may
// populate this struct from these sources:
//   - a single .safetensors file (header-only parse)
//   - the per-shard headers of a multi-shard model, merged into one package
//   - a Docker AI OCI model artifact: the config blob
//     (vnd.docker.ai.model.config.v0.1+json) plus each weight layer's header
//
// Model name, license, and version live on the enclosing syft Package rather
// than in this struct.
type SafeTensorsModelInfo struct {
	// Format is the source format label (always "safetensors" for this metadata type).
	// Present because the Docker AI model config blob carries an explicit format field
	// that can also be "gguf", and recording it here makes the origin explicit.
	Format string `json:"format,omitempty" cyclonedx:"format"`

	// Architecture is the model architecture (e.g., "LlamaForCausalLM",
	// "Qwen3MoeForConditionalGeneration"). It is not present in the SafeTensors
	// header itself; it is enriched from the companion Hugging Face config.json
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
	// (string-to-string key/values set by the producer). Stored as a sorted KeyValues
	// slice rather than a Go map so SBOM output is stable across runs.
	UserMetadata KeyValues `json:"userMetadata,omitempty" cyclonedx:"userMetadata"`

	// MetadataHash is an xxhash over the on-disk SafeTensors header (sorted tensor
	// entries + __metadata__). It is derived ONLY from the safetensors file bytes —
	// never from OCI manifest, layer descriptor, or config-blob fields — so the same
	// model content scanned via a directory source and via an OCI image produces the
	// same value. Treat this as the cross-source content fingerprint.
	MetadataHash string `json:"metadataHash,omitempty" cyclonedx:"metadataHash"`

	// Parts contains metadata from additional SafeTensors shards or OCI layers that
	// were merged into this package during post-processing.
	Parts []SafeTensorsModelInfo `json:"parts,omitempty" cyclonedx:"parts"`
}
