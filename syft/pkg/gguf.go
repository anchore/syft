package pkg

// GGUFFileMetadata represents metadata extracted from a GGUF (GPT-Generated Unified Format) model file.
// GGUF is a binary file format used for storing model weights for the GGML library, designed for fast
// loading and saving of models, particularly quantized large language models.
type GGUFFileMetadata struct {
	// ModelFormat is always "gguf"
	ModelFormat string `json:"modelFormat" cyclonedx:"modelFormat"`

	// ModelName is the name of the model (from general.name or filename)
	ModelName string `json:"modelName" cyclonedx:"modelName"`

	// ModelVersion is the version of the model (if available in header, else "unknown")
	ModelVersion string `json:"modelVersion,omitempty" cyclonedx:"modelVersion"`

	// FileSize is the size of the GGUF file in bytes (best-effort if available from resolver)
	FileSize int64 `json:"fileSize,omitempty" cyclonedx:"fileSize"`

	// Hash is a content hash of the metadata (for stable global identifiers across remotes)
	Hash string `json:"hash,omitempty" cyclonedx:"hash"`

	// License is the license identifier (from general.license if present)
	License string `json:"license,omitempty" cyclonedx:"license"`

	// GGUFVersion is the GGUF format version (e.g., 3)
	GGUFVersion uint32 `json:"ggufVersion" cyclonedx:"ggufVersion"`

	// Architecture is the model architecture (from general.architecture, e.g., "qwen3moe", "llama")
	Architecture string `json:"architecture,omitempty" cyclonedx:"architecture"`

	// Quantization is the quantization type (e.g., "IQ4_NL", "Q4_K_M")
	Quantization string `json:"quantization,omitempty" cyclonedx:"quantization"`

	// Parameters is the number of model parameters (if present in header)
	Parameters uint64 `json:"parameters,omitempty" cyclonedx:"parameters"`

	// TensorCount is the number of tensors in the model
	TensorCount uint64 `json:"tensorCount" cyclonedx:"tensorCount"`

	// Header contains the remaining key-value pairs from the GGUF header that are not already
	// represented as typed fields above. This preserves additional metadata fields for reference
	// (namespaced with general.*, llama.*, etc.) while avoiding duplication.
	Header map[string]interface{} `json:"header,omitempty" cyclonedx:"header"`

	// TruncatedHeader indicates if the header was truncated during parsing (for very large headers)
	TruncatedHeader bool `json:"truncatedHeader,omitempty" cyclonedx:"truncatedHeader"`
}
