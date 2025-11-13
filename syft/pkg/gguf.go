package pkg

// GGUFFileHeader represents metadata extracted from a GGUF (GPT-Generated Unified Format) model file.
// GGUF is a binary file format used for storing model weights for the GGML library, designed for fast
// loading and saving of models, particularly quantized large language models.
// The Model Name, License, and Version fields have all been lifted up to be on the syft Package.
type GGUFFileHeader struct {
	// GGUFVersion is the GGUF format version (e.g., 3)
	GGUFVersion uint32 `json:"ggufVersion" cyclonedx:"ggufVersion"`

	// FileSize is the size of the GGUF file in bytes (best-effort if available from resolver)
	FileSize int64 `json:"fileSize,omitempty" cyclonedx:"fileSize"`

	// Architecture is the model architecture (from general.architecture, e.g., "qwen3moe", "llama")
	Architecture string `json:"architecture,omitempty" cyclonedx:"architecture"`

	// Quantization is the quantization type (e.g., "IQ4_NL", "Q4_K_M")
	Quantization string `json:"quantization,omitempty" cyclonedx:"quantization"`

	// Parameters is the number of model parameters (if present in header)
	Parameters uint64 `json:"parameters,omitempty" cyclonedx:"parameters"`

	// TensorCount is the number of tensors in the model
	TensorCount uint64 `json:"tensorCount" cyclonedx:"tensorCount"`

	// RemainingKeyValues contains the remaining key-value pairs from the GGUF header that are not already
	// represented as typed fields above. This preserves additional metadata fields for reference
	// (namespaced with general.*, llama.*, etc.) while avoiding duplication.
	RemainingKeyValues map[string]interface{} `json:"header,omitempty" cyclonedx:"header"`

	// MetadataKeyValuesHash is a xx64 hash of all key-value pairs from the GGUF header metadata.
	// This hash is computed over the complete header metadata (including the fields extracted
	// into typed fields above) and provides a stable identifier for the model configuration
	// across different file locations or remotes. It allows matching identical models even
	// when stored in different repositories or with different filenames.
	MetadataKeyValuesHash string `json:"metadataHash,omitempty" cyclonedx:"metadataHash"`
}
