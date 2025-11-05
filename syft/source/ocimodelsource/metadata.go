package ocimodelsource

import "github.com/anchore/syft/syft/source"

// OCIModelMetadata represents all static metadata that defines what an OCI model artifact is.
// This is similar to ImageMetadata but includes model-specific fields and OCI artifact annotations.
type OCIModelMetadata struct {
	// Core OCI artifact metadata (mirrors ImageMetadata)
	UserInput      string                  `json:"userInput"`
	ID             string                  `json:"artifactID"`
	ManifestDigest string                  `json:"manifestDigest"`
	MediaType      string                  `json:"mediaType"`
	Tags           []string                `json:"tags"`
	Size           int64                   `json:"artifactSize"`
	Layers         []source.LayerMetadata  `json:"layers"`
	RawManifest    []byte                  `json:"manifest"`
	RawConfig      []byte                  `json:"config"`
	RepoDigests    []string                `json:"repoDigests"`
	Architecture   string                  `json:"architecture"`
	Variant        string                  `json:"architectureVariant,omitempty"`
	OS             string                  `json:"os"`
	Labels         map[string]string       `json:"labels,omitempty"`

	// OCI-specific metadata
	Annotations map[string]string `json:"annotations,omitempty"`

	// Model-specific metadata
	ModelFormat string          `json:"modelFormat,omitempty"` // e.g., "gguf"
	GGUFLayers  []GGUFLayerInfo `json:"ggufLayers,omitempty"`
}

// GGUFLayerInfo represents metadata about a GGUF layer in the OCI artifact.
type GGUFLayerInfo struct {
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`         // Full blob size in registry
	MediaType    string            `json:"mediaType"`    // Should be "application/vnd.docker.ai.gguf.v3"
	Annotations  map[string]string `json:"annotations,omitempty"`
	FetchedBytes int64             `json:"fetchedBytes"` // How many bytes we actually fetched via range-GET
}
