package source

// ImageMetadata represents all static metadata that defines what a container image is. This is useful to later describe
// "what" was cataloged without needing the more complicated stereoscope Image objects or FileResolver objects.
type ImageMetadata struct {
	UserInput      string            `json:"userInput"`
	ID             string            `json:"imageID"`
	ManifestDigest string            `json:"manifestDigest"`
	MediaType      string            `json:"mediaType"`
	Tags           []string          `json:"tags"`
	Size           int64             `json:"imageSize"`
	Layers         []LayerMetadata   `json:"layers"`
	RawManifest    []byte            `json:"manifest"`
	RawConfig      []byte            `json:"config"`
	RepoDigests    []string          `json:"repoDigests"`
	Architecture   string            `json:"architecture"`
	Variant        string            `json:"architectureVariant,omitempty"`
	OS             string            `json:"os"`
	Labels         map[string]string `json:"labels,omitempty"`
}

// LayerMetadata represents all static metadata that defines what a container image layer is.
type LayerMetadata struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}
