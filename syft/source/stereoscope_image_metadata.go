package source

import "github.com/anchore/stereoscope/pkg/image"

// StereoscopeImageSourceMetadata represents all static metadata that defines what a container image is. This is useful to later describe
// "what" was cataloged without needing the more complicated stereoscope Image objects or FileResolver objects.
type StereoscopeImageSourceMetadata struct {
	UserInput      string                     `json:"userInput"`
	ID             string                     `json:"imageID"`
	ManifestDigest string                     `json:"manifestDigest"`
	MediaType      string                     `json:"mediaType"`
	Tags           []string                   `json:"tags"`
	Size           int64                      `json:"imageSize"`
	Layers         []StereoscopeLayerMetadata `json:"layers"`
	RawManifest    []byte                     `json:"manifest"`
	RawConfig      []byte                     `json:"config"`
	RepoDigests    []string                   `json:"repoDigests"`
	Architecture   string                     `json:"architecture"`
	Variant        string                     `json:"architectureVariant,omitempty"`
	OS             string                     `json:"os"`
	Labels         map[string]string          `json:"labels,omitempty"`
}

// StereoscopeLayerMetadata represents all static metadata that defines what a container image layer is.
type StereoscopeLayerMetadata struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// NewStereoscopeImageMetadata creates a new ImageMetadata object populated from the given stereoscope Image object and user configuration.
func NewStereoscopeImageMetadata(img *image.Image, userInput string) StereoscopeImageSourceMetadata {
	// populate artifacts...
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}
	theImg := StereoscopeImageSourceMetadata{
		ID:             img.Metadata.ID,
		UserInput:      userInput,
		ManifestDigest: img.Metadata.ManifestDigest,
		Size:           img.Metadata.Size,
		MediaType:      string(img.Metadata.MediaType),
		Tags:           tags,
		Layers:         make([]StereoscopeLayerMetadata, len(img.Layers)),
		RawConfig:      img.Metadata.RawConfig,
		RawManifest:    img.Metadata.RawManifest,
		RepoDigests:    img.Metadata.RepoDigests,
		Architecture:   img.Metadata.Architecture,
		Variant:        img.Metadata.Variant,
		OS:             img.Metadata.OS,
		Labels:         img.Metadata.Config.Config.Labels,
	}

	// populate image metadata
	for idx, l := range img.Layers {
		theImg.Layers[idx] = StereoscopeLayerMetadata{
			MediaType: string(l.Metadata.MediaType),
			Digest:    l.Metadata.Digest,
			Size:      l.Metadata.Size,
		}
	}
	return theImg
}
