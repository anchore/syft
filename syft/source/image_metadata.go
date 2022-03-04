package source

import "github.com/anchore/stereoscope/pkg/image"

// ImageMetadata represents all static metadata that defines what a container image is. This is useful to later describe
// "what" was cataloged without needing the more complicated stereoscope Image objects or FileResolver objects.
type ImageMetadata struct {
	UserInput      string          `json:"userInput"`
	ID             string          `json:"imageID"`
	ManifestDigest string          `json:"manifestDigest"`
	MediaType      string          `json:"mediaType"`
	Tags           []string        `json:"tags"`
	Size           int64           `json:"imageSize"`
	Layers         []LayerMetadata `json:"layers"`
	RawManifest    []byte          `json:"manifest"`
	RawConfig      []byte          `json:"config"`
	RepoDigests    []string        `json:"repoDigests"`
	Architecture   string          `json:"architecture"`
	Variant        string          `json:"architectureVariant,omitempty"`
	OS             string          `json:"os"`
}

// LayerMetadata represents all static metadata that defines what a container image layer is.
type LayerMetadata struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// NewImageMetadata creates a new ImageMetadata object populated from the given stereoscope Image object and user configuration.
func NewImageMetadata(img *image.Image, userInput string) ImageMetadata {
	// populate artifacts...
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}
	theImg := ImageMetadata{
		ID:             img.Metadata.ID,
		UserInput:      userInput,
		ManifestDigest: img.Metadata.ManifestDigest,
		Size:           img.Metadata.Size,
		MediaType:      string(img.Metadata.MediaType),
		Tags:           tags,
		Layers:         make([]LayerMetadata, len(img.Layers)),
		RawConfig:      img.Metadata.RawConfig,
		RawManifest:    img.Metadata.RawManifest,
		RepoDigests:    img.Metadata.RepoDigests,
		Architecture:   img.Metadata.Architecture,
		Variant:        img.Metadata.Variant,
		OS:             img.Metadata.OS,
	}

	// populate image metadata
	for idx, l := range img.Layers {
		theImg.Layers[idx] = LayerMetadata{
			MediaType: string(l.Metadata.MediaType),
			Digest:    l.Metadata.Digest,
			Size:      l.Metadata.Size,
		}
	}
	return theImg
}
