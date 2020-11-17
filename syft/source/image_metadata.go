package source

import "github.com/anchore/stereoscope/pkg/image"

// ImageMetadata represents all static metadata that defines what a container image is. This is useful to later describe
// "what" was cataloged without needing the more complicated stereoscope Image objects or Resolver objects.
type ImageMetadata struct {
	UserInput string          `json:"userInput"`
	Scope     Scope           `json:"scope"` // specific perspective to catalog
	Layers    []LayerMetadata `json:"layers"`
	Size      int64           `json:"size"`
	Digest    string          `json:"digest"`
	MediaType string          `json:"mediaType"`
	Tags      []string        `json:"tags"`
}

// LayerMetadata represents all static metadata that defines what a container image layer is.
type LayerMetadata struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// NewImageMetadata creates a new ImageMetadata object populated from the given stereoscope Image object and user configuration.
func NewImageMetadata(img *image.Image, userInput string, scope Scope) ImageMetadata {
	// populate artifacts...
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}
	theImg := ImageMetadata{
		UserInput: userInput,
		Scope:     scope,
		Digest:    img.Metadata.Digest,
		Size:      img.Metadata.Size,
		MediaType: string(img.Metadata.MediaType),
		Tags:      tags,
		Layers:    make([]LayerMetadata, len(img.Layers)),
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
