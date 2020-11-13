package source

import "github.com/anchore/stereoscope/pkg/image"

type ImageMetadata struct {
	UserInput string          `json:"userInput"`
	Layers    []LayerMetadata `json:"layers"`
	Size      int64           `json:"size"`
	Digest    string          `json:"digest"`
	MediaType string          `json:"mediaType"`
	Tags      []string        `json:"tags"`
}

type LayerMetadata struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func NewImageMetadata(img *image.Image, userInput string) ImageMetadata {
	// populate artifacts...
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}
	theImg := ImageMetadata{
		UserInput: userInput,
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
