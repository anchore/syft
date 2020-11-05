package json

import (
	"github.com/anchore/syft/syft/scope"
)

type Image struct {
	Layers    []Layer  `json:"layers"`
	Size      int64    `json:"size"`
	Digest    string   `json:"digest"`
	MediaType string   `json:"mediaType"`
	Tags      []string `json:"tags"`
}

type Layer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

func NewImage(src scope.ImageSource) *Image {
	// populate artifacts...
	tags := make([]string, len(src.Img.Metadata.Tags))
	for idx, tag := range src.Img.Metadata.Tags {
		tags[idx] = tag.String()
	}
	img := Image{
		Digest:    src.Img.Metadata.Digest,
		Size:      src.Img.Metadata.Size,
		MediaType: string(src.Img.Metadata.MediaType),
		Tags:      tags,
		Layers:    make([]Layer, len(src.Img.Layers)),
	}

	// populate image metadata
	for idx, l := range src.Img.Layers {
		img.Layers[idx] = Layer{
			MediaType: string(l.Metadata.MediaType),
			Digest:    l.Metadata.Digest,
			Size:      l.Metadata.Size,
		}
	}
	return &img
}
