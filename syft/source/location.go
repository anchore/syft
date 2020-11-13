package source

import (
	"github.com/anchore/syft/internal/log"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
)

type Location struct {
	Path       string `json:"path"`
	LayerIndex uint   `json:"layerIndex"`
	LayerID    string `json:"layerID"`
	ref        file.Reference
}

func NewLocation(path string) Location {
	return Location{
		Path: path,
	}
}

func NewLocationFromImage(ref file.Reference, img *image.Image) Location {
	entry, err := img.FileCatalog.Get(ref)
	if err != nil {
		log.Warnf("unable to find file catalog entry for ref=%+v", ref)
		return Location{
			Path: string(ref.Path),
			ref:  ref,
		}
	}

	return Location{
		Path:       string(ref.Path),
		LayerIndex: entry.Source.Metadata.Index,
		LayerID:    entry.Source.Metadata.Digest,
		ref:        ref,
	}
}
