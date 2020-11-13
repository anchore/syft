package json

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

type Locations interface{}

type ImageLocation struct {
	Path       string `json:"path"`
	LayerIndex uint   `json:"layerIndex"`
}

func NewLocations(p *pkg.Package, s source.Source) (Locations, error) {
	switch src := s.Target.(type) {
	case source.ImageSource:
		locations := make([]ImageLocation, len(p.Source))
		for idx := range p.Source {
			entry, err := src.Img.FileCatalog.Get(p.Source[idx])
			if err != nil {
				return nil, fmt.Errorf("unable to find layer index for source-idx=%d package=%s", idx, p.Name)
			}

			artifactSource := ImageLocation{
				LayerIndex: entry.Source.Metadata.Index,
				Path:       string(p.Source[idx].Path),
			}

			locations[idx] = artifactSource
		}
		return locations, nil

	case source.DirSource:
		locations := make([]string, len(p.Source))
		for idx := range p.Source {
			locations[idx] = string(p.Source[idx].Path)
		}
		return locations, nil
	default:
		return nil, fmt.Errorf("unable to determine source: %T", src)
	}
}
