package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

type Presenter struct {
	catalog *pkg.Catalog
	scope   scope.Scope
}

func NewPresenter(catalog *pkg.Catalog, s scope.Scope) *Presenter {
	return &Presenter{
		catalog: catalog,
		scope:   s,
	}
}

type document struct {
	Artifacts []artifact `json:"artifacts"`
	Image     *image     `json:"image,omitempty"`
	Directory *string    `json:"directory,omitempty"`
}

type image struct {
	Layers    []layer  `json:"layers"`
	Size      int64    `json:"size"`
	Digest    string   `json:"digest"`
	MediaType string   `json:"media-type"`
	Tags      []string `json:"tags"`
}

type layer struct {
	MediaType string `json:"media-type"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type source struct {
	FoundBy   string   `json:"found-by"`
	Locations []string `json:"locations"`
}

type artifact struct {
	Name     string      `json:"name"`
	Version  string      `json:"version"`
	Type     string      `json:"type"`
	Sources  []source    `json:"sources"`
	Metadata interface{} `json:"metadata,omitempty"`
}

func (pres *Presenter) Present(output io.Writer) error {
	doc := document{
		Artifacts: make([]artifact, 0),
	}

	srcObj := pres.scope.Source()
	switch src := srcObj.(type) {
	case scope.ImageSource:
		// populate artifacts...
		tags := make([]string, len(src.Img.Metadata.Tags))
		for idx, tag := range src.Img.Metadata.Tags {
			tags[idx] = tag.String()
		}
		doc.Image = &image{
			Digest:    src.Img.Metadata.Digest,
			Size:      src.Img.Metadata.Size,
			MediaType: string(src.Img.Metadata.MediaType),
			Tags:      tags,
			Layers:    make([]layer, len(src.Img.Layers)),
		}

		// populate image metadata
		for idx, l := range src.Img.Layers {
			doc.Image.Layers[idx] = layer{
				MediaType: string(l.Metadata.MediaType),
				Digest:    l.Metadata.Digest,
				Size:      l.Metadata.Size,
			}
		}

	case scope.DirSource:
		doc.Directory = &pres.scope.DirSrc.Path
	default:
		return fmt.Errorf("unsupported source: %T", src)
	}

	for _, p := range pres.catalog.Sorted() {
		art := artifact{
			Name:     p.Name,
			Version:  p.Version,
			Type:     string(p.Type),
			Sources:  make([]source, len(p.Source)),
			Metadata: p.Metadata,
		}

		for idx := range p.Source {
			srcObj := source{
				FoundBy:   p.FoundBy,
				Locations: []string{string(p.Source[idx].Path)},
			}
			art.Sources[idx] = srcObj
		}

		doc.Artifacts = append(doc.Artifacts, art)
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
