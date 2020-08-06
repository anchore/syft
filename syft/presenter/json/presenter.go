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

type Document struct {
	Artifacts []Artifact `json:"artifacts"`
	Image     *Image     `json:"image,omitempty"`
	Directory *string    `json:"directory,omitempty"`
}

type Image struct {
	Layers    []Layer  `json:"layers"`
	Size      int64    `json:"size"`
	Digest    string   `json:"digest"`
	MediaType string   `json:"media-type"`
	Tags      []string `json:"tags"`
}

type Layer struct {
	MediaType string `json:"media-type"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type ImageLocation struct {
	Path       string `json:"path"`
	LayerIndex uint   `json:"layer-index"`
}

type Artifact struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Type      string      `json:"type"`
	FoundBy   []string    `json:"found-by"`
	Locations interface{} `json:"locations,omitempty"` // this can be a []string for simple dir sources or []ImageLocation for image sources
	Metadata  interface{} `json:"metadata,omitempty"`
}

// nolint:funlen
func (pres *Presenter) Present(output io.Writer) error {
	doc := Document{
		Artifacts: make([]Artifact, 0),
	}

	srcObj := pres.scope.Source()
	switch src := srcObj.(type) {
	case scope.ImageSource:
		// populate artifacts...
		tags := make([]string, len(src.Img.Metadata.Tags))
		for idx, tag := range src.Img.Metadata.Tags {
			tags[idx] = tag.String()
		}
		doc.Image = &Image{
			Digest:    src.Img.Metadata.Digest,
			Size:      src.Img.Metadata.Size,
			MediaType: string(src.Img.Metadata.MediaType),
			Tags:      tags,
			Layers:    make([]Layer, len(src.Img.Layers)),
		}

		// populate image metadata
		for idx, l := range src.Img.Layers {
			doc.Image.Layers[idx] = Layer{
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
		art := Artifact{
			Name:     p.Name,
			Version:  p.Version,
			Type:     string(p.Type),
			FoundBy:  []string{p.FoundBy},
			Metadata: p.Metadata,
		}

		switch src := srcObj.(type) {
		case scope.ImageSource:
			locations := make([]ImageLocation, len(p.Source))
			for idx := range p.Source {
				entry, err := src.Img.FileCatalog.Get(p.Source[idx])
				if err != nil {
					return fmt.Errorf("unable to find layer index for source-idx=%d package=%s", idx, p.Name)
				}

				artifactSource := ImageLocation{
					LayerIndex: entry.Source.Metadata.Index,
					Path:       string(p.Source[idx].Path),
				}

				locations[idx] = artifactSource
			}
			art.Locations = locations

		case scope.DirSource:
			locations := make([]string, len(p.Source))
			for idx := range p.Source {
				locations[idx] = string(p.Source[idx].Path)
			}
			art.Locations = locations
		}

		doc.Artifacts = append(doc.Artifacts, art)
	}

	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	return enc.Encode(&doc)
}
