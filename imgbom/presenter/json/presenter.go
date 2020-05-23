package json

import (
	"encoding/json"
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal/log"
	stereoscopeImg "github.com/anchore/stereoscope/pkg/image"
)

type Presenter struct{}

func NewPresenter() *Presenter {
	return &Presenter{}
}

type document struct {
	Image     image      `json:"image"`
	Artifacts []artifact `json:"artifacts"`
}

type image struct {
	Layers    []layer  `json:"layers"`
	Size      int64    `json:"size"`
	Digest    string   `json:"digest"`
	MediaType string   `json:"mediaType"`
	Tags      []string `json:"tags"`
}

type layer struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

type source struct {
	Source  string   `json:"source"`
	Layer   int      `json:"layer"`
	Effects []string `json:"effects"`
}

type artifact struct {
	Name     string      `json:"name"`
	Version  string      `json:"version"`
	Type     string      `json:"type"`
	Analyzer string      `json:"analyzer"`
	Sources  []source    `json:"sources"`
	Metadata interface{} `json:"metadata"`
}

func (pres *Presenter) Present(output io.Writer, img *stereoscopeImg.Image, catalog pkg.Catalog) error {
	tags := make([]string, len(img.Metadata.Tags))
	for idx, tag := range img.Metadata.Tags {
		tags[idx] = tag.String()
	}

	doc := document{
		Image: image{
			Digest:    img.Metadata.Digest,
			Size:      img.Metadata.Size,
			MediaType: string(img.Metadata.MediaType),
			Tags:      tags,
			Layers:    make([]layer, len(img.Layers)),
		},
		Artifacts: make([]artifact, 0),
	}

	// populate image...
	for idx, l := range img.Layers {
		doc.Image.Layers[idx] = layer{
			MediaType: string(l.Metadata.MediaType),
			Digest:    l.Metadata.Digest,
			Size:      l.Metadata.Size,
		}
	}

	// populate artifacts...
	for p := range catalog.Enumerate() {
		art := artifact{
			Name:     p.Name,
			Version:  p.Version,
			Type:     p.Type.String(),
			Analyzer: "TODO", // TODO
			Sources:  make([]source, len(p.Source)),
			Metadata: p.Metadata,
		}

		for idx, src := range p.Source {
			fileMetadata, err := img.FileCatalog.Get(src)
			if err != nil {
				// TODO: test case
				log.Errorf("could not get metadata from catalog (presenter=json): %+v", src)
			}

			srcObj := source{
				Source:  "",
				Layer:   int(fileMetadata.Source.Metadata.Index),
				Effects: []string{}, // TODO
			}
			art.Sources[idx] = srcObj
		}

		doc.Artifacts = append(doc.Artifacts, art)
	}

	bytes, err := json.Marshal(&doc)
	if err != nil {
		log.Errorf("failed to marshal json (presenter=json): %w", err)
	}

	_, err = output.Write(bytes)
	return err
}
