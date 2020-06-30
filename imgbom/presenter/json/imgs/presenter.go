package imgs

import (
	"encoding/json"
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal/log"
	stereoscopeImg "github.com/anchore/stereoscope/pkg/image"
)

type Presenter struct {
	img     *stereoscopeImg.Image
	catalog *pkg.Catalog
}

func NewPresenter(img *stereoscopeImg.Image, catalog *pkg.Catalog) *Presenter {
	return &Presenter{
		img:     img,
		catalog: catalog,
	}
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
	FoundBy string   `json:"foundBy"`
	Layer   int      `json:"layer"`
	Effects []string `json:"effects"`
}

type artifact struct {
	Name      string      `json:"name"`
	Version   string      `json:"version"`
	Type      string      `json:"type"`
	Cataloger string      `json:"cataloger"`
	Sources   []source    `json:"sources"`
	Metadata  interface{} `json:"metadata"`
}

func (pres *Presenter) Present(output io.Writer) error {
	tags := make([]string, len(pres.img.Metadata.Tags))
	for idx, tag := range pres.img.Metadata.Tags {
		tags[idx] = tag.String()
	}

	doc := document{
		Image: image{
			Digest:    pres.img.Metadata.Digest,
			Size:      pres.img.Metadata.Size,
			MediaType: string(pres.img.Metadata.MediaType),
			Tags:      tags,
			Layers:    make([]layer, len(pres.img.Layers)),
		},
		Artifacts: make([]artifact, 0),
	}

	// populate image...
	for idx, l := range pres.img.Layers {
		doc.Image.Layers[idx] = layer{
			MediaType: string(l.Metadata.MediaType),
			Digest:    l.Metadata.Digest,
			Size:      l.Metadata.Size,
		}
	}

	// populate artifacts...
	for p := range pres.catalog.Enumerate() {
		art := artifact{
			Name:     p.Name,
			Version:  p.Version,
			Type:     p.Type.String(),
			Sources:  make([]source, len(p.Source)),
			Metadata: p.Metadata,
		}

		for idx, src := range p.Source {
			fileMetadata, err := pres.img.FileCatalog.Get(src)
			var layer int
			if err != nil {
				// TODO: test case
				log.Errorf("could not get metadata from catalog (presenter=json): %+v - error: %w", src, err)
				layer = 0
			} else {
				layer = int(fileMetadata.Source.Metadata.Index)
			}

			srcObj := source{
				FoundBy: p.FoundBy,
				Layer:   layer,
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
