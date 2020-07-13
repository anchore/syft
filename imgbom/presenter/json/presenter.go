package json

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/imgbom/scope"
	"github.com/anchore/imgbom/internal/log"
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

// Source returns a DirSrc or ImgSrc
func (pres *Presenter) Source() interface{} {
	srcObj := pres.scope.Source()
	switch src := srcObj.(type) {
	case scope.ImageSource:
		return pres.scope.ImgSrc
	case scope.DirSource:
		return pres.scope.DirSrc
	default:
		return fmt.Errorf("unsupported source: %T", src)
	}
}

type document struct {
	Artifacts []artifact `json:"artifacts"`
	Image     image      `json:"image"`
	Source    string
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
	doc := document{
		Artifacts: make([]artifact, 0),
	}

	src := pres.Source()
	imgSrc, ok := src.(scope.ImageSource)

	// populate artifacts...
	if ok {
		tags := make([]string, len(imgSrc.Img.Metadata.Tags))
		for idx, tag := range imgSrc.Img.Metadata.Tags {
			tags[idx] = tag.String()
		}
		doc.Image = image{
			Digest:    imgSrc.Img.Metadata.Digest,
			Size:      imgSrc.Img.Metadata.Size,
			MediaType: string(imgSrc.Img.Metadata.MediaType),
			Tags:      tags,
			Layers:    make([]layer, len(imgSrc.Img.Layers)),
		}
	} else {
		doc.Source = pres.scope.DirSrc.Path
	}

	for p := range pres.catalog.Enumerate() {
		art := artifact{
			Name:     p.Name,
			Version:  p.Version,
			Type:     p.Type.String(),
			Sources:  make([]source, len(p.Source)),
			Metadata: p.Metadata,
		}

		for idx := range p.Source {
			srcObj := source{
				FoundBy: p.FoundBy,
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
